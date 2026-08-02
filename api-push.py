#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
api-push.py — 通过 GitHub Git API 推送提交
============================================

适用场景：github.com 直连受限（如国内网络），但 api.github.com 可访问时，
用 REST Git API 完成「上传文件 → 建树 → 建提交 → 更新分支」的推送。

特性：
- 以远程分支的最新树为基础树，未改动的文件全部保留
- 支持新增 / 修改 / 删除文件
- 上传的 blob 与本地 `git hash-object` 逐字节核对
- 可选 --sync-local：推送后把远程历史重建到本地，SHA 与远程完全一致

依赖：仅 Python 标准库（>=3.8）。

Token 来源（按优先级）：
  1. --token 参数
  2. 环境变量 GITHUB_PAT_TOKEN
  3. gh CLI 配置文件 ~/.config/gh/hosts.yml 中的 oauth_token

用法（在仓库根目录运行）：
  # 推送指定文件（提交信息必填）
  python3 api-push.py -m "fix: 修复xxx" desensitize.py SKILL.md

  # 推送全部工作区改动（含新增/修改/删除）
  python3 api-push.py -m "feat: xxx" --all

  # 只打印将执行的步骤，不实际推送
  python3 api-push.py -m "test" --all --dry-run

  # 推送后同步本地历史（SHA 与远程一致）
  python3 api-push.py -m "feat: xxx" --all --sync-local

安全说明：脚本不会把 token 打印到任何输出。
"""

import argparse
import base64
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

API = "https://api.github.com"
REPO_DIR = os.getcwd()


# ------------------------------------------------------------
# 基础工具
# ------------------------------------------------------------

def git(*args, input_bytes=None, check=True):
    """在仓库根目录执行 git 命令"""
    return subprocess.run(
        ["git", "-C", REPO_DIR, *args],
        input=input_bytes,
        capture_output=True,
        check=check,
    )


def load_token(explicit):
    if explicit:
        return explicit
    env = os.environ.get("GITHUB_PAT_TOKEN", "")
    if env:
        return env
    hosts = os.path.expanduser("~/.config/gh/hosts.yml")
    if os.path.exists(hosts):
        with open(hosts, encoding="utf-8") as fh:
            for line in fh:
                m = re.match(r"\s*oauth_token:\s*(\S+)", line)
                if m:
                    return m.group(1)
    return ""


def api_call(method, path, token, payload=None):
    req = urllib.request.Request(API + path, method=method)
    req.add_header("Authorization", "Bearer " + token)
    req.add_header("Accept", "application/vnd.github+json")
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, data, timeout=60) as r:
            body = r.read().decode("utf-8")
            return r.status, json.loads(body) if body else {}
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")
        raise RuntimeError(f"GitHub API {method} {path} 失败: HTTP {e.code} {detail}")


def parse_remote(remote_url):
    remote_url = (remote_url or "").strip().rstrip("/")
    m = re.search(r"(?:github\.com[:/])([^/\s]+)/([^/\s]+?)(?:\.git)?$", remote_url)
    if not m:
        raise SystemExit(f"无法从远程地址解析仓库（可用 --repo 指定）: {remote_url!r}")
    return f"{m.group(1)}/{m.group(2)}"


def get_default_branch(repo, token):
    _, info = api_call("GET", f"/repos/{repo}", token)
    return info.get("default_branch", "main")


def get_head(repo, branch, token):
    _, ref = api_call(
        "GET", f"/repos/{repo}/git/refs/heads/{urllib.parse.quote(branch)}", token
    )
    return ref


def get_commit_tree(repo, sha, token):
    _, c = api_call("GET", f"/repos/{repo}/git/commits/{sha}", token)
    return c["tree"]["sha"]


def get_tree_entries(repo, tree_sha, token):
    _, t = api_call("GET", f"/repos/{repo}/git/trees/{tree_sha}?recursive=1", token)
    return t["tree"]


def collect_changes(all_flag, file_args):
    """返回 [(状态, 路径)]；状态 D=删除，其余视为修改/新增。"""
    if file_args:
        out = []
        for f in file_args:
            st = "D" if not os.path.exists(os.path.join(REPO_DIR, f)) else "M"
            out.append((st, f))
        return out
    if not all_flag:
        raise SystemExit("请指定要推送的文件，或使用 --all 推送全部工作区改动")
    # porcelain -z：路径不转义，中文/空格安全
    p = git("status", "--porcelain", "-z")
    raw = p.stdout.decode("utf-8", "replace")
    changes = []
    for item in raw.split("\0"):
        if len(item) < 4:
            continue
        st, path = item[:2], item[3:]  # 格式为 "XY <path>"，跳过状态码后的空格
        if "D" in st or "M" in st or "A" in st or "?" in st or "U" in st:
            changes.append(("D" if "D" in st else "M", path))
    return changes


# ------------------------------------------------------------
# 推送主流程
# ------------------------------------------------------------

def push(repo, branch, token, changes, message, dry_run):
    ref = get_head(repo, branch, token)
    head_sha = ref["object"]["sha"]
    base_tree = get_commit_tree(repo, head_sha, token)
    print(f"远程 {branch} 当前: {head_sha}（基础树 {base_tree}）")
    print(f"本次变更 ({len(changes)}):")
    for st, f in changes:
        print(f"  [{st}] {f}")

    tree_updates = []
    for st, f in changes:
        path = os.path.join(REPO_DIR, f)
        if st == "D" or not os.path.exists(path):
            tree_updates.append({"path": f, "sha": None})  # sha=null 表示删除
            print(f"删除: {f}")
            continue
        if os.path.isdir(path):
            print(f"跳过目录: {f}（请逐个指定文件）")
            continue
        with open(path, "rb") as fh:
            raw = fh.read()
        local_sha = git("hash-object", f).stdout.decode().strip()
        if dry_run:
            print(f"blob {f}: {local_sha[:12]} (dry-run, 不上传)")
            tree_updates.append(
                {"path": f, "mode": "100755" if os.access(path, os.X_OK) else "100644",
                 "type": "blob", "sha": local_sha}
            )
            continue
        try:
            payload = {"content": raw.decode("utf-8"), "encoding": "utf-8"}
        except UnicodeDecodeError:
            payload = {
                "content": base64.b64encode(raw).decode("ascii"),
                "encoding": "base64",
            }
        _, blob = api_call("POST", f"/repos/{repo}/git/blobs", token, payload)
        if blob["sha"] != local_sha:
            raise SystemExit(f"{f} 的 blob 校验不一致（{blob['sha']} vs {local_sha}），中止")
        print(f"blob {f}: {blob['sha'][:12]} OK")
        mode = "100755" if os.access(path, os.X_OK) else "100644"
        tree_updates.append({"path": f, "mode": mode, "type": "blob", "sha": blob["sha"]})

    if dry_run:
        print("[dry-run] 未创建树/提交，未更新远程分支")
        return

    _, tree = api_call(
        "POST", f"/repos/{repo}/git/trees", token,
        {"base_tree": base_tree, "tree": tree_updates},
    )
    print("新树:", tree["sha"])

    name = git("config", "user.name", check=False).stdout.decode().strip() or "GitHub"
    email = git("config", "user.email", check=False).stdout.decode().strip() or "noreply@github.com"
    now = datetime.now().astimezone().isoformat()
    _, commit = api_call(
        "POST", f"/repos/{repo}/git/commits", token,
        {
            "message": message,
            "tree": tree["sha"],
            "parents": [head_sha],
            "author": {"name": name, "email": email, "date": now},
            "committer": {"name": name, "email": email, "date": now},
        },
    )
    print("新提交:", commit["sha"], "-", message.splitlines()[0])

    _, updated = api_call(
        "PATCH", f"/repos/{repo}/git/refs/heads/{urllib.parse.quote(branch)}", token,
        {"sha": commit["sha"], "force": False},
    )
    print("分支已更新:", updated.get("ref"), updated.get("object", {}).get("sha"))

    ref2 = get_head(repo, branch, token)
    if ref2["object"]["sha"] != commit["sha"]:
        raise SystemExit("验证失败：远程分支与本次提交不一致")
    print("验证: PUSH OK")
    print(f"查看变更: https://github.com/{repo}/compare/{head_sha[:12]}...{commit['sha'][:12]}")
    return commit["sha"]


# ------------------------------------------------------------
# 本地历史同步（可选，--sync-local）
# ------------------------------------------------------------

def sync_local(repo, branch, new_head, token):
    """把远程提交历史重建到本地，使本地 main 与远程 SHA 完全一致。"""
    chain = []
    sha = new_head
    while sha:
        if git("cat-file", "-e", sha, check=False).returncode == 0:
            break  # 已存在（含公共祖先）
        _, c = api_call("GET", f"/repos/{repo}/git/commits/{sha}", token)
        chain.append(c)
        sha = c["parents"][0]["sha"] if c.get("parents") else None
    chain.reverse()
    if not chain:
        print("[sync-local] 本地历史已包含最新提交，无需重建")
        return
    print(f"[sync-local] 重建 {len(chain)} 个提交…")

    for i, c in enumerate(chain, 1):
        # 1) blob 对象
        tree = get_tree_entries(repo, c["tree"]["sha"], token)
        for e in tree:
            if e["type"] != "blob":
                continue
            if git("cat-file", "-e", e["sha"] + "^{blob}", check=False).returncode != 0:
                _, b = api_call("GET", f"/repos/{repo}/git/blobs/{e['sha']}", token)
                raw = base64.b64decode(b["content"])
                p = git("hash-object", "-w", "--stdin", input_bytes=raw)
                if p.returncode != 0:
                    raise SystemExit(f"blob 写入失败 {e['sha']}")
        # 2) 树对象（逐项校验 SHA）
        lines = []
        for e in tree:
            mode = e["mode"] if e["type"] == "blob" else "040000"
            lines.append(f"{mode} {e['type']} {e['sha']}\t{e['path']}")
        p = git("mktree", input_bytes="\n".join(lines).encode("utf-8"))
        local_tree = p.stdout.decode().strip()
        if local_tree != c["tree"]["sha"]:
            raise SystemExit(f"树 SHA 不一致: {c['sha'][:12]}")
        # 3) 提交对象（消息换行 × 时区偏移 组合试探，逐提交校验 SHA）
        dt = datetime.fromisoformat(c["author"]["date"].replace("Z", "+00:00"))
        epoch = int(dt.timestamp())
        messages = [c["message"]]
        if not c["message"].endswith("\n"):
            messages.append(c["message"] + "\n")
        matched = None
        for msg in messages:
            for offset in ("+0800", "+0000"):
                lines = [f"tree {c['tree']['sha']}"]
                for pp in c.get("parents", []):
                    lines.append(f"parent {pp['sha']}")
                lines.append(
                    f"author {c['author']['name']} <{c['author']['email']}> {epoch} {offset}"
                )
                lines.append(
                    f"committer {c['committer']['name']} <{c['committer']['email']}> {epoch} {offset}"
                )
                raw = ("\n".join(lines) + "\n\n" + msg).encode("utf-8")
                p = git("hash-object", "-t", "commit", "--stdin", input_bytes=raw)
                if p.stdout.decode().strip() == c["sha"]:
                    matched = raw
                    break
            if matched:
                break
        if matched is None:
            raise SystemExit(f"提交 SHA 无法复现: {c['sha'][:12]}（日期/消息元数据差异）")
        git("hash-object", "-t", "commit", "-w", "--stdin", input_bytes=matched)
        print(f"  OK {i}/{len(chain)}: {c['sha'][:12]} {c['message'].splitlines()[0][:38]}")

    git("update-ref", f"refs/heads/{branch}", new_head)
    git("update-ref", f"refs/remotes/origin/{branch}", new_head)
    git("reset", "--mixed", "HEAD")
    print(f"[sync-local] 本地 {branch} 已指向 {new_head}")
    status = git("status", "--short").stdout
    print("[sync-local] git status:", status if status else "（干净）")


def main():
    ap = argparse.ArgumentParser(
        description="通过 GitHub Git API 推送提交（github.com 直连受限时的替代方案）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例:\n  python3 api-push.py -m \"fix: xxx\" desensitize.py\n  python3 api-push.py -m \"feat: xxx\" --all --sync-local",
    )
    ap.add_argument("files", nargs="*", help="要推送的文件路径（相对仓库根）")
    ap.add_argument("-m", "--message", required=True, help="提交信息")
    ap.add_argument("--all", action="store_true", help="推送全部工作区改动（含新增/修改/删除）")
    ap.add_argument("--branch", default="", help="目标分支（默认远程默认分支）")
    ap.add_argument("--repo", default="", help="owner/repo（默认从 origin 解析）")
    ap.add_argument("--token", default="", help="GitHub token（默认读环境变量或 gh 配置）")
    ap.add_argument("--dry-run", action="store_true", help="只打印将执行的步骤，不实际推送")
    ap.add_argument("--sync-local", action="store_true", help="推送后重建本地历史至与远程一致")
    args = ap.parse_args()

    if not os.path.isdir(".git") and not os.path.exists(".git"):
        raise SystemExit("请在 git 仓库根目录运行本脚本")
    token = load_token(args.token)
    if not token:
        raise SystemExit("未找到 token：请用 --token、设置 GITHUB_PAT_TOKEN 或先 gh auth login")

    remote_url = git("config", "--get", "remote.origin.url", check=False).stdout.decode().strip()
    repo = args.repo or parse_remote(remote_url)
    branch = args.branch or get_default_branch(repo, token)
    print(f"仓库: {repo}  分支: {branch}")

    changes = collect_changes(args.all, args.files)
    if not changes:
        raise SystemExit("没有需要推送的改动")

    new_head = push(repo, branch, token, changes, args.message, args.dry_run)
    if args.sync_local and new_head:
        sync_local(repo, branch, new_head, token)


if __name__ == "__main__":
    main()
