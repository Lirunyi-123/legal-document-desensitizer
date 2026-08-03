#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
git-push-api.py — 通过 GitHub REST API 推送本地提交（curl 传输）
================================================================

适用场景：`git push` 直连 github.com:443 被网络阻断（Empty reply /
Connection refused），而 api.github.com 可通过 curl 访问时的推送方案。

特性：
- 把 `远程ref..HEAD` 之间本地领先的提交逐个通过 API 重建到远程；
- blob 与本地 `git hash-object` 逐字节核对，树 SHA 与本地一致；
- author/committer 元数据原样传递，能保留提交 SHA 时优先保留；
- 推送成功后更新本地 `refs/remotes/origin/<branch>`，工作树无感；
- 无需先提交再 reset，直接对已提交的改动工作。

用法（仓库根目录）：
    python3 git-push-api.py              # 推送当前分支到 origin 同名分支
    python3 git-push-api.py main          # 指定分支
    python3 git-push-api.py -n            # dry-run（只打印计划）
    python3 git-push-api.py --sync-local  # 推送后把远程提交对象重建到本地，
                                          # 本地 main 与远程 SHA 完全一致

Token 来源（与 gh CLI 共用）：
    ~/.config/gh/hosts.yml 中的 oauth_token
    或环境变量 GITHUB_PAT_TOKEN
    或 --token 参数

依赖：Python 标准库 + curl（HTTP 层走 curl，避免本机 Python DNS 异常）。
"""

import argparse
import base64
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone

API = "https://api.github.com"
REPO_DIR = os.getcwd()


# ------------------------------------------------------------
# 基础工具
# ------------------------------------------------------------

def git(*args, check=True, input_bytes=None):
    p = subprocess.run(["git"] + list(args), capture_output=True,
                       text=(input_bytes is None),
                       input=input_bytes, cwd=REPO_DIR)
    if check and p.returncode != 0:
        raise SystemExit(f"git {' '.join(args)} 失败: {p.stderr.strip()[:200]}")
    return p


def load_token(arg_token=""):
    if arg_token:
        return arg_token
    env = os.environ.get("GITHUB_PAT_TOKEN", "").strip()
    if env:
        return env
    path = os.path.expanduser("~/.config/gh/hosts.yml")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            text = f.read()
        m = re.search(r"github\.com:.*?oauth_token:\s*[\"']?([A-Za-z0-9_]+)",
                      text, re.S)
        if m:
            return m.group(1)
    raise SystemExit("未找到 token：请用 --token、设置 GITHUB_PAT_TOKEN 或先 gh auth login")


def api(method, url, token, payload=None, ok=None):
    cmd = ["curl", "-sS", "-X", method,
           "-H", f"Authorization: Bearer {token}",
           "-H", "Accept: application/vnd.github+json",
           "-H", "Content-Type: application/json",
           "--connect-timeout", "20", "--max-time", "180"]
    if payload is not None:
        cmd += ["-d", json.dumps(payload, ensure_ascii=False)]
    cmd += [url, "-w", "\n%{http_code}"]
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        raise SystemExit(f"curl 失败({p.returncode}): {p.stderr.strip()[:200]}")
    body, _, code = p.stdout.rpartition("\n")
    try:
        code = int(code.strip() or 0)
    except ValueError:
        code = 0
    if ok is not None:
        ok_status = ok
    else:
        ok_status = range(200, 300)
    if code not in ok_status:
        raise SystemExit(f"API 错误({code}): {body.strip()[:200]}")
    if not body.strip():
        return {}
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        raise SystemExit(f"非 JSON 响应: {body[:200]}")
    return data


def get_token_owner_repo(token):
    """返回 (owner, repo)。支持 --repo 或从 origin 远程解析。"""
    p = git("config", "--get", "remote.origin.url", check=False)
    url = p.stdout.strip()
    m = re.search(r"(?:github\.com[:/])([^/\s]+)/([^/\s]+?)(?:\.git)?$", url or "")
    if not m:
        raise SystemExit(f"无法从远程地址解析仓库: {url!r}（可用 --repo 指定）")
    return m.group(1), m.group(2)


# ------------------------------------------------------------
# 提交解析
# ------------------------------------------------------------

def parse_commit(sha):
    """解析本地提交：返回 dict(tree, parents, author, committer, message)。"""
    p = git("cat-file", "commit", sha)
    raw = p.stdout
    headers = {}
    lines = raw.splitlines()
    idx = 0
    while idx < len(lines) and lines[idx] != "":
        line = lines[idx]
        key, _, val = line.partition(" ")
        headers.setdefault(key, []).append(val)
        idx += 1
    message = "\n".join(lines[idx + 1:])
    if message and not message.endswith("\n"):
        message += "\n"
    return {
        "tree": headers["tree"][0],
        "parents": headers.get("parent", []),
        "author": headers["author"][0],
        "committer": headers["committer"][0],
        "message": message,
    }


def git_date_to_iso(git_date):
    """git 日期 "1730000000 +0800" → RFC3339 "2024-10-27T12:00:00+08:00"。"""
    m = re.match(r"(\d+)\s+([+-]\d{4})", git_date)
    if not m:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ")
    epoch, off = int(m.group(1)), m.group(2)
    tz = timezone(timedelta(hours=int(off[:3]), minutes=int(off[3:])))
    return datetime.fromtimestamp(epoch, tz).isoformat()


def split_author(line):
    """git 作者行 "Name <email> 1730000000 +0800" → (name, email, iso_date)。"""
    m = re.match(r"^(.*?)\s+<([^>]*)>\s+(\d+\s+[+-]\d{4})$", line)
    if not m:
        return line, "", time.strftime("%Y-%m-%dT%H:%M:%SZ")
    return m.group(1), m.group(2), git_date_to_iso(m.group(3))


def rebuild_commit_local(remote_commit):
    """把远程提交对象重建到本地 git 仓库；成功返回 True。

    GitHub API 创建提交时会把 author/committer 时间归一化，导致与本地提交
    SHA 不一致。此处用"消息换行 × 时区偏移"组合暴力还原提交对象字节，
    使本地 main 与远程 SHA 完全一致。
    """
    target = remote_commit["sha"]
    # 本地对象已存在（SHA 保留成功的常规情况）→ 直接通过
    if git("cat-file", "-e", target, check=False).returncode == 0:
        return True
    base_msg = remote_commit["message"]
    from datetime import datetime as _dt
    dt = _dt.fromisoformat(remote_commit["author"]["date"].replace("Z", "+00:00"))
    epoch_utc = int(dt.timestamp())
    for msg in (base_msg, base_msg + "\n", base_msg.rstrip("\n")):
        for off in ("+0800", "+0000"):
            lines = [f"tree {remote_commit['tree']['sha']}"]
            for p in remote_commit.get("parents", []):
                lines.append(f"parent {p['sha']}")
            for f in ("author", "committer"):
                v = remote_commit[f]
                lines.append(f"{f} {v['name']} <{v['email']}> {epoch_utc} {off}")
            raw = ("\n".join(lines) + "\n\n" + msg).encode("utf-8")
            p = git("hash-object", "-t", "commit", "--stdin", input_bytes=raw)
            if p.stdout.strip() == target:
                git("hash-object", "-t", "commit", "-w", "--stdin", input_bytes=raw)
                return True
    return False


def sync_local(repo, branch, pushed_shas, token):
    """推送后对齐本地：按序重建远程提交对象并更新本地分支引用。"""
    built = []
    for sha in pushed_shas:
        c = api("GET", f"{API}/repos/{repo}/git/commits/{sha}", token)
        ok = rebuild_commit_local(c)
        print(f"  sync {sha[:12]} {'OK' if ok else '跳过（对象缺失）'}")
        if ok:
            built.append(sha)
        else:
            break
    if built:
        git("update-ref", f"refs/heads/{branch}", built[-1])
        git("update-ref", f"refs/remotes/origin/{branch}", built[-1])
        print(f"本地 {branch} 与远程对齐: {built[-1]}")
    else:
        raise SystemExit("同步失败：远程提交对象无法在本地重建")


def try_update_origin_ref(branch, sha):
    """远程对象已存在本地时更新 origin 跟踪引用，否则提示用 --sync-local。"""
    p = git("cat-file", "-e", sha, check=False)
    if p.returncode == 0:
        git("update-ref", f"refs/remotes/origin/{branch}", sha)
        print(f"本地 refs/remotes/origin/{branch} → {sha}")
    else:
        print(f"提示: 远程提交 {sha[:12]} 尚未在本地（用 --sync-local 可本地对齐）")


# ------------------------------------------------------------
# 推送主流程
# ------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="通过 GitHub REST API 推送本地提交")
    ap.add_argument("branch", nargs="?", default=None,
                    help="分支名（默认：当前分支）")
    ap.add_argument("--repo", default=None, help="owner/repo（默认从 origin 解析）")
    ap.add_argument("--token", default="", help="GitHub PAT（默认从 gh CLI 配置读取）")
    ap.add_argument("-n", "--dry-run", action="store_true", help="只打印计划")
    ap.add_argument("--sync-local", action="store_true",
                    help="推送后重建远程提交对象，本地与远程 SHA 完全一致")
    ap.add_argument("--force", action="store_true",
                    help="非快进时也更新远程分支（会丢弃远程孤立提交，慎用）")
    args = ap.parse_args()

    token = load_token(args.token)
    owner, repo_name = get_token_owner_repo(token)
    repo = args.repo or f"{owner}/{repo_name}"
    branch = args.branch or git("rev-parse", "--abbrev-ref", "HEAD").stdout.strip()
    print(f"仓库: {repo}  分支: {branch}")

    # 1) 远程当前头
    ref = api("GET", f"{API}/repos/{repo}/git/ref/heads/{branch}", token)
    if isinstance(ref, dict) and ref.get("message") and "sha" not in ref:
        print(f"远程 {branch} 不存在（作为新分支推送）")
        remote_head = None
    else:
        remote_head = ref["object"]["sha"]
        print(f"远程 {branch}: {remote_head}")

    # 2) 本地领先提交（从旧到新）：远程已存在的本地提交（含重映射/历史）跳过
    p = git("rev-list", "--reverse", "HEAD")
    commits = []
    for sha in p.stdout.split():
        exists = api("GET", f"{API}/repos/{repo}/git/commits/{sha}", token,
                     ok=(200, 404))
        if isinstance(exists, dict) and exists.get("sha") == sha:
            continue
        commits.append(sha)
    if not commits:
        print("没有需要推送的提交")
        if remote_head and git("cat-file", "-e", remote_head,
                               check=False).returncode == 0:
            git("update-ref", f"refs/remotes/origin/{branch}", remote_head)
            print(f"本地 refs/remotes/origin/{branch} → {remote_head}（已与远程一致）")
        return
    # 快进预检：首个待推送提交的父必须等于远程头
    if remote_head:
        first = parse_commit(commits[0])
        lp = first["parents"][0] if first["parents"] else None
        if lp and lp != remote_head:
            pe = api("GET", f"{API}/repos/{repo}/git/commits/{lp}", token,
                     ok=(200, 404))
            if isinstance(pe, dict) and pe.get("sha") == lp:
                if not args.force:
                    raise SystemExit(
                        f"非快进推送：远程头 {remote_head[:12]} 不是首个待推送提交"
                        f"的父 {lp[:12]}。远程存在孤立/重映射提交时需 --force，"
                        "或先同步本地与远程")
            else:
                raise SystemExit(f"首个待推送提交的父 {lp[:12]} 在远程不存在")
    print(f"待推送 {len(commits)} 个提交:")
    for c in commits:
        print(f"  {c[:12]} {parse_commit(c)['message'].splitlines()[0][:50]}")
    if args.dry_run:
        raise SystemExit("[dry-run] 未推送")

    # 3) 逐个重建提交（从旧到新；要求线性父链）
    parent_remote = remote_head          # 当前提交在远程侧的父提交 SHA
    parent_tree = None
    if parent_remote:
        pc = api("GET", f"{API}/repos/{repo}/git/commits/{parent_remote}", token)
        parent_tree = pc["tree"]["sha"]
    last_remote = None
    pushed_shas = []
    pushed_local = {}                    # 本地 sha → 远程 sha

    for sha in commits:
        info = parse_commit(sha)
        local_parent = info["parents"][0] if info["parents"] else None
        # 父提交在远程必须是"同 SHA 存在"或"本次刚推送"：
        # - 刚推送：用重映射后的远程 SHA 作父
        # - 远程同 SHA 存在：直接用本地 SHA 作父（保证线性）
        if local_parent:
            if local_parent in pushed_local:
                parent_remote = pushed_local[local_parent]
            else:
                pe = api("GET", f"{API}/repos/{repo}/git/commits/{local_parent}",
                         token, ok=(200, 404))
                if isinstance(pe, dict) and pe.get("sha") == local_parent:
                    parent_remote = local_parent
                else:
                    raise SystemExit(
                        f"{sha[:12]} 的父提交 {local_parent[:12]} 在远程为不同 SHA"
                        "（历史被重映射），请先同步本地与远程后再推送")
            pc = api("GET", f"{API}/repos/{repo}/git/commits/{parent_remote}", token)
            parent_tree = pc["tree"]["sha"]
        # 变化文件（相对父提交；根提交取全部文件）
        if local_parent:
            p = git("diff-tree", "-r", "--no-commit-id", "--name-only", "-z",
                    local_parent, sha)
        else:
            p = git("ls-tree", "-r", "--name-only", "-z", sha)
        paths = [x for x in p.stdout.split("\0") if x.strip()]

        # 上传变化文件的 blob
        tree_updates = []
        for path in paths:
            blob = git("rev-parse", f"{sha}:{path}")
            local_blob_sha = blob.stdout.strip()
            raw = git("show", f"{sha}:{path}", check=False)
            if raw.returncode != 0:
                continue  # 子模块等非常规条目
            payload = {"content": raw.stdout, "encoding": "utf-8"}
            try:
                payload["content"].encode("utf-8")
            except UnicodeEncodeError:
                payload = {"content": base64.b64encode(raw.stdout.encode()).decode(),
                           "encoding": "base64"}
            created = api("POST", f"{API}/repos/{repo}/git/blobs", token, payload)
            if created["sha"] != local_blob_sha:
                raise SystemExit(f"blob 校验不一致: {path} {created['sha']} vs {local_blob_sha}")
            tree_updates.append({"path": path, "mode": "100644",
                                 "type": "blob", "sha": created["sha"]})

        # 建树（基于远程父树）
        tree_payload = {"base_tree": parent_tree, "tree": tree_updates}
        tree = api("POST", f"{API}/repos/{repo}/git/trees", token, tree_payload)
        if tree["sha"] != info["tree"]:
            print(f"  ⚠ {sha[:12]} 树 SHA 不一致（本地 {info['tree']} / 远程 {tree['sha']}），"
                  "以远程树继续")

        # 建提交（元数据原样传递，尽量保留 SHA）
        an, ae, ad = split_author(info["author"])
        cn, ce, cd = split_author(info["committer"])
        payload = {
            "message": info["message"],
            "tree": tree["sha"],
            "parents": [parent_remote] if parent_remote else [],
            "author": {"name": an, "email": ae, "date": ad},
            "committer": {"name": cn, "email": ce, "date": cd},
        }
        created = api("POST", f"{API}/repos/{repo}/git/commits", token, payload)
        marker = "SHA一致 ✓" if created["sha"] == sha else "SHA重映射"
        print(f"  {sha[:12]} → {created['sha'][:12]} [{marker}] "
              f"{info['message'].splitlines()[0][:40]}")
        parent_remote = created["sha"]
        parent_tree = created["tree"]["sha"] if "tree" in created else tree["sha"]
        last_remote = created["sha"]
        pushed_shas.append(created["sha"])
        pushed_local[sha] = created["sha"]

    # 4) 更新分支引用
    updated = api("PATCH", f"{API}/repos/{repo}/git/refs/heads/{branch}", token,
                  {"sha": last_remote, "force": args.force})
    print("分支已更新:", updated.get("ref"))
    verify = {}
    for _ in range(5):
        time.sleep(2)
        verify = api("GET", f"{API}/repos/{repo}/git/ref/heads/{branch}", token)
        if verify.get("object", {}).get("sha") == last_remote:
            break
    if verify["object"]["sha"] != last_remote:
        raise SystemExit("验证失败：远程分支与本次提交不一致")
    print("验证: PUSH OK")
    print(f"查看: https://github.com/{repo}/commits/{branch}")

    # 5) 可选：重建远程提交对象到本地，本地 main 与远程 SHA 一致
    if args.sync_local:
        print("同步本地历史…")
        sync_local(repo, branch, pushed_shas, token)
    else:
        try_update_origin_ref(branch, last_remote)


if __name__ == "__main__":
    main()
