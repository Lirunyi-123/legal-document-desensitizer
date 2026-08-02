#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
法律文书脱敏工具 — 一键自检
============================

用法：
    python3 selfcheck.py                # 跑全部必检项（LLM 项无服务时自动跳过）
    python3 selfcheck.py --llm          # 强制检查本地 LLM（默认地址 localhost:11434）

环境变量：
    SELFCHECK_LLM_ENDPOINT  指定 LLM 地址（如 http://localhost:11434）
    SELFCHECK_LLM_MODEL     指定模型名（默认 qwen2.5）
    SELFCHECK_LLM_API       ollama（默认）或 openai（云端 OpenAI 兼容 API）
    LLM_API_KEY             云端 API Key（openai 模式需要）

输出：每项 PASS / FAIL / SKIP / WARN，全部必检项通过时退出码 0。
"""

import argparse
import json
import os
import re
import subprocess
import sys

REPO_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(REPO_DIR)


def run(cmd, timeout=120):
    return subprocess.run(cmd, capture_output=True, text=True,
                          timeout=timeout)


def check(name, fn):
    """执行单项检查，fn 返回 (ok, detail)；ok 为 None 表示跳过。"""
    try:
        ok, detail = fn()
    except Exception as e:
        ok, detail = False, f'异常：{e}'
    if ok is None:
        print(f'  SKIP  {name}：{detail}')
        return None
    status = 'PASS' if ok else 'FAIL'
    print(f'  {status}  {name}：{detail}')
    return ok


def required_files():
    files = [
        'desensitize.py', 'evaluate.py', 'llm_layer.py', 'ner_interface.py',
        'test_desensitize.py', 'test_llm_layer.py', 'SKILL.md', 'README.md',
        os.path.join('测试', '红队语料库.jsonl'),
    ]
    missing = [f for f in files if not os.path.exists(f)]
    return (not missing, f'缺失 {missing}' if missing else f'{len(files)} 个文件齐全')


def imports_ok():
    p = run([sys.executable, '-c',
             'import desensitize, ner_interface, llm_layer; print("ok")'])
    return (p.returncode == 0, p.stdout.strip() or p.stderr.strip())


def unit_tests():
    p = run([sys.executable, '-m', 'unittest',
             'test_desensitize', 'test_llm_layer'])
    output = p.stdout + p.stderr
    m = re.search(r'Ran (\d+) tests.*?(OK|FAILED)', output, re.S)
    if not m:
        return (False, f'无法解析测试输出：\n{output[-500:]}')
    total, status = int(m.group(1)), m.group(2)
    return (status == 'OK', f'{total} 项测试 {status}' if status == 'OK'
            else f'测试失败：\n{output[-800:]}')


def redteam_eval():
    p = run([sys.executable, 'evaluate.py'])
    fail_m = re.search(r'失败: (\d+)', p.stdout)
    recall_m = re.search(r'召回率 (\d+\.?\d*)%', p.stdout)
    if not fail_m or not recall_m:
        return (False, f'无法解析评测输出：\n{p.stdout[-500:]}')
    failures, recall = int(fail_m.group(1)), float(recall_m.group(1))
    return (failures == 0 and recall == 100.0,
            f'{failures} 失败，结构化召回率 {recall:.1f}%')


def restore_roundtrip():
    code = '''
from desensitize import Desensitizer, restore_text, parse_mapping_text
text = ("原告：陈建国，男，1980年1月1日出生，住浙江省杭州市西湖区文一西路1号，"
        "身份证号110101198001011232。尾款80万元、违约金人民币伍佰万元整。"
        "微信聊天记录（微信号lawyer_wang888）可以印证。")
r = Desensitizer().mask(text)
back = restore_text(r.text, parse_mapping_text(r.to_json()))
print("EXACT" if back == text else "DIFF")
'''
    p = run([sys.executable, '-c', code])
    return (p.stdout.strip() == 'EXACT',
            'mask→映射→restore 往返一致' if p.stdout.strip() == 'EXACT'
            else f'还原不一致：{p.stdout.strip()} {p.stderr.strip()[:300]}')


def llm_layer(args):
    endpoint = os.environ.get('SELFCHECK_LLM_ENDPOINT', 'http://localhost:11434')
    model = os.environ.get('SELFCHECK_LLM_MODEL', 'qwen2.5')
    api = os.environ.get('SELFCHECK_LLM_API', 'ollama')
    if not args.llm and not _endpoint_alive(endpoint):
        return (None, f'未检测到 LLM 服务（{endpoint}），已跳过；'
                      f'如需检查请先启动 ollama serve 或设 SELFCHECK_LLM_ENDPOINT')
    code = f'''
import sys
sys.path.insert(0, {REPO_DIR!r})
from llm_layer import LLMConfig, full_desensitize
cfg = LLMConfig(api={api!r}, model={model!r}, endpoint={endpoint!r}, timeout=60)
try:
    r, _ = full_desensitize('张三欠李四钱不还。\\n原告：陈建国。', cfg)
    ok = '[当事人' in r.text and '张三' not in r.text
    print('LLM_OK' if ok else 'LLM_BAD:' + r.text)
except Exception as e:
    print('LLM_ERR:' + str(e)[:300])
'''
    p = run([sys.executable, '-c', code], timeout=180)
    out = p.stdout.strip()
    if out.startswith('LLM_OK'):
        return (True, f'模型 {model} 二轮脱敏正常（裸人名已替换）')
    if out.startswith('LLM_ERR'):
        return (False, out[len('LLM_ERR:'):])
    return (False, out or p.stderr.strip()[:300])


def _endpoint_alive(endpoint, timeout=3):
    import urllib.request
    import urllib.error
    try:
        urllib.request.urlopen(endpoint, timeout=timeout)
        return True
    except urllib.error.HTTPError:
        return True  # 服务有响应（401/404 也算可达）
    except Exception:
        return False


def optional_deps():
    missing = []
    for mod in ('cryptography', 'docx', 'fitz'):
        try:
            __import__(mod)
        except ImportError:
            missing.append(mod)
    names = {'cryptography': '映射表加密', 'docx': 'docx 支持', 'fitz': 'pdf 支持'}
    if not missing:
        return (True, '全部可选依赖已安装')
    return (None, f'可选依赖未装：{[names.get(m, m) for m in missing]}'
                  '（不影响纯规则层，缺少时相关功能不可用）')


def version_info():
    p = run(['git', 'log', '-1', '--format=%h %s'])
    sha = p.stdout.strip() if p.returncode == 0 else '（非 git 副本）'
    return (None, f'当前版本提交：{sha}')


def main():
    ap = argparse.ArgumentParser(description='法律文书脱敏工具自检')
    ap.add_argument('--llm', action='store_true', help='强制检查本地 LLM（无服务则判失败）')
    args = ap.parse_args()

    print('=' * 56)
    print('法律文书脱敏工具 — 自检')
    print('=' * 56)
    results = []
    for name, fn in [
        ('必要文件齐全', required_files),
        ('模块导入', imports_ok),
        ('单元测试(44项)', unit_tests),
        ('红队评测(48用例)', redteam_eval),
        ('mask→restore 往返', restore_roundtrip),
        ('本地LLM二轮脱敏', lambda: llm_layer(args)),
        ('可选依赖', optional_deps),
        ('版本信息', version_info),
    ]:
        r = check(name, fn)
        if r is not None:
            results.append(r)

    print('=' * 56)
    fails = sum(1 for r in results if not r)
    if fails:
        print(f'结果：{len(results) - fails} 通过，{fails} 项失败 ❌')
        print('请把上方 FAIL 项的输出发给维护者，或对照《自检清单.md》排查。')
        return 1
    print(f'结果：{len(results)} 项必检全部通过 ✅')
    print('规则层可复现性已验证：文件一致 + 测试一致 + 评测一致 + 还原一致。')
    return 0


if __name__ == '__main__':
    sys.exit(main())
