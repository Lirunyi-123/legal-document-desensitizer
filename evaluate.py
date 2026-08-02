#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
红队评测工具 — 法律文书脱敏规则层量化指标
=========================================

用法：
    python3 evaluate.py                          # 跑默认语料库（测试/红队语料库.jsonl）
    python3 evaluate.py -c 我的语料.jsonl         # 指定语料库
    python3 evaluate.py --all-dates              # 全量日期模式
    python3 evaluate.py --report 评测报告.md      # 输出 Markdown 报告
    python3 evaluate.py --json 评测结果.json      # 输出 JSON 结果

语料库格式（JSONL，每行一个用例）：
    {
      "id": "id_01",
      "note": "说明",
      "text": "待测文本",
      "expect_masked": [{"type": "身份证号", "value": "110101198001011232"}],
      "expect_kept":   [{"type": "日期", "value": "2024年1月15日"}],   # 必须保留
      "expect_absent": ["13800138000"],                                 # 绝不能出现
      "llm_only": ["人名", "人名"]                                      # LLM层才覆盖（不参与召回率）
    }

评分口径：
    - 命中 = 期望值进入映射表（或被替换为占位符，即原文不再出现）
    - 分类型召回率 = 命中数 / 期望数（仅统计 expect_masked）
    - 误报 = expect_kept 中应保留却被替换的条目
    - llm_only 条目单独列出，说明这些是"规则层不承诺、需 LLM 层处理"的项
"""

import argparse
import json
import os
import sys
from collections import defaultdict


def load_corpus(path):
    cases = []
    with open(path, 'r', encoding='utf-8') as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            try:
                case = json.loads(line)
            except json.JSONDecodeError as e:
                print(f'⚠️  语料库第 {lineno} 行 JSON 解析失败：{e}', file=sys.stderr)
                continue
            case.setdefault('expect_masked', [])
            case.setdefault('expect_kept', [])
            case.setdefault('expect_absent', [])
            case.setdefault('llm_only', [])
            case['_lineno'] = lineno
            cases.append(case)
    return cases


def run_case(case, desensitizer):
    """对单个用例执行脱敏并给出结构化结果。"""
    text = case['text']
    result = desensitizer.mask(text)
    mapping_originals = {m.original for m in result.mapping}
    masked_text = result.text

    checks = []
    for item in case['expect_masked']:
        value = item['value']
        typ = item['type']
        # 命中：进入映射表，或原文中已消失（被占位符替换）
        hit = value in mapping_originals or value not in masked_text
        checks.append({'kind': 'masked', 'type': typ, 'value': value,
                       'ok': hit, 'detail': value in mapping_originals})
    for item in case['expect_kept']:
        if isinstance(item, str):
            item = {'value': item, 'type': '保留项'}
        value = item['value']
        ok = value in masked_text and value not in mapping_originals
        checks.append({'kind': 'kept', 'type': item.get('type', '保留项'),
                       'value': value, 'ok': ok, 'detail': value in masked_text})
    for value in case['expect_absent']:
        ok = value not in masked_text
        checks.append({'kind': 'absent', 'type': '泄露检查', 'value': value,
                       'ok': ok, 'detail': value not in masked_text})
    return result, checks


def main():
    parser = argparse.ArgumentParser(description='法律文书脱敏规则层红队评测')
    parser.add_argument('-c', '--corpus', default=os.path.join('测试', '红队语料库.jsonl'),
                        help='语料库路径（默认 测试/红队语料库.jsonl）')
    parser.add_argument('--all-dates', action='store_true',
                        help='使用 --all-dates 全量日期模式评测')
    parser.add_argument('--report', help='输出 Markdown 报告路径')
    parser.add_argument('--json', dest='json_out', help='输出 JSON 结果路径')
    args = parser.parse_args()

    from desensitize import Desensitizer
    d = Desensitizer(mask_all_dates=args.all_dates)
    cases = load_corpus(args.corpus)
    if not cases:
        sys.exit('❌ 未读取到任何用例，请检查语料库路径')

    # 运行全部用例
    results = []
    for case in cases:
        result, checks = run_case(case, d)
        failures = [c for c in checks if not c['ok']]
        results.append({
            'id': case.get('id', f'line{case["_lineno"]}'),
            'note': case.get('note', ''),
            'masked': result.text,
            'checks': checks,
            'failures': failures,
            'llm_only': case.get('llm_only', []),
        })

    # 汇总统计
    type_stats = defaultdict(lambda: {'expected': 0, 'hit': 0})
    kept_total = kept_fail = 0
    absent_total = absent_fail = 0
    llm_only_total = 0
    failed_cases = []
    for r in results:
        for c in r['checks']:
            if c['kind'] == 'masked':
                type_stats[c['type']]['expected'] += 1
                if c['ok']:
                    type_stats[c['type']]['hit'] += 1
            elif c['kind'] == 'kept':
                kept_total += 1
                kept_fail += 0 if c['ok'] else 1
            elif c['kind'] == 'absent':
                absent_total += 1
                absent_fail += 0 if c['ok'] else 1
        llm_only_total += len(r['llm_only'])
        if r['failures']:
            failed_cases.append(r)

    expected_total = sum(s['expected'] for s in type_stats.values())
    hit_total = sum(s['hit'] for s in type_stats.values())
    recall = (hit_total / expected_total) if expected_total else 1.0

    # 控制台报告
    print('=' * 62)
    print('法律文书脱敏规则层 — 红队评测报告')
    print('=' * 62)
    print(f'用例总数: {len(results)}   通过: {len(results) - len(failed_cases)}   失败: {len(failed_cases)}')
    print(f'结构化期望: {expected_total} 项，命中 {hit_total} 项，召回率 {recall:.1%}')
    print(f'保留项检查: {kept_total} 项，误报 {kept_fail} 项')
    if absent_total:
        print(f'泄露检查: {absent_total} 项，发现泄露 {absent_fail} 项')
    if llm_only_total:
        print(f'LLM 层待覆盖项（不计入召回率）: {llm_only_total} 项')
    print()
    print('按类型召回率：')
    print(f'  {"类型":<16}{"期望":>5}{"命中":>5}{"召回率":>9}')
    for typ in sorted(type_stats):
        s = type_stats[typ]
        r = s['hit'] / s['expected'] if s['expected'] else 1.0
        mark = '✅' if r >= 0.95 else ('⚠️' if r >= 0.8 else '❌')
        print(f'  {mark} {typ:<15}{s["expected"]:>5}{s["hit"]:>5}{r:>9.1%}')

    if failed_cases:
        print()
        print('失败用例明细：')
        for r in failed_cases:
            print(f'  [{r["id"]}] {r["note"]}')
            for c in r['failures']:
                if c['kind'] == 'masked':
                    print(f'    ✗ 未脱敏: {c["type"]} = {c["value"]}')
                elif c['kind'] == 'kept':
                    print(f'    ✗ 误脱敏: 应保留的 {c["value"]} 被替换')
                elif c['kind'] == 'absent':
                    print(f'    ✗ 泄露: 原文仍包含 {c["value"]}')

    # 输出 Markdown 报告
    if args.report:
        lines = [
            '# 法律文书脱敏规则层 — 红队评测报告',
            '',
            f'- 评测时间：{__import__("datetime").datetime.now().strftime("%Y-%m-%d %H:%M")}',
            f'- 语料库：{args.corpus}',
            f'- 模式：{"全量日期（--all-dates）" if args.all_dates else "默认（仅出生日期）"}',
            '',
            '## 总览',
            '',
            '| 指标 | 数值 |',
            '|------|------|',
            f'| 用例总数 | {len(results)} |',
            f'| 通过用例 | {len(results) - len(failed_cases)} |',
            f'| 结构化期望项 | {expected_total} |',
            f'| 召回率（整体） | {recall:.1%} |',
            f'| 保留项误报 | {kept_fail}/{kept_total} |',
        ]
        if absent_total:
            lines.append(f'| 泄露检查 | {absent_fail}/{absent_total} 项泄露 |')
        lines += [
            '',
            '## 分类型召回率',
            '',
            '| 类型 | 期望 | 命中 | 召回率 |',
            '|------|------|------|--------|',
        ]
        for typ in sorted(type_stats):
            s = type_stats[typ]
            r = s['hit'] / s['expected'] if s['expected'] else 1.0
            lines.append(f'| {typ} | {s["expected"]} | {s["hit"]} | {r:.1%} |')
        if failed_cases:
            lines += ['', '## 失败用例', '']
            for r in failed_cases:
                lines.append(f'### {r["id"]} — {r["note"]}')
                for c in r['failures']:
                    if c['kind'] == 'masked':
                        lines.append(f'- ✗ 未脱敏：{c["type"]} = `{c["value"]}`')
                    elif c['kind'] == 'kept':
                        lines.append(f'- ✗ 误脱敏：应保留的 `{c["value"]}` 被替换')
                    elif c['kind'] == 'absent':
                        lines.append(f'- ✗ 泄露：原文仍包含 `{c["value"]}`')
                lines.append(f'  - 原文：{r["masked"]}')
        with open(args.report, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines) + '\n')
        print(f'\n✅ Markdown 报告已保存: {args.report}')

    if args.json_out:
        payload = {
            'summary': {
                'cases': len(results),
                'passed': len(results) - len(failed_cases),
                'expected': expected_total,
                'hit': hit_total,
                'recall': recall,
                'kept_total': kept_total,
                'kept_fail': kept_fail,
                'absent_total': absent_total,
                'absent_fail': absent_fail,
                'llm_only_total': llm_only_total,
            },
            'by_type': {t: dict(s) for t, s in type_stats.items()},
            'failed_cases': [{'id': r['id'], 'note': r['note'],
                              'failures': r['failures']} for r in failed_cases],
        }
        with open(args.json_out, 'w', encoding='utf-8') as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        print(f'✅ JSON 结果已保存: {args.json_out}')

    # 退出码：有失败用例则非零
    return 1 if failed_cases else 0


if __name__ == '__main__':
    sys.exit(main())
