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

评分口径（v3.0：entity-level per-tag P/R/F1 + support，内化自 rizzo-pii）：
    - 正样本 = expect_masked：命中（进入映射表或原文消失且无片段残留）= TP，漏 = FN
    - 负样本 = expect_kept：应保留却被替换 = FP（precision 的分母）
    - 分类型 precision / recall / F1 + support（样本数），外加 MICRO（总体）
      与 MACRO（类型平均）汇总——规则层最怕误伤，precision/F1 才是
      "改保守了还是改漏了"的量化指标
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


def _partial_leak(value, masked_text, n=6):
    """检测敏感值是否部分残留在脱敏文本中（如地址只脱敏了尾部）。

    取连续 n 个字符的片段检查：完全脱敏时任何片段都不应再出现。
    """
    if len(value) <= n:
        return value in masked_text
    return any(value[i:i + n] in masked_text for i in range(len(value) - n + 1))


def run_case(case, desensitizer, include_llm=False):
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
        in_mapping = value in mapping_originals
        gone = value not in masked_text
        leak = _partial_leak(value, masked_text)
        hit = (in_mapping or gone) and not leak
        checks.append({'kind': 'masked', 'type': typ, 'value': value,
                       'ok': hit,
                       'detail': f'mapping={in_mapping} gone={gone} leak={leak}'})
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
    # LLM 层覆盖项：仅在 LLM 评测模式下作为硬性期望
    for item in case.get('llm_only', []):
        if isinstance(item, str):
            continue  # 无值的旧格式条目：仅计数，不验证
        value = item.get('value', '')
        if not value or not include_llm:
            continue
        ok = value not in masked_text
        checks.append({'kind': 'llm', 'type': item.get('type', 'LLM层'),
                       'value': value, 'ok': ok,
                       'detail': value not in masked_text})
    return result, checks


class FullPipeline:
    """规则层 + LLM 层完整流水线（评测用）"""

    def __init__(self, llm_config, mask_all_dates=False):
        self._config = llm_config
        self._mask_all_dates = mask_all_dates

    def mask(self, text):
        from llm_layer import full_desensitize
        result, _ = full_desensitize(text, self._config,
                                     mask_all_dates=self._mask_all_dates)
        return result


def main():
    parser = argparse.ArgumentParser(description='法律文书脱敏规则层红队评测')
    parser.add_argument('-c', '--corpus', default=os.path.join('测试', '红队语料库.jsonl'),
                        help='语料库路径（默认 测试/红队语料库.jsonl）')
    parser.add_argument('--all-dates', action='store_true',
                        help='使用 --all-dates 全量日期模式评测')
    parser.add_argument('--report', help='输出 Markdown 报告路径')
    parser.add_argument('--json', dest='json_out', help='输出 JSON 结果路径')
    parser.add_argument('--llm-api', default=None, choices=['ollama', 'openai'],
                        help='启用 LLM 评测模式并指定 API（ollama/openai 兼容）')
    parser.add_argument('--llm-model', default='qwen2.5', help='LLM 模型名')
    parser.add_argument('--llm-endpoint', default='http://localhost:11434',
                        help='LLM 服务地址')
    parser.add_argument('--llm-api-key', default='',
                        help='云端 API Key（也可用环境变量 LLM_API_KEY）')
    parser.add_argument('--llm-timeout', type=int, default=180,
                        help='LLM 调用超时（秒）')
    args = parser.parse_args()

    from desensitize import Desensitizer
    if args.llm_api:
        from llm_layer import LLMConfig
        d = FullPipeline(
            LLMConfig(api=args.llm_api, model=args.llm_model,
                      endpoint=args.llm_endpoint, timeout=args.llm_timeout,
                      api_key=args.llm_api_key),
            mask_all_dates=args.all_dates)
        llm_mode = True
    else:
        d = Desensitizer(mask_all_dates=args.all_dates)
        llm_mode = False
    cases = load_corpus(args.corpus)
    if not cases:
        sys.exit('❌ 未读取到任何用例，请检查语料库路径')

    # 运行全部用例
    results = []
    for case in cases:
        try:
            result, checks = run_case(case, d, include_llm=llm_mode)
        except Exception as e:
            results.append({
                'id': case.get('id', f'line{case["_lineno"]}'),
                'note': case.get('note', ''),
                'masked': '',
                'checks': [],
                'failures': [{'kind': 'llm', 'type': 'LLM层',
                              'value': '', 'ok': False,
                              'detail': f'流水线异常：{e}'}],
                'llm_only': case.get('llm_only', []),
            })
            continue
        failures = [c for c in checks if not c['ok']]
        results.append({
            'id': case.get('id', f'line{case["_lineno"]}'),
            'note': case.get('note', ''),
            'masked': result.text,
            'checks': checks,
            'failures': failures,
            'llm_only': case.get('llm_only', []),
        })

    # 汇总统计（v3.0：entity-level per-tag P/R/F1 + support）
    # 正样本 = expect_masked（命中=TP，漏=FN）；负样本 = expect_kept（被替换=FP）
    type_metrics = defaultdict(lambda: {'support': 0, 'tp': 0, 'fp': 0, 'fn': 0})
    kept_total = kept_fail = 0
    absent_total = absent_fail = 0
    llm_only_total = 0
    llm_hit_total = 0
    failed_cases = []
    for r in results:
        for c in r['checks']:
            t = c['type']
            if c['kind'] in ('masked', 'llm'):
                type_metrics[t]['support'] += 1
                if c['ok']:
                    type_metrics[t]['tp'] += 1
                else:
                    type_metrics[t]['fn'] += 1
                if c['kind'] == 'llm':
                    llm_only_total += 1
                    if c['ok']:
                        llm_hit_total += 1
            elif c['kind'] == 'kept':
                kept_total += 1
                if c['ok']:
                    continue
                kept_fail += 1
                type_metrics[t]['fp'] += 1          # 负样本误替换 → 该类型 FP
            elif c['kind'] == 'absent':
                absent_total += 1
                absent_fail += 0 if c['ok'] else 1
        if not llm_mode:
            llm_only_total += len([i for i in r['llm_only'] if not isinstance(i, str)])
        if r['failures']:
            failed_cases.append(r)

    def prf(tp, fp, fn):
        p = tp / (tp + fp) if tp + fp else 0.0
        r = tp / (tp + fn) if tp + fn else 0.0
        f = 2 * p * r / (p + r) if p + r else 0.0
        return p, r, f

    tags = sorted(type_metrics, key=lambda t: -type_metrics[t]['support'])
    TP = sum(v['tp'] for v in type_metrics.values())
    FP = sum(v['fp'] for v in type_metrics.values())
    FN = sum(v['fn'] for v in type_metrics.values())
    P, R, F = prf(TP, FP, FN)
    per_tag = {t: prf(v['tp'], v['fp'], v['fn']) for t, v in type_metrics.items()}
    macro_f = (sum(v[2] for v in per_tag.values()) / len(per_tag)
               if per_tag else 0.0)

    # 控制台报告
    print('=' * 72)
    print('法律文书脱敏规则层 — 红队评测报告')
    print('=' * 72)
    print(f'用例总数: {len(results)}   通过: {len(results) - len(failed_cases)}   失败: {len(failed_cases)}')
    print(f'评测模式: {"规则层+LLM层" if llm_mode else "仅规则层"}')
    print(f'正样本(expect_masked): {TP + FN} 项，命中 {TP} 项')
    print(f'负样本(expect_kept):   {kept_total} 项，误替换 {kept_fail} 项')
    if absent_total:
        print(f'泄露检查: {absent_total} 项，发现泄露 {absent_fail} 项')
    if llm_only_total:
        if llm_mode:
            print(f'LLM 层覆盖项（已计入）: {llm_hit_total}/{llm_only_total}')
        else:
            print(f'LLM 层待覆盖项（不计入）: {llm_only_total} 项')
    print()
    print('按类型指标（entity-level）：')
    print(f'  {"类型":<16}{"support":>8}{"precision":>11}{"recall":>9}{"F1":>9}')
    for t in tags:
        p, r, f = per_tag[t]
        v = type_metrics[t]
        mark = '✅' if f >= 0.95 else ('⚠️' if f >= 0.8 else '❌')
        print(f'  {mark} {t:<15}{v["support"]:>8}{p:>11.4f}{r:>9.4f}{f:>9.4f}')
    print('  ' + '-' * 53)
    print(f'  {"MICRO (overall)":<16}{TP + FN:>8}{P:>11.4f}{R:>9.4f}{F:>9.4f}')
    print(f'  {"MACRO (类型平均)":<16}{"":>8}{"":>11}{"":>9}{macro_f:>9.4f}')

    if failed_cases:
        print()
        print('失败用例明细：')
        for r in failed_cases:
            print(f'  [{r["id"]}] {r["note"]}')
            for c in r['failures']:
                if c['kind'] == 'masked':
                    print(f'    ✗ 未完全脱敏: {c["type"]} = {c["value"]}（{c["detail"]}）')
                elif c['kind'] == 'kept':
                    print(f'    ✗ 误脱敏: 应保留的 {c["value"]} 被替换')
                elif c['kind'] == 'absent':
                    print(f'    ✗ 泄露: 原文仍包含 {c["value"]}')
                elif c['kind'] == 'llm':
                    print(f'    ✗ LLM层未脱敏: {c["type"]} = {c["value"]}（{c["detail"]}）')

    # 输出 Markdown 报告
    if args.report:
        lines = [
            '# 法律文书脱敏规则层 — 红队评测报告',
            '',
            f'- 评测时间：{__import__("datetime").datetime.now().strftime("%Y-%m-%d %H:%M")}',
            f'- 语料库：{args.corpus}',
            f'- 模式：{"规则层+LLM层（--llm-api）" if llm_mode else "仅规则层"}'
            f'，日期：{"全量（--all-dates）" if args.all_dates else "默认（仅出生日期）"}',
            '',
            '## 总览',
            '',
            '| 指标 | 数值 |',
            '|------|------|',
            f'| 用例总数 | {len(results)} |',
            f'| 通过用例 | {len(results) - len(failed_cases)} |',
            f'| 正样本（expect_masked） | {TP + FN} |',
            f'| 命中（TP） | {TP} |',
            f'| 负样本（expect_kept） | {kept_total} |',
            f'| 误替换（FP） | {kept_fail} |',
            f'| precision（micro） | {P:.4f} |',
            f'| recall（micro） | {R:.4f} |',
            f'| F1（micro） | {F:.4f} |',
            f'| F1（macro，类型平均） | {macro_f:.4f} |',
        ]
        if absent_total:
            lines.append(f'| 泄露检查 | {absent_fail}/{absent_total} 项泄露 |')
        lines += [
            '',
            '## 按类型指标（entity-level，P/R/F1 + support）',
            '',
            '| 类型 | support | precision | recall | F1 |',
            '|------|--------:|----------:|-------:|----:|',
        ]
        for t in tags:
            p, r, f = per_tag[t]
            lines.append(f'| {t} | {type_metrics[t]["support"]} | {p:.4f} | {r:.4f} | {f:.4f} |')
        lines += [
            f'| **MICRO (overall)** | **{TP + FN}** | **{P:.4f}** | **{R:.4f}** | **{F:.4f}** |',
            f'| **MACRO (类型平均)** | | | | **{macro_f:.4f}** |',
        ]
        if failed_cases:
            lines += ['', '## 失败用例', '']
            for r in failed_cases:
                lines.append(f'### {r["id"]} — {r["note"]}')
                for c in r['failures']:
                    if c['kind'] == 'masked':
                        lines.append(f'- ✗ 未完全脱敏：{c["type"]} = `{c["value"]}`（{c["detail"]}）')
                    elif c['kind'] == 'kept':
                        lines.append(f'- ✗ 误脱敏：应保留的 `{c["value"]}` 被替换')
                    elif c['kind'] == 'absent':
                        lines.append(f'- ✗ 泄露：原文仍包含 `{c["value"]}`')
                    elif c['kind'] == 'llm':
                        lines.append(f'- ✗ LLM层未脱敏：{c["type"]} = `{c["value"]}`')
                lines.append(f'  - 原文：{r["masked"]}')
        with open(args.report, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines) + '\n')
        print(f'\n✅ Markdown 报告已保存: {args.report}')

    if args.json_out:
        payload = {
            'summary': {
                'cases': len(results),
                'passed': len(results) - len(failed_cases),
                'tp': TP,
                'fp': FP,
                'fn': FN,
                'micro': {'precision': P, 'recall': R, 'f1': F, 'support': TP + FN},
                'macro_f1': macro_f,
                'kept_total': kept_total,
                'kept_fail': kept_fail,
                'absent_total': absent_total,
                'absent_fail': absent_fail,
                'llm_only_total': llm_only_total,
                'llm_hit_total': llm_hit_total,
            },
            'by_type': {t: {'support': type_metrics[t]['support'],
                            'precision': per_tag[t][0],
                            'recall': per_tag[t][1],
                            'f1': per_tag[t][2],
                            'tp': type_metrics[t]['tp'],
                            'fp': type_metrics[t]['fp'],
                            'fn': type_metrics[t]['fn']}
                        for t in tags},
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
