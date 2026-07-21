#!/usr/bin/env python3
"""
法律文书脱敏工具 — 规则引擎 + LLM 混合脱敏
=============================================

Usage:
    # 命令行脱敏
    python desensitize.py scan < input.txt          # 仅扫描识别敏感信息
    python desensitize.py mask < input.txt           # 规则层脱敏（正则）
    python desensitize.py mask -f input.docx > out.txt  # 处理文件

    # Python 模块调用
    from desensitize import Desensitizer
    d = Desensitizer()
    result = d.mask("张三的电话是13800138000")
    # result.text -> "[当事人甲]的电话是[手机号]"
    # result.mapping -> [Mapping(original='张三', replacement='[当事人甲]', type='人名'), ...]
"""

import re
import sys
import json
import os
from dataclasses import dataclass, field, asdict
from typing import List, Optional


# ============================================================
# 数据模型
# ============================================================

@dataclass
class Mapping:
    """一条脱敏映射记录"""
    original: str
    replacement: str
    type: str           # 类型：身份证号、手机号、人名、公司名、地址、案号...
    count: int = 1      # 出现次数

    def to_dict(self):
        return {'original': self.original, 'replacement': self.replacement,
                'type': self.type, 'count': self.count}


@dataclass
class MaskResult:
    """脱敏结果"""
    text: str                    # 脱敏后的文本
    mapping: List[Mapping]       # 完整映射表
    stats: dict = field(default_factory=dict)  # 统计信息

    def to_json(self, indent=2):
        return json.dumps({
            'text': self.text,
            'mapping': [m.to_dict() for m in self.mapping],
            'stats': self.stats,
        }, ensure_ascii=False, indent=indent)

    def to_markdown(self):
        """生成脱敏映射表的 Markdown 格式"""
        lines = [
            "# 脱敏映射表",
            "",
            "| 序号 | 原始值 | 替换值 | 类型 | 出现次数 |",
            "|------|--------|--------|------|---------|",
        ]
        for i, m in enumerate(self.mapping, 1):
            lines.append(f"| {i} | {m.original} | {m.replacement} | {m.type} | {m.count} |")

        lines.extend(["", "", "## 统计", ""])
        for k, v in sorted(self.stats.items()):
            lines.append(f"- **{k}**: {v}")

        return "\n".join(lines)


# ============================================================
# 脱敏规则引擎
# ============================================================

class Desensitizer:
    """法律文书脱敏器 — 规则引擎层"""

    def __init__(self):
        # 已替换的记录，避免重复替换
        self._replaced = {}   # original -> (replacement, type)
        self._counter = {}    # type -> counter for unique naming
        self._stats = {}      # type -> count

        # 存储规则执行过程中需要跟踪的数据
        self._person_counter = 0
        self._company_counter = 0
        self._address_counter = 0
        self._court_counter = 0
        self._party_counter = 0

    # --------------------------------------------------------
    # 核心方法
    # --------------------------------------------------------

    def mask(self, text: str) -> MaskResult:
        """对文本执行规则层脱敏"""
        self._reset()
        original_text = text

        # 按顺序执行各规则（先精确匹配再宽泛匹配）
        text = self._mask_bar_number(text)    # 17位执业证号（优先于身份证号）
        text = self._mask_id_card(text)        # 18位身份证号
        text = self._mask_phone(text)           # 手机号
        text = self._mask_landline(text)        # 固定电话
        text = self._mask_email(text)           # 邮箱
        text = self._mask_wechat(text)          # 微信号
        text = self._mask_qq(text)              # QQ号
        text = self._mask_credit_code(text)     # 统一社会信用代码（含字母）
        text = self._mask_bank_card(text)       # 16-19位数字（排除了已匹配的）
        text = self._mask_case_number(text)     # 案号
        text = self._mask_license_plate(text)  # 车牌号
        text = self._mask_date(text)           # 日期

        # 构建映射表
        mapping = []
        for original, (replacement, typ) in self._replaced.items():
            mapping.append(Mapping(
                original=original,
                replacement=replacement,
                type=typ,
                count=self._stats.get(typ, 0)
            ))

        # 排序：按出现次数降序
        mapping.sort(key=lambda m: m.count, reverse=True)

        # 统计
        stats = dict(self._stats)
        stats['总脱敏项数'] = len(mapping)
        stats['总替换次数'] = sum(m.count for m in mapping)

        return MaskResult(text=text, mapping=mapping, stats=stats)

    def scan(self, text: str) -> List[dict]:
        """仅扫描，不替换，返回所有敏感信息位置"""
        findings = []
        for rule_name, pattern, _ in self._get_all_rules():
            for match in re.finditer(pattern, text):
                findings.append({
                    'type': rule_name,
                    'value': match.group(),
                    'start': match.start(),
                    'end': match.end(),
                })
        return findings

    # --------------------------------------------------------
    # 重置状态
    # --------------------------------------------------------

    def _reset(self):
        self._replaced = {}
        self._counter = {}
        self._stats = {}
        self._person_counter = 0
        self._company_counter = 0
        self._address_counter = 0
        self._court_counter = 0
        self._party_counter = 0

    # --------------------------------------------------------
    # 各规则实现
    # --------------------------------------------------------

    def _mask_bar_number(self, text: str) -> str:
        """
        律师执业证号：17-18位纯数字（必须优先于身份证号匹配）。
        注意：以执业证/律师证等关键词为上下文线索，捕获全部数字避免残留。
        """
        # 有明确上下文提示的：执业证号: 17位或18位数字
        def bar_replacer(m):
            original = m.group(2)
            replacement = '[律师执业证号]'
            self._replaced[original] = (replacement, '律师执业证号')
            self._stats['律师执业证号'] = self._stats.get('律师执业证号', 0) + 1
            return m.group(1) + '：' + replacement

        text = re.sub(
            r'(执业证号|律师执业证|执业证)[\s]*[：:]?[\s]*(\d{17,18})',
            bar_replacer,
            text
        )
        return text

    def _safe_replace(self, text: str, pattern: str, replacement: str,
                       typ: str, original_group: int = 0) -> str:
        """安全替换：记录替换日志，避免重复替换已替换的内容"""
        def replacer(m):
            original = m.group(original_group) if original_group > 0 else m.group()
            if original in self._replaced:
                return self._replaced[original][0]
            self._replaced[original] = (replacement, typ)
            self._stats[typ] = self._stats.get(typ, 0) + 1
            return replacement

        return re.sub(pattern, replacer, text)

    def _mask_id_card(self, text: str) -> str:
        """身份证号：18位，末位可能为X"""
        # 匹配18位数字，末位可能是X
        return self._safe_replace(
            text,
            r'(?<!\d)(\d{17}[\dXx])(?!\d)',
            '[身份证号]',
            '身份证号'
        )

    def _mask_phone(self, text: str) -> str:
        """手机号：11位，1开头"""
        return self._safe_replace(
            text,
            r'(?<!\d)(1[3-9]\d{9})(?!\d)',
            '[手机号]',
            '手机号'
        )

    def _mask_landline(self, text: str) -> str:
        """固定电话：含区号"""
        text = self._safe_replace(
            text,
            r'(?<!\d)(0\d{2,3}[-\s]?\d{7,8})(?!\d)',
            '[固定电话]',
            '固定电话'
        )
        # 400/800电话
        text = self._safe_replace(
            text,
            r'(?<!\d)([48]00[-\s]?\d{3}[-\s]?\d{4})(?!\d)',
            '[服务电话]',
            '固定电话'
        )
        return text

    def _mask_email(self, text: str) -> str:
        """邮箱地址 - 使用a-zA-Z避免匹配中文字符"""
        return self._safe_replace(
            text,
            r'[A-Za-z0-9.+-]+@[A-Za-z0-9-]+\.[A-Za-z0-9.-]+',
            '[邮箱]',
            '邮箱'
        )

    def _mask_wechat(self, text: str) -> str:
        """微信号"""
        # 微信号: xxx 或 微信: xxx
        text = re.sub(
            r'(微信号|微信)\s*[：:]\s*\S+',
            lambda m: m.group(1) + '：[微信号]',
            text
        )
        return text

    def _mask_qq(self, text: str) -> str:
        """QQ号"""
        text = re.sub(
            r'[Qq][Qq]\s*[：:]?\s*(\d{5,12})',
            lambda m: '[QQ号]',
            text
        )
        return text

    def _mask_bank_card(self, text: str) -> str:
        """银行卡号：16-19位纯数字"""
        # 注意：排除前面已匹配的身份证号(18位)、手机号(11位)的上下文
        return self._safe_replace(
            text,
            r'(?<!\d)(\d{16,19})(?!\d)',
            '[银行账号]',
            '银行账号'
        )

    def _mask_credit_code(self, text: str) -> str:
        """统一社会信用代码：18位字母数字（通常以9开头或特定规则）"""
        return self._safe_replace(
            text,
            r'(?<!\d)([0-9A-Z]{18})(?!\d)',
            '[统一社会信用代码]',
            '统一社会信用代码'
        )

    def _mask_case_number(self, text: str) -> str:
        """案号：(2024)京0108民初12345号 / (2024)最高法民申1234号 — 排除年月日误匹配"""
        return self._safe_replace(
            text,
            r'\(?\d{4}\)?(?![年月日])[\u4e00-\u9fa5]{1,10}\d{0,6}[\u4e00-\u9fa5]{0,6}\d{1,6}号',
            '[案号]',
            '案号'
        )

    def _mask_license_plate(self, text: str) -> str:
        """车牌号：粤B88888 / 京A12345 等格式 — 1个汉字省份简称+1个字母城市代码+5-6位字母数字"""
        return self._safe_replace(
            text,
            r'[\u4e00-\u9fa5][A-Z][A-Z0-9]{5,6}',
            '[车牌号]',
            '车牌号'
        )

    def _mask_date(self, text: str) -> str:
        """日期：年月日格式"""
        return self._safe_replace(
            text,
            r'(\d{4})年(\d{1,2})月(\d{1,2})日',
            '[日期]',
            '日期'
        )

    def _get_all_rules(self):
        """返回所有规则（用于scan）"""
        return [
            ('身份证号', r'\d{17}[\dXx]', self._mask_id_card),
            ('手机号', r'1[3-9]\d{9}', self._mask_phone),
            ('固定电话', r'0\d{2,3}[-\s]?\d{7,8}', self._mask_landline),
            ('邮箱', r'[\w.+-]+@[\w-]+\.[\w.-]+', self._mask_email),
            ('银行账号', r'\d{16,19}', self._mask_bank_card),
            ('统一社会信用代码', r'[0-9A-Z]{18}', self._mask_credit_code),
            ('案号', r'\(?\d{4}\)?[\u4e00-\u9fa5]{1,10}\(?\d{1,6}\)?\d{0,3}号?', self._mask_case_number),
            ('车牌号', r'[\u4e00-\u9fa5][A-Z][A-Z0-9]{5,6}', self._mask_license_plate),
            ('日期', r'\d{4}年\d{1,2}月\d{1,2}日', self._mask_date),
        ]


# ============================================================
# LLM 脱敏提示词生成
# ============================================================

LLM_PROMPT_TEMPLATE = """你是一个法律文书脱敏专家。以下文本已经完成了结构化数据脱敏（身份证号、手机号等已替换为占位符），现在请你识别文本中**剩余的敏感信息**，按照语义替换规则进行脱敏。

## 你需要识别并替换的内容

1. **人名**：所有自然人姓名（包括但不限于当事人、法定代表人、委托代理人、联系人、证人、法官、书记员等）
2. **公司/机构名**：所有企业、机构、组织的全称及简称
3. **地址**：精确到街道、门牌号的地址信息（如"北京市海淀区中关村大街1号"→"[地址]"，以"路""街""大道""号""室""层"结尾的精确地址）
4. **金额**：大额合同金额、赔偿金额等（小额如餐费、打车费等不处理）
5. **案情中的敏感细节**：涉及个人隐私、商业秘密、不宜公开的具体事实描述

## 替换规则

- 不同人用不同占位符：[当事人甲]、[当事人乙]、[法定代表人]、[委托代理人]、[法官]、[书记员]、[证人]等，**同一人必须用同一个占位符**
- 不同公司按角色区分：[合同甲方]、[合同乙方]、[第三方公司]、[担保方]等
- 法院名称 → [审理法院] 或 [一审法院] / [二审法院]
- 地址 → [地址]（保持一次即可）
- 金额 → [金额]
- 其他敏感细节用 `[具体信息概括]` 格式

## 输出格式

严格按照以下格式输出，以 `---` 分隔：

---
## 脱敏后内容

{脱敏后的完整文档}
---

## 补充映射表

| 原始值 | 替换值 | 类型 |
|--------|--------|------|
| 张三 | [当事人甲] | 人名 |
| 北京华信科技有限公司 | [合同甲方] | 公司名 |
...

---

## 脱敏前文本（已执行规则层）

{rule_masked_text}"""


def make_llm_prompt(rule_masked_text: str) -> str:
    """生成LLM脱敏提示词，供Reasonix Skill调用"""
    return LLM_PROMPT_TEMPLATE.replace('{rule_masked_text}', rule_masked_text)


# ============================================================
# 文件读取（支持 .txt / .docx / .pdf）
# ============================================================

def read_text_from_file(filepath: str) -> str:
    """自动检测文件格式并提取文本"""
    ext = os.path.splitext(filepath)[1].lower()

    if ext == '.txt':
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.read()

    elif ext == '.docx':
        try:
            from docx import Document
        except ImportError:
            sys.exit('❌ 需要安装 python-docx: pip3 install python-docx')
        doc = Document(filepath)
        paragraphs = [p.text for p in doc.paragraphs]
        # 也提取表格中的文本
        tables_text = []
        for table in doc.tables:
            for row in table.rows:
                cells = [cell.text for cell in row.cells]
                tables_text.append(' | '.join(cells))
        all_text = '\n'.join(paragraphs)
        if tables_text:
            all_text += '\n\n' + '\n'.join(tables_text)
        return all_text

    elif ext == '.pdf':
        try:
            import fitz
        except ImportError:
            sys.exit('❌ 需要安装 PyMuPDF: pip3 install PyMuPDF')
        doc = fitz.open(filepath)
        pages = []
        for page in doc:
            pages.append(page.get_text())
        doc.close()
        return '\n\n'.join(pages)

    else:
        # 当作纯文本尝试
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.read()


# ============================================================
# CLI 入口
# ============================================================

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description='法律文书脱敏工具 — 规则引擎层',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  # 从 stdin 读取，脱敏后输出到 stdout
  cat document.txt | python desensitize.py mask

  # 扫描敏感信息
  cat document.txt | python desensitize.py scan

  # 输出 JSON 格式
  cat document.txt | python desensitize.py mask --json

  # 输出脱敏映射表
  cat document.txt | python desensitize.py mask --mapping

  # 生成 LLM 脱敏提示词
  cat document.txt | python desensitize.py llm-prompt

  # 读取文件（支持 .txt .docx .pdf）
  python desensitize.py mask -f contract.docx
  python desensitize.py mask -f contract.pdf
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='子命令')

    # mask 命令
    mask_parser = subparsers.add_parser('mask', help='执行规则层脱敏')
    mask_parser.add_argument('-f', '--file', help='输入文件路径（默认从stdin读取）')
    mask_parser.add_argument('--json', action='store_true', help='以JSON格式输出')
    mask_parser.add_argument('--mapping', action='store_true', help='仅输出脱敏映射表')

    # scan 命令
    scan_parser = subparsers.add_parser('scan', help='扫描敏感信息（不替换）')
    scan_parser.add_argument('-f', '--file', help='输入文件路径（默认从stdin读取）')
    scan_parser.add_argument('--json', action='store_true', help='以JSON格式输出')

    # llm-prompt 命令
    llm_parser = subparsers.add_parser('llm-prompt', help='生成LLM脱敏提示词（规则层+LLM提示）')
    llm_parser.add_argument('-f', '--file', help='输入文件路径（默认从stdin读取）')

    args = parser.parse_args()

    # 读取输入（支持 .txt / .docx / .pdf）
    if hasattr(args, 'file') and args.file:
        text = read_text_from_file(args.file)
    else:
        text = sys.stdin.read()

    d = Desensitizer()

    if args.command == 'mask':
        result = d.mask(text)
        if args.mapping:
            print(result.to_markdown())
        elif args.json:
            print(result.to_json())
        else:
            # 输出脱敏后文本 + 映射表摘要
            print("=" * 60)
            print("【脱敏后文本】")
            print("=" * 60)
            print(result.text)
            print()
            print("=" * 60)
            print("【脱敏统计】")
            for k, v in result.stats.items():
                print(f"  {k}: {v}")
            print()
            print("=" * 60)
            print("【脱敏映射表】（共 {} 项）".format(len(result.mapping)))
            print("=" * 60)
            print(result.to_markdown())

    elif args.command == 'scan':
        findings = d.scan(text)
        if args.json:
            print(json.dumps(findings, ensure_ascii=False, indent=2))
        else:
            print(f"扫描到 {len(findings)} 处敏感信息")
            print("=" * 60)
            # 按类型分组
            from collections import defaultdict
            by_type = defaultdict(list)
            for f in findings:
                by_type[f['type']].append(f)
            for typ, items in sorted(by_type.items()):
                print(f"\n【{typ}】共 {len(items)} 处")
                for item in items[:5]:  # 最多显示5个
                    context_start = max(0, item['start'] - 10)
                    context_end = min(len(text), item['end'] + 10)
                    ctx = text[context_start:context_end].replace('\n', ' ')
                    print(f"  位置{item['start']}: ...{ctx}...")
                if len(items) > 5:
                    print(f"  ...还有 {len(items) - 5} 处")

    elif args.command == 'llm-prompt':
        result = d.mask(text)
        print(make_llm_prompt(result.text))

    else:
        parser.print_help()


if __name__ == '__main__':
    main()
