# -*- coding: utf-8 -*-
"""
LLM 模板银行 — 让 LLM 写中文法律文书模板，代码注入合法校验值（v3.0）
====================================================================

内化自 rizzo-pii 的 llm_template_bank.py，核心原则完全一致：

1. LLM 只写**法律文书的 prose**，且只能使用白名单占位符 {当事人甲}、{身份证}、
   {银行账号}…——严禁写任何真实或虚构的人名/地址/号码。
2. 真正的号码（身份证 GB 11643、信用代码 GB 32100、银行卡 Luhn…）由
   `generate_synthetic_pii.py` 用代码注入，构造上合法 → 评测时规则层必然命中，
   BIO 标注天然精确，且 LLM 永远不可能产出真实 PII。
3. QA 门控（clean_and_validate）：模板若夹带占位符外的"姓名/号码"（如
   "原告王某某诉张某"）→ 整条丢弃；无槽位、非中文、非法槽位也丢弃。
4. 内置模板兜底：不接 LLM（无 API key / 本地模型）也能直接用
   generate_synthetic_pii.py 生成语料（其内置 TEMPLATES 就是模板库）。

用法：
    # 后端一：OpenAI 兼容（本地 Ollama / LM Studio / 云端）
    export LLM_BASE_URL=http://127.0.0.1:11434/v1
    export LLM_MODEL=qwen2.5
    python3 synthetic/llm_template_bank.py --per-type 2 --out synthetic/legal_templates.json

    # 后端二：直接编辑 synthetic/legal_templates.json 手工补充模板（AI 可在
    # 本对话中直接产出模板 JSON），generate_synthetic_pii.py 自动加载。
"""

import argparse
import io
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', write_through=True)

# 槽位白名单 = generate_synthetic_pii 的注入器能填的所有槽位（单一事实源）
sys.path.insert(0, str(Path(__file__).resolve().parent))
import generate_synthetic_pii as _gen  # noqa: E402

ALLOWED_SLOTS = set(_gen._SLOT_LABELS) | set(_gen._SEMANTIC_SLOTS)

SLOT_HINTS = """  {当事人甲}/{当事人乙} = 自然人姓名（原告、被告、证人、审判员…）
  {公司甲}/{公司乙} = 公司/机构全称
  {身份证} = 居民身份证号    {银行账号} = 银行卡号/账号
  {信用代码} = 统一社会信用代码    {手机号} = 手机号
  {地址} = 详细地址（省市区路号）    {案号} = 案件编号
  {金额} = 具体金额    {车牌} = 机动车号牌    {邮箱} = 电子邮箱
  {出生日期} = 出生日期    {日期} = 普通日期（保留项，不脱敏）
  {法院} = 法院名称（保留项，不脱敏）"""

DOC_TYPES = [
    '民事判决书', '民事调解书', '行政处罚决定书', '建设工程施工合同',
    '借款合同', '律师函', '劳动仲裁申请书', '财产保全申请书',
    '刑事判决书', '离婚协议书', '房屋租赁合同', '执行申请书',
]

PROMPT = """你是一名中国法律文书专家。请写一份{doc_type}，要求内容真实可信、格式规范、
符合中国法院/行政机关的文书惯例，全文 10 到 30 行。

绝对规则：不得写入任何真实或虚构的个人信息（人名、身份证号、手机号、
银行卡号、地址、公司名、案号、金额等，一律不得虚构）。凡需要个人数据之处，
只能使用下方白名单中的占位符，写法必须完全一致（花括号包裹）：

{slot_list}

占位符说明：
{slot_hints}

每个占位符可重复使用多次。不得使用白名单以外的任何占位符。
严禁在正文中书写任何姓名（哪怕是"张三""李四"这类明显虚构的名字），
严禁写任何城市名、街道名、公司名——一律用对应占位符替代。
只输出文书正文本身，不要任何前后缀、说明、Markdown 代码块。"""

# 常见姓氏（用于 QA 门控，识别占位符外漏写的姓名）
_SURNAMES = set(_gen.SURNAME_POOL) | set(_gen.COMPOUND_SURNAME_POOL)
# 角色词后跟姓名的模式（漏写人名的最常见形态）
_ROLE_RE = re.compile(
    r'(原告|被告|上诉人|被上诉人|第三人|法定代表人|负责人|审判长|审判员|'
    r'书记员|委托代理人|证人|申请人|被申请人|出借人|借款人|承包人|发包人)'
    r'\s*([\u4e00-\u9fa5]{2,4})')
# 连续 2-4 字的中文串（用于检测"姓氏+名"裸名）
_NAME_RE = re.compile(r'[\u4e00-\u9fa5]{2,4}')
# 常见双字词（"人名"误报白名单）
_COMMON_WORDS = {
    '人民', '法院', '公司', '银行', '合同', '协议', '案件', '原告', '被告',
    '判决', '裁定', '调解', '审理', '执行', '上诉', '申请', '请求', '事实',
    '证据', '认为', '查明', '本院', '法庭', '书记', '审判', '公诉', '辩护',
    '代理', '委托', '送达', '开庭', '答辩', '反诉', '撤诉', '管辖', '回避',
    '当事人', '诉讼', '仲裁', '律师', '法官', '书记员', '执行员', '法警',
    '企业', '单位', '机构', '部门', '责任', '义务', '权利', '合法', '无效',
    '违约', '赔偿', '利息', '本金', '借款', '货款', '工资', '租金', '定金',
    '违约金', '保证金', '预付款', '建设工程', '施工', '竣工验收', '结算',
}

SLOT_RE = re.compile(r'\{([A-Za-z\u4e00-\u9fa5]+)\}')


def _is_person_name(s):
    """疑似人名：首字为常见姓氏，其余部分不是常见词/词尾。"""
    if len(s) < 2 or len(s) > 4:
        return False
    if s[0] not in _SURNAMES:
        return False
    if s in _COMMON_WORDS:
        return False
    # 词尾在黑名单（如"人民""公司"结尾）也不是人名
    return not any(s.endswith(w) or w.endswith(s) for w in _COMMON_WORDS if len(w) >= 2)


def find_stray_names(text):
    """占位符外漏写的姓名：角色词+2~4字，或"姓氏+名"连续串。"""
    masked = SLOT_RE.sub(' ', text)          # 先摘掉占位符
    stray = []
    for m in _ROLE_RE.finditer(masked):
        name = m.group(2)
        if _is_person_name(name):
            stray.append(m.group(0).strip())
    for name in _NAME_RE.findall(masked):
        if _is_person_name(name):
            stray.append(name)
    return stray


def clean_and_validate(text):
    """QA 门控：无槽位/非法槽位/夹带姓名/非中文 → 丢弃。"""
    if not text or not text.strip():
        return None
    text = re.sub(r'^```.*?\n|```$', '', text.strip(), flags=re.MULTILINE).strip()
    slots = set(SLOT_RE.findall(text))
    if not slots:
        print('  丢弃：无占位符')
        return None
    if slots - ALLOWED_SLOTS:
        print(f'  丢弃：非法占位符 {sorted(slots - ALLOWED_SLOTS)[:6]}')
        return None
    stray = find_stray_names(text)
    if stray:
        print(f'  丢弃：占位符外疑似姓名 {sorted(set(stray))[:6]}')
        return None
    # 非中文文本（模型跑偏输出英文/乱码）
    han = len(re.findall(r'[\u4e00-\u9fa5]', text))
    if han < 10:
        print('  丢弃：非中文/文本过短')
        return None
    return text


def call_llm(prompt, config):
    """调 OpenAI 兼容后端（本地 Ollama/LM Studio 或云端）。"""
    from llm_layer import LLMConfig, call_llm as _call
    try:
        return _call(prompt, config)
    except Exception as e:
        print(f'  LLM 调用失败：{e}')
        return None


def main():
    ap = argparse.ArgumentParser(description='LLM 中文法律文书模板银行（QA 门控）')
    ap.add_argument('--per-type', type=int, default=2, help='每种文书生成条数')
    ap.add_argument('--out', default=str(ROOT / 'synthetic' / 'legal_templates.json'))
    ap.add_argument('--append', action='store_true', help='追加到已有文件')
    ap.add_argument('--llm-endpoint', default=os.environ.get('LLM_BASE_URL', ''),
                    help='OpenAI 兼容端点（默认读 LLM_BASE_URL）')
    ap.add_argument('--llm-model', default=os.environ.get('LLM_MODEL', 'qwen2.5'))
    ap.add_argument('--llm-api-key', default=os.environ.get('LLM_API_KEY', ''))
    args = ap.parse_args()

    if not args.llm_endpoint:
        sys.exit('❌ 未配置 LLM：export LLM_BASE_URL=http://127.0.0.1:11434/v1 '
                 '（或用 generate_synthetic_pii.py 的内置模板，无需 LLM）')
    from llm_layer import LLMConfig
    config = LLMConfig(api='openai', model=args.llm_model,
                       endpoint=args.llm_endpoint, api_key=args.llm_api_key,
                       timeout=180)

    templates = []
    if args.append and os.path.exists(args.out):
        templates = json.load(open(args.out, encoding='utf-8'))
        print(f'追加到 {len(templates)} 个已有模板')
    tid = len(templates)

    slot_list = '\n'.join(f'  {{{s}}}' for s in sorted(ALLOWED_SLOTS))
    total = len(DOC_TYPES) * args.per_type
    ok = skip = 0
    for dt in DOC_TYPES:
        for _ in range(args.per_type):
            raw = call_llm(
                PROMPT.format(doc_type=dt, slot_list=slot_list,
                              slot_hints=SLOT_HINTS), config)
            text = clean_and_validate(raw)
            if text:
                templates.append({'id': tid, 'doc_type': dt, 'text': text})
                tid += 1
                ok += 1
                json.dump(templates, open(args.out, 'w', encoding='utf-8'),
                          ensure_ascii=False, indent=2)   # 增量保存
                print(f'  ✓ 通过 {dt}（{len(SLOT_RE.findall(text))} 槽位）')
            else:
                skip += 1

    print(f'\n完成：通过 {ok} / 丢弃 {skip} / 模板总数 {len(templates)} -> {args.out}')
    print('下一步：python3 synthetic/generate_synthetic_pii.py '
          '（注入合法校验值并自动标注期望）')


if __name__ == '__main__':
    main()
