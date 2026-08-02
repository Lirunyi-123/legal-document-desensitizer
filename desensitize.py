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
import secrets
import calendar
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
    order: int = 0      # 首次出现顺序（用于还原时按原文顺序配对）

    def to_dict(self):
        return {'original': self.original, 'replacement': self.replacement,
                'type': self.type, 'count': self.count, 'order': self.order}


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
        for i, m in enumerate(sorted(self.mapping, key=lambda m: m.order), 1):
            lines.append(f"| {i} | {m.original} | {m.replacement} | {m.type} | {m.count} |")

        lines.extend(["", "", "## 统计", ""])
        for k, v in sorted(self.stats.items()):
            lines.append(f"- **{k}**: {v}")

        return "\n".join(lines)


# ============================================================
# 规则辅助函数（mask 与 scan 共用）
# ============================================================

def _is_valid_id_birthdate(value: str) -> bool:
    """粗略校验身份证号第 6-14 位是否为有效出生日期（无标签身份证的判据）。"""
    if len(value) != 18:
        return False
    try:
        year = int(value[6:10])
        month = int(value[10:12])
        day = int(value[12:14])
    except ValueError:
        return False
    if not (1900 <= year <= 2100) or not (1 <= month <= 12):
        return False
    return 1 <= day <= calendar.monthrange(year, month)[1]


# GB 11643-1999 居民身份证校验
# 前17位加权因子与第18位校验码映射表
_ID_WEIGHTS = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
_ID_CHECK_CODES = '10X98765432'


def _is_valid_id_checksum(value: str) -> bool:
    """GB 11643 身份证第18位校验码验证。

    只有通过校验码验证的号码才是真正合法的身份证号，可有效区分
    "长得像身份证的银行卡/订单号"与真实身份证号。
    """
    if len(value) != 18 or not value[:17].isdigit():
        return False
    total = sum(int(value[i]) * _ID_WEIGHTS[i] for i in range(17))
    return value[17].upper() == _ID_CHECK_CODES[total % 11]


def _is_plausible_id(value: str) -> bool:
    """无标签身份证判定：GB 11643 校验码合法，或内嵌有效出生日期（兼容录入错误）。"""
    return _is_valid_id_checksum(value) or _is_valid_id_birthdate(value)


# GB 32100-2015 统一社会信用代码校验
# 18位字符集（排除 I O S V Z），加权因子
_CREDIT_ALPHABET = '0123456789ABCDEFGHJKLMNPQRTUWXY'
_CREDIT_WEIGHTS = [1, 3, 9, 27, 19, 26, 16, 17, 20, 29, 25, 13, 8, 24, 10, 30, 28]


def _is_valid_credit_code(value: str) -> bool:
    """GB 32100 统一社会信用代码第18位校验码验证（含 9 字头主体标识码规则）。"""
    if len(value) != 18:
        return False
    value = value.upper()
    total = 0
    for i, ch in enumerate(value[:17]):
        if ch not in _CREDIT_ALPHABET:
            return False
        total += _CREDIT_ALPHABET.index(ch) * _CREDIT_WEIGHTS[i]
    check = _CREDIT_ALPHABET[(31 - total % 31) % 31]
    return check == value[17]


def _luhn_check(value: str) -> bool:
    """Luhn 算法校验银行卡号。"""
    if not value.isdigit() or len(value) < 12:
        return False
    total = 0
    reverse = value[::-1]
    for i, ch in enumerate(reverse):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


# 带上下文的规则：前缀组保留原文，目标值进入映射表
_BAR_PATTERN = re.compile(
    r'((?:执业证号|执业许可证号|律师执业证号|律师执业证|执业证)\s*[：:]?\s*)'
    r'([0-9A-Z]{17,18})'
)
_ID_CONTEXT = re.compile(
    r'((?:身份证号|身份证号码|身份证|证件号码|证件号)\s*[：:]?\s*)'
    r'(\d{17}[\dXx])'
)
_CREDIT_CONTEXT = re.compile(
    r'((?:统一社会信用代码|社会信用代码|信用代码)\s*[：:]?\s*)'
    r'([0-9A-Z]{18})'
)
_BIRTHDATE_CONTEXT = re.compile(
    r'((?:出生日期|出生年月|生日|出生于|生于)\s*[：:]?\s*)(\d{4}年\d{1,2}月\d{1,2}日)'
    r'|(\d{4}年\d{1,2}月\d{1,2}日)\s*(?:出生|生)'
)
_QQ_PATTERN = re.compile(
    r'((?:QQ|Qq|qq)\s*[：:]?\s*)(\d{5,12})(?!\d)'
)

# 其他证件（带上下文，律师办案常见）
_OTHER_CERT_PATTERNS = [
    (r'((?:护照|护照号)\s*[：:]?\s*)([A-Za-z0-9]{6,12})', '护照号'),
    (r'((?:港澳通行证|往来港澳通行证|港澳居民来往内地通行证)\s*[：:]?\s*)([A-Za-z0-9]{5,12})', '港澳通行证'),
    (r'((?:台湾居民来往大陆通行证|台胞证)\s*[：:]?\s*)([A-Za-z0-9]{5,12})', '台胞证'),
    (r'((?:驾驶证|驾驶证号|驾驶证号码)\s*[：:]?\s*)([0-9A-Za-z]{6,20})', '驾驶证号'),
    (r'((?:军官证|士兵证|警官证|工作证)\s*[：:]?\s*)([0-9A-Za-z]{4,20})', '军官证'),
    (r'((?:营业执照|营业执照号|营业执照号码)\s*[：:]?\s*)([0-9A-Za-z]{8,20})', '营业执照号'),
    (r'((?:税务登记证号|税务登记号)\s*[：:]?\s*)([0-9A-Za-z]{8,20})', '税务登记号'),
]

# 银行账号（带上下文，标签具有权威性，无条件替换）
_ACCOUNT_CONTEXT = re.compile(
    r'((?:银行账号|开户账号|账户号码|银行卡号|收款账号|付款账号|卡号)\s*[：:]?\s*)'
    r'([0-9]{12,24})'
)

# 组织机构代码（老式 8-1 位格式，如 69920000-2）
_ORG_CODE_PATTERN = re.compile(r'(?<![0-9A-Z-])([0-9A-Z]{8}-[0-9A-Z])(?![0-9A-Z-])')


# ============================================================
# 实体归一化与角色绑定
# ============================================================

class EntityResolver:
    """实体归一化与角色绑定层
    
    解决问题：
    1. 同一实体不同表述 → 统一ID（金进跃 = 原告金进跃 = 金进跃先生）
    2. 公司名称无区分 → 按角色生成不同占位符（甲方/乙方/第三方）
    3. 角色绑定基于上下文 → 而非出现顺序
    4. 简称可链接到全称 → 鼎盛公司 → 杭州鼎盛房地产开发有限公司
    """
    
    ROLE_LABELS = {
        'plaintiff': '当事人甲（原告）',
        'defendant': '当事人乙（被告）',
        'third_party': '当事人丙（第三人）',
        'judge': '法官',
        'clerk': '书记员',
        'lawyer': '委托代理人',
        'legal_rep': '法定代表人',
        'guarantor': '担保方',
        'contract_a': '合同甲方',
        'contract_b': '合同乙方',
        'subcontractor': '分包方',
    }
    
    COMPANY_ROLE_LABELS = {
        'plaintiff': '合同甲方',
        'defendant': '合同乙方',
        'contract_a': '合同甲方',
        'contract_b': '合同乙方',
        'guarantor': '担保方',
        'subcontractor': '分包方',
        'third_party': '第三方公司',
    }
    
    # 角色关键词 → 归一化角色名
    ROLE_KEYWORDS = {
        '原告': 'plaintiff', '上诉人': 'plaintiff', '申请执行人': 'plaintiff',
        '被告': 'defendant', '被上诉人': 'defendant', '被执行人': 'defendant',
        '第三人': 'third_party',
        '审判员': 'judge', '审判长': 'judge', '代理审判员': 'judge',
        '书记员': 'clerk',
        '委托诉讼代理人': 'lawyer', '委托代理人': 'lawyer',
        '法定代表人': 'legal_rep', '负责人': 'legal_rep',
        '甲方': 'contract_a', '发包人': 'contract_a',
        '乙方': 'contract_b', '承包人': 'contract_b',
        '担保方': 'guarantor',
    }
    
    def __init__(self):
        self._canonical_map: Dict[str, str] = {}  # 归一化文本 → 统一ID
        self._role_bindings: Dict[str, str] = {}  # 统一ID → 角色占位符
        self._id_original: Dict[str, str] = {}    # 统一ID → 首次出现的原始文本
        self._person_counter = 0
        self._company_counter = 0
    
    def normalize(self, text: str) -> str:
        """归一化文本：去空格、统一全半角、去冗余修饰"""
        text = text.replace(' ', '').replace('\u3000', '').replace('\t', '')
        # 去除常见称谓后缀
        for suffix in ['先生', '女士', '同志', '律师', '法官']:
            if text.endswith(suffix) and len(text) > len(suffix) + 1:
                text = text[:-len(suffix)]
        return text
    
    def normalize_company(self, name: str) -> str:
        """公司名归一化：去除常见后缀以匹配简称"""
        for suffix in ['有限公司', '股份有限公司', '有限责任公司', '集团公司', '合伙企业',
                       '律师事务所', '会计师事务所', '事务所']:
            if name.endswith(suffix):
                return name[:-len(suffix)]
        return name
    
    def resolve_person(self, name: str, role: str = '') -> tuple:
        """
        解析人名实体：归一化 → 分配或查找ID → 绑定角色 → 生成占位符
        
        返回: (entity_id, placeholder)
        """
        canonical = self.normalize(name)
        role = self.ROLE_KEYWORDS.get(role, role)
        
        # 查找或创建
        if canonical not in self._canonical_map:
            self._person_counter += 1
            ent_id = f'person_{self._person_counter}'
            self._canonical_map[canonical] = ent_id
            self._id_original[ent_id] = name
        else:
            ent_id = self._canonical_map[canonical]
        
        # 角色绑定（不覆盖已有角色，除非冲突）
        if role and ent_id not in self._role_bindings:
            self._role_bindings[ent_id] = role
        
        return ent_id, self._make_placeholder(ent_id)
    
    def resolve_company(self, name: str, role: str = '') -> tuple:
        """
        解析公司实体：处理全称和简称的归一化链接
        """
        # 先尝试精确匹配
        if name in self._canonical_map:
            ent_id = self._canonical_map[name]
            if role and ent_id not in self._role_bindings:
                self._role_bindings[ent_id] = role
            return ent_id, self._make_placeholder(ent_id)
        
        # 归一化后匹配（简称链接到全称）
        canonical = self.normalize_company(name)
        for existing_canonical, existing_id in self._canonical_map.items():
            if self.normalize_company(existing_canonical) == canonical:
                self._canonical_map[name] = existing_id
                if role and existing_id not in self._role_bindings:
                    self._role_bindings[existing_id] = role
                return existing_id, self._make_placeholder(existing_id)
        
        # 新实体
        self._company_counter += 1
        ent_id = f'company_{self._company_counter}'
        self._canonical_map[name] = ent_id
        self._id_original[ent_id] = name
        if role:
            self._role_bindings[ent_id] = role
        
        return ent_id, self._make_placeholder(ent_id)
    
    def _make_placeholder(self, entity_id: str) -> str:
        """生成语义占位符"""
        parts = entity_id.split('_')
        entity_type = parts[0]
        idx = parts[1]
        
        role = self._role_bindings.get(entity_id, '')
        
        if entity_type == 'company':
            label = self.COMPANY_ROLE_LABELS.get(role, f'公司_{idx}')
            return f'[{label}]'
        else:
            label = self.ROLE_LABELS.get(role, f'当事人_{idx}')
            return f'[{label}]'
    
    def get_entity_original(self, entity_id: str) -> str:
        """获取实体首次出现的原始文本"""
        return self._id_original.get(entity_id, entity_id)
    
    def reset(self):
        """重置解析器状态"""
        self._canonical_map.clear()
        self._role_bindings.clear()
        self._id_original.clear()
        self._person_counter = 0
        self._company_counter = 0
# ============================================================
# 脱敏规则引擎
# ============================================================

class Desensitizer:
    """法律文书脱敏器 — 规则引擎层"""

    def __init__(self, mask_all_dates: bool = False):
        # 实体归一化解析器（用于人名/公司名的角色绑定）
        self._resolver = EntityResolver()
        # True 时把所有"年月日"日期替换为 [日期]；默认仅处理带出生上下文的日期
        self._mask_all_dates = mask_all_dates

        # 已替换的记录，避免重复替换
        self._replaced = {}   # original -> (replacement, type)
        self._counts = {}     # original -> 出现次数（按原始值统计）
        self._order = {}      # original -> 首次出现顺序（用于还原）
        self._counter = {}    # type -> counter for unique naming
        self._stats = {}      # type -> count

    # --------------------------------------------------------
    # 核心方法
    # --------------------------------------------------------

    def mask(self, text: str) -> MaskResult:
        """对文本执行规则层脱敏"""
        self._reset()

        # 预处理：清洗零宽字符、全角字母转半角
        text = self._preprocess(text)
        self._original_text = text  # 保留原文用于跨规则的出现顺序修正

        text = self._run_rules(text)
        return self._finalize(text)

    def mask_with_ner(self, text: str, ner_backend=None) -> MaskResult:
        """规则层 + 本地 NER 层脱敏。

        ner_backend: ner_interface.LegalNER 实例（spaCy / HuggingFace / 本地 LLM），
        在规则层完成后，再识别规则覆盖不到的人名、公司名、地址、法院等
        非结构化实体并替换，同一实体仍由 EntityResolver 归一化。
        """
        self._reset()
        text = self._preprocess(text)
        self._original_text = text

        text = self._run_rules(text)
        if ner_backend is not None:
            text = self._apply_ner_entities(text, ner_backend)
        return self._finalize(text)

    def _run_rules(self, text: str) -> str:
        """按顺序执行全部规则层正则（先精确匹配再宽泛匹配）。"""
        # 按顺序执行各规则（先精确匹配再宽泛匹配）
        text = self._mask_bar_number(text)    # 律师执业证号（带上下文，优先）
        text = self._mask_other_cert(text)    # 护照/港澳通行证/驾驶证等证件号（优先于身份证/微信，避免误判）
        text = self._mask_id_card(text)        # 身份证号（上下文优先，无标签需内嵌有效出生日期）
        text = self._mask_email(text)           # 邮箱（优先于手机号，避免"138...@qq.com"被拆开）
        text = self._mask_phone(text)           # 手机号
        text = self._mask_landline(text)        # 固定电话
        text = self._mask_wechat(text)          # 微信号
        text = self._mask_qq(text)              # QQ号
        text = self._mask_org_code(text)        # 组织机构代码（8-1位格式）
        text = self._mask_credit_code(text)     # 统一社会信用代码（带"信用代码"上下文）
        text = self._mask_bank_card(text)       # 14-20位纯数字银行账号
        text = self._mask_credit_code_bare(text)  # 统一社会信用代码（无标签，9开头18位）
        text = self._mask_case_number(text)     # 案号
        text = self._mask_license_plate(text)  # 车牌号
        if self._mask_all_dates:
            text = self._mask_date(text)        # 全部"年月日"日期
        else:
            text = self._mask_birthdate(text)   # 仅带出生上下文的日期
        text = self._mask_person_name(text)    # 人名（角色词上下文）
        text = self._mask_company_name(text)   # 公司名
        text = self._mask_address(text)        # 地址
        text = self._mask_amount(text)         # 金额（带单位的大额数字）
        return text

    def _finalize(self, text: str) -> MaskResult:
        """构建映射表与统计（mask / mask_with_ner 共用）。"""
        # 修正映射顺序：按原文出现顺序重新编号（还原时按原文顺序配对）
        self._assign_text_order(self._original_text)

        # 构建映射表
        mapping = []
        for original, (replacement, typ) in self._replaced.items():
            mapping.append(Mapping(
                original=original,
                replacement=replacement,
                type=typ,
                count=self._counts.get(original, 0),
                order=self._order.get(original, 0)
            ))

        # 排序：按首次出现顺序（还原时按原文顺序配对）
        mapping.sort(key=lambda m: m.order)

        # 统计
        stats = dict(self._stats)
        stats['总脱敏项数'] = len(mapping)
        stats['总替换次数'] = sum(m.count for m in mapping)

        return MaskResult(text=text, mapping=mapping, stats=stats)

    def _apply_ner_entities(self, text: str, ner_backend) -> str:
        """用本地 NER 识别规则层未覆盖的实体并替换为语义占位符。"""
        try:
            from ner_interface import EntityType
        except ImportError:
            return text

        ner_result = ner_backend.extract(text)
        entities = [e for e in ner_result.entities
                    if e.confidence >= 0.5 and '[' not in e.text and ']' not in e.text]
        entities.sort(key=lambda e: (e.start, -e.end))

        # 第一遍：正序解析并记录映射（保证 order 与原文一致）
        for e in entities:
            self._resolve_ner_entity(e, EntityType, record=True)

        # 第二遍：逆序替换，避免位置偏移
        for e in reversed(entities):
            placeholder, typ = self._resolve_ner_entity(e, EntityType, record=False)
            if not placeholder:
                continue
            text = text[:e.start] + placeholder + text[e.end:]
        return text

    def _resolve_ner_entity(self, entity, EntityType, record: bool) -> tuple:
        """解析单个 NER 实体 → (占位符, 类型)；record=True 时记入映射表。"""
        etype = entity.type
        value = entity.text

        if etype == EntityType.LAWYER:
            _, placeholder = self._resolver.resolve_person(value, 'lawyer')
            typ = '人名'
        elif etype == EntityType.PERSON:
            role = self._detect_role_before(value, self._original_text)
            _, placeholder = self._resolver.resolve_person(value, role)
            typ = '人名'
        elif etype == EntityType.COMPANY:
            _, placeholder = self._resolver.resolve_company(value)
            typ = '公司名'
        elif etype == EntityType.COURT:
            placeholder = '[审理法院]' if '法院' in value else '[法院]'
            typ = '法院'
        elif etype == EntityType.ADDRESS:
            placeholder = '[地址]'
            typ = '地址'
        else:
            return ('', '')

        if record:
            self._record(value, placeholder, typ)
        return (placeholder, typ)

    def _detect_role_before(self, value: str, text: str) -> str:
        """在原文中查找实体前最近的诉讼角色关键词（用于占位符语义）。"""
        pos = text.find(value)
        if pos == -1:
            return ''
        context_before = text[max(0, pos - 20):pos]
        best_role, best_pos = '', -1
        for kw, role in self._resolver.ROLE_KEYWORDS.items():
            p = context_before.rfind(kw)
            if p > best_pos:
                best_pos, best_role = p, role
        return best_role

    def scan(self, text: str) -> List[dict]:
        """仅扫描，不替换，返回所有敏感信息位置"""
        findings = []
        for rule in self._get_all_rules():
            rule_name = rule['type']
            pattern = rule['pattern']
            for match in re.finditer(pattern, text):
                value = match.group(rule.get('group', 0))
                confidence = 1.0
                validate = rule.get('validate')
                if validate is not None:
                    confidence = validate(value)
                findings.append({
                    'type': rule_name,
                    'value': value,
                    'start': match.start(),
                    'end': match.end(),
                    'confidence': confidence,
                })
        return findings

    # --------------------------------------------------------
    # 重置状态
    # --------------------------------------------------------

    def _reset(self):
        self._resolver.reset()
        self._replaced = {}
        self._counts = {}
        self._order = {}
        self._counter = {}
        self._stats = {}
        self._court_counter = 0
        self._party_counter = 0

    def _preprocess(self, text: str) -> str:
        """
        文本预处理：清除影响正则匹配的干扰字符
        - 去除零宽空格（U+200B-U+200D, U+FEFF）
        - 全角字母/数字转半角
        - 全角空格转半角
        """
        # 零宽字符
        text = re.sub(r'[\u200b\u200c\u200d\ufeff]', '', text)
        # 全角字母转半角
        text = re.sub(r'[\uff21-\uff3a]', lambda m: chr(ord(m.group()) - 0xfee0), text)
        text = re.sub(r'[\uff41-\uff5a]', lambda m: chr(ord(m.group()) - 0xfee0), text)
        # 全角数字转半角
        text = re.sub(r'[\uff10-\uff19]', lambda m: chr(ord(m.group()) - 0xfee0), text)
        # 全角空格转半角
        text = text.replace('\u3000', ' ')
        return text

    # --------------------------------------------------------
    # 各规则实现
    # --------------------------------------------------------

    def _mask_bar_number(self, text: str) -> str:
        """
        律师执业证号：带"执业证"上下文（含"执业许可证号"）的 17-18 位字母数字，
        必须优先于身份证号/信用代码匹配，避免律所执业许可证被误判为信用代码。
        """
        def bar_replacer(m):
            self._record(m.group(2), '[律师执业证号]', '律师执业证号')
            return m.group(1) + '[律师执业证号]'
        return _BAR_PATTERN.sub(bar_replacer, text)

    def _record(self, original: str, replacement: str, typ: str) -> None:
        """记录一次替换：去重、按原始值计数、按类型统计。"""
        self._replaced[original] = (replacement, typ)
        self._counts[original] = self._counts.get(original, 0) + 1
        if original not in self._order:
            self._order[original] = len(self._order) + 1
        self._stats[typ] = self._stats.get(typ, 0) + 1

    def _assign_text_order(self, original_text: str) -> None:
        """按原文出现顺序给映射条目重新编号。

        规则引擎按"规则顺序"执行（如金额的多种写法分多个 pass），
        与原文出现顺序可能不一致；还原（restore）需要按原文顺序
        把占位符逐一配对回原始值，因此用全部规则在原文上做一次
        最左匹配优先扫描，把每个原始值映射到它在原文中的首次出现序号。
        """
        rules = self._get_all_rules()
        compiled = []
        for rule in rules:
            try:
                pat = re.compile(rule['pattern'])
            except re.error:
                continue
            compiled.append((pat, rule.get('group', 0), rule.get('validate')))
        if not compiled:
            return

        order_map = {}
        order_seq = 0
        pos = 0
        n = len(original_text)
        while pos < n:
            best_start, best_end, best_value = n + 1, -1, None
            for pat, group, validate in compiled:
                m = pat.search(original_text, pos)
                if not m:
                    continue
                value = m.group(group) if group else m.group()
                if validate is not None:
                    try:
                        if not validate(value):
                            continue
                    except Exception:
                        continue
                if (m.start() < best_start or
                        (m.start() == best_start and m.end() > best_end)):
                    best_start, best_end, best_value = m.start(), m.end(), value
            if best_start > n:
                break
            if best_value is not None and best_value not in order_map:
                order_seq += 1
                order_map[best_value] = order_seq
            pos = best_end if best_end > best_start else best_start + 1

        # 覆盖为原文顺序（仅对确实出现在原文中的值）
        for value, order in order_map.items():
            if value in self._order:
                self._order[value] = order

    def _safe_replace(self, text: str, pattern: str, replacement: str,
                       typ: str, original_group: int = 0,
                       validate=None) -> str:
        """安全替换：记录替换日志，同一原始值沿用同一占位符，出现次数按值累计。

        validate: 可选校验函数，返回 False 时不替换（保留原文本）。
        """
        def replacer(m):
            original = m.group(original_group) if original_group > 0 else m.group()
            if validate is not None and not validate(original):
                return m.group(0)
            if original in self._replaced:
                # 同一原始值再次出现：沿用原占位符，计数照常累加
                self._counts[original] = self._counts.get(original, 0) + 1
                self._stats[typ] = self._stats.get(typ, 0) + 1
                return self._replaced[original][0]
            self._record(original, replacement, typ)
            return replacement

        return re.sub(pattern, replacer, text)

    def _mask_id_card(self, text: str) -> str:
        """身份证号：18位，末位可能为X。

        带"身份证/证件"上下文时无条件替换；无标签的 18 位数字要求
        GB 11643 校验码合法或内嵌有效出生日期，其余由银行卡规则处理，
        避免 18 位银行账号/订单号被误判为身份证号。
        """
        def context_replacer(m):
            self._record(m.group(2), '[身份证号]', '身份证号')
            return m.group(1) + '[身份证号]'
        text = _ID_CONTEXT.sub(context_replacer, text)
        return self._safe_replace(
            text,
            r'(?<!\d)(\d{17}[\dXx])(?!\d)',
            '[身份证号]',
            '身份证号',
            validate=_is_plausible_id
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
        """微信号：匹配有前缀 或 独立出现的微信号模式"""
        # 微信号: xxx 或 微信: xxx（有前缀，带冒号）
        text = re.sub(
            r'(微信号|微信)\s*[：:]\s*([a-zA-Z][a-zA-Z0-9_]{4,19})',
            lambda m: self._safe_replace_wechat(m.group(2), m.group(1)),
            text
        )
        # 独立微信号：字母开头 + 字母数字下划线，6-20位
        # 使用 [a-zA-Z0-9_] 而非 \w 避免匹配中文
        # 排除邮箱（含@）、URL、纯数字；前面紧贴中文时不算（避免误吞"粤B88888"这类车牌）
        text = re.sub(
            r'(?<![\u4e00-\u9fa5a-zA-Z0-9_@/.])([a-zA-Z][a-zA-Z0-9_]{5,19})(?![a-zA-Z0-9_@]|\.com|\.cn)',
            lambda m: self._safe_replace_wechat(m.group(1)),
            text
        )
        return text

    def _safe_replace_wechat(self, original: str, prefix: str = '') -> str:
        """记录微信号替换"""
        self._record(original, '[微信号]', '微信号')
        return f'{prefix}：[微信号]' if prefix else '[微信号]'

    def _mask_qq(self, text: str) -> str:
        """QQ号：保留前缀并记录映射"""
        def qq_replacer(m):
            self._record(m.group(2), '[QQ号]', 'QQ号')
            return m.group(1) + '[QQ号]'
        return _QQ_PATTERN.sub(qq_replacer, text)

    def _mask_bank_card(self, text: str) -> str:
        """银行卡号：14-20位纯数字（覆盖各银行不同长度）"""
        # 注意：排除前面已匹配的身份证号(18位)、手机号(11位)的上下文
        # 常见银行卡长度：招行16位、建行19位、部分旧卡15位、企业账户20位
        text = self._safe_replace(
            text,
            r'(?<!\d)(\d{14,20})(?!\d)',
            '[银行账号]',
            '银行账号'
        )
        # 带"账号/卡号"上下文的 12-24 位数字：标签权威，无条件替换
        return _ACCOUNT_CONTEXT.sub(self._account_replacer, text)

    def _account_replacer(self, m):
        self._record(m.group(2), '[银行账号]', '银行账号')
        return m.group(1) + '[银行账号]'

    def _mask_other_cert(self, text: str) -> str:
        """其他证件号码（护照、港澳通行证、驾驶证等）：带上下文标签识别。"""
        for pattern, label in _OTHER_CERT_PATTERNS:
            def make_replacer(lbl):
                def replacer(m):
                    self._record(m.group(2), f'[{lbl}]', lbl)
                    return m.group(1) + f'[{lbl}]'
                return replacer
            text = re.sub(pattern, make_replacer(label), text)
        return text

    def _mask_org_code(self, text: str) -> str:
        """组织机构代码：老式 8-1 位格式（如 69920000-2），常见于旧合同与备案材料。"""
        return self._safe_replace(
            text,
            r'(?<![0-9A-Z-])([0-9A-Z]{8}-[0-9A-Z])(?![0-9A-Z-])',
            '[组织机构代码]',
            '组织机构代码'
        )

    def _mask_credit_code(self, text: str) -> str:
        """统一社会信用代码：带"信用代码"上下文时按标签识别（18位字母数字）。"""
        def context_replacer(m):
            self._record(m.group(2), '[统一社会信用代码]', '统一社会信用代码')
            return m.group(1) + '[统一社会信用代码]'
        return _CREDIT_CONTEXT.sub(context_replacer, text)

    def _mask_credit_code_bare(self, text: str) -> str:
        """统一社会信用代码（无标签）：仅匹配以 9 开头的 18 位字母数字。

        放在银行卡规则之后执行：纯数字账号优先归银行/身份证规则，避免误判。
        校验码（GB 32100）不作为脱敏硬门槛——宁替勿漏，校验码用于 scan 置信度。
        """
        return self._safe_replace(
            text,
            r'(?<![0-9A-Z])(9[0-9A-Z]{17})(?![0-9A-Z])',
            '[统一社会信用代码]',
            '统一社会信用代码'
        )

    def _mask_case_number(self, text: str) -> str:
        """案号：(2024)京0108民初12345号 / （2025）浙民终123号 — 排除年月日误匹配"""
        return self._safe_replace(
            text,
            r'[（(]?\d{4}[）)]?(?![年月日])[\u4e00-\u9fa5]{1,10}\d{0,6}[\u4e00-\u9fa5]{0,6}\d{1,6}号',
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
        """日期（全量模式 --all-dates）：所有"年月日"格式"""
        return self._safe_replace(
            text,
            r'(?<!\d)(\d{4}年\d{1,2}月\d{1,2}日)(?!\d)',
            '[日期]',
            '日期'
        )

    def _mask_birthdate(self, text: str) -> str:
        """出生日期（默认模式）：仅脱敏带"出生/生日/生于"等上下文的日期"""
        def context_replacer(m):
            if m.group(2) is not None:
                self._record(m.group(2), '[出生日期]', '出生日期')
                return m.group(1) + '[出生日期]'
            # "1985年8月15日出生" 这种日期在前、上下文在后的写法
            self._record(m.group(3), '[出生日期]', '出生日期')
            # 保留"出生/生"等上下文词，还原时无损
            return '[出生日期]' + m.group(0)[len(m.group(3)):]
        return _BIRTHDATE_CONTEXT.sub(context_replacer, text)

    # --------------------------------------------------------
    # 新增：人名 / 公司名 / 地址（规则层初步匹配）
    # --------------------------------------------------------

    def _mask_person_name(self, text: str) -> str:
        """
        人名识别 + 实体归一化：
        - 角色词后 2-4 字姓名（含4字复姓）
        - 同一人物全文档用统一占位符 [当事人甲（原告）]
        """
        role_patterns = [
            r'(原告|被告|上诉人|被上诉人|第三人|申请执行人|被执行人|委托诉讼代理人|委托代理人|法定代表人|法定代理人|负责人|联系人|审判员|审判长|代理审判员|代理审判长|人民陪审员|书记员)[：:，,，\s]*([\u4e00-\u9fa5]{2,4})(?=[，,。.\s（(的]|\u3001|$)',
        ]
        for pat in role_patterns:
            def make_replacer(p):
                def replacer(m):
                    role = m.group(1)
                    name = m.group(2)
                    # 通过EntityResolver进行归一化和角色绑定
                    _, placeholder = self._resolver.resolve_person(name, role)
                    # 记录映射
                    canonical = self._resolver.normalize(name)
                    self._record(canonical, placeholder, '人名')
                    # 保留原文分隔符
                    raw = m.group(0)
                    after_role = raw[len(role):]
                    delim = ''
                    for ch in after_role:
                        if ch in '：:，,　 ':
                            delim += ch
                        else:
                            break
                    if delim.strip():
                        return f'{role}{delim}{placeholder}'
                    else:
                        # 原文无分隔符时不插入空格，保证还原保真
                        return f'{role}{placeholder}'
                return replacer
            text = re.sub(pat, make_replacer(pat), text)
        return text

    def _mask_company_name(self, text: str) -> str:
        """
        公司/机构名称识别 + 实体归一化：
        - 全称/简称统一链接到同一实体
        - 不同公司按角色生成不同占位符 [合同甲方] [合同乙方] [第三方公司]
        """
        original = text  # 保留原文用于上下文角色检测
        
        def co_replacer(m):
            name = m.group(1)
            # 检查上下文中的角色词
            role = ''
            start = m.start()
            context_before = original[max(0, start-25):start]
            # 找最近的角色关键词（不是第一个）
            role = ''
            best_pos = -1
            for kw, r in self._resolver.ROLE_KEYWORDS.items():
                pos = context_before.rfind(kw)
                if pos > best_pos:
                    best_pos = pos
                    role = r
            _, placeholder = self._resolver.resolve_company(name, role)
            self._record(name, placeholder, '公司名')
            return placeholder

        text = re.sub(
            r'([\u4e00-\u9fa5（）\(\)]{4,30}(?:有限公司|股份有限公司|集团公司|有限责任公司|合伙企业))',
            co_replacer,
            text
        )
        text = re.sub(
            r'([\u4e00-\u9fa5]{4,20}(?:律师事务所|会计师事务所|资产评估事务所))',
            co_replacer,
            text
        )
        text = re.sub(
            # 前不能紧贴中文/字母（避免吞掉更长公司名中的片段）；
            # 后不设约束（"华信置业公司应于..."这类句法必须命中，宁替勿漏）
            r'(?<![\u4e00-\u9fa5A-Za-z0-9])([\u4e00-\u9fa5]{3,6})公司',
            co_replacer,
            text
        )
        return text
        return text

    def _mask_address(self, text: str) -> str:
        """
        地址信息，匹配地理层级结构：
        住所地/地址 + 内容，或 省/市/区/路/号 层级结构
        """
        # 住所地/地址/位于 + 内容
        text = re.sub(
            r'(住所地|住址|地址|位于)[：:]?\s*([\u4e00-\u9fa5]{1,3}(?:省|自治区)[\u4e00-\u9fa5\s]{1,10}(?:市)[\u4e00-\u9fa5\s]{1,10}(?:区|县|市)[\u4e00-\u9fa5\d\-（\(）\)\s]{5,40}(?:号|室|层))',
            lambda m: self._record_addr(m.group(2), m.group(0)[:m.start(2)]),
            text
        )
        # 独立的地理地址（省开头 + 详细到号/室）
        text = re.sub(
            r'([\u4e00-\u9fa5]{1,3}(?:省|自治区)[\u4e00-\u9fa5\s]{1,10}(?:市)[\u4e00-\u9fa5\s]{1,10}(?:区|县|市)[\u4e00-\u9fa5\d\-（\(\)）\s]{5,40}(?:号|室|层))',
            lambda m: self._record_addr(m.group(1)),
            text
        )
        # 独立城市级地址（市/区开头 + 详细到路/街/号）
        text = re.sub(
            r'((?:[\u4e00-\u9fa5]{2,8}(?:市|区|县|镇))[\u4e00-\u9fa5]*(?:路|街|大道|巷)[\u4e00-\u9fa5\d\-（\(\)）\s]{2,29}(?:号|室|层|栋|幢)(?:\d+)?)',
            lambda m: self._record_addr(m.group(1)),
            text
        )
        return text

    def _record_addr(self, addr: str, prefix: str = '') -> str:
        """记录地址替换"""
        self._record(addr.replace(' ', ''), '[地址]', '地址')
        return f'{prefix}[地址]' if prefix else '[地址]'

    def _mask_amount(self, text: str) -> str:
        """
        金额匹配：大额货币数值（人民币/美元/欧元等）
        匹配格式：¥2,350,000元  236,000,000.00元  80万  3.6万  500美元  80万
                 伍佰万元整  贰亿叁仟陆佰万元整  人民币伍佰万元
        排除：普通数字、日期、股票数量（带"股"）、百分比（带%）
        """
        # 中文大写金额：零壹贰叁肆伍陆柒捌玖拾佰仟万亿元整
        # 必须含至少一个"大写数字/拾"，避免把普通数字后的"万元"单独吃掉
        text = self._safe_replace(
            text,
            r'(?<![\d零壹贰叁肆伍陆柒捌玖拾])(?:人民币|美金|港币)?[零壹贰叁肆伍陆柒捌玖拾][零壹贰叁肆伍陆柒捌玖拾佰仟万亿元整亿]*(?:元|圆)?(?:整)?',
            '[金额]',
            '金额'
        )
        # 带"元/美元/欧元"等单位的完整金额
        text = self._safe_replace(
            text,
            r'[$¥]?(?:\d{1,3}(?:,\d{3})*|\d+)(?:\.\d{1,2})?(?:[万千亿])?(?:元|美元|欧元|英镑|港币)(?![.\d万千亿])',
            '[金额]',
            '金额'
        )
        # 口语化金额：X万 / X.X万（无"元"后缀，如"借我80万""3.6万利息"）
        # 排除常见非金额搭配：像素、股、人、户、平方米、瓦、公里、粉丝等
        text = self._safe_replace(
            text,
            r'(?<!\d)(\d+(?:\.\d+)?)[万千亿](?![.\d万千亿])(?!像素|股|人|户|平方米|平米|瓦|公里|粉丝|预算|年薪|月薪|彩礼)',
            '[金额]',
            '金额'
        )
        return text


    def _get_all_rules(self):
        """返回所有规则（用于scan）— 与 mask 执行顺序和正则保持一致。

        每条规则：type/pattern/handler 与 mask 一致；validate 返回置信度
        (0.0~1.0)，用于标注"标签匹配/校验码验证通过"与"仅格式相似"的差异。
        """
        def id_confidence(value):
            # 标签匹配（value 来自 group(2)）或校验码通过 → 高置信
            if len(value) >= 18 and value[-1] in '0123456789Xx':
                if _is_valid_id_checksum(value):
                    return 1.0
                return 0.6 if _is_valid_id_birthdate(value) else 0.0
            return 0.5

        def credit_confidence(value):
            return 1.0 if _is_valid_credit_code(value) else 0.5

        def bank_confidence(value):
            return 1.0 if _luhn_check(value) else 0.6

        rules = [
            {'type': '律师执业证号',
             'pattern': r'((?:执业证号|执业许可证号|律师执业证号|律师执业证|执业证)\s*[：:]?\s*)([0-9A-Z]{17,18})',
             'handler': self._mask_bar_number, 'group': 2},
            {'type': '身份证号',
             'pattern': r'((?:身份证号|身份证号码|身份证|证件号码|证件号)\s*[：:]?\s*)(\d{17}[\dXx])',
             'handler': self._mask_id_card, 'group': 2, 'validate': id_confidence},
            {'type': '身份证号',
             'pattern': r'(?<!\d)(\d{17}[\dXx])(?!\d)',
             'handler': self._mask_id_card, 'group': 1, 'validate': id_confidence},
            {'type': '邮箱',
             'pattern': r'[A-Za-z0-9.+-]+@[A-Za-z0-9-]+\.[A-Za-z0-9.-]+',
             'handler': self._mask_email},
            {'type': '手机号',
             'pattern': r'(?<!\d)(1[3-9]\d{9})(?!\d)',
             'handler': self._mask_phone, 'group': 1},
            {'type': '固定电话',
             'pattern': r'(?<!\d)(0\d{2,3}[-\s]?\d{7,8})(?!\d)',
             'handler': self._mask_landline, 'group': 1},
            {'type': '服务电话',
             'pattern': r'(?<!\d)([48]00[-\s]?\d{3}[-\s]?\d{4})(?!\d)',
             'handler': self._mask_landline, 'group': 1},
            {'type': '微信号',
             'pattern': r'(?<![\u4e00-\u9fa5a-zA-Z0-9_@/.])([a-zA-Z][a-zA-Z0-9_]{5,19})(?![a-zA-Z0-9_@]|\.com|\.cn)',
             'handler': self._mask_wechat, 'group': 1},
            {'type': 'QQ号',
             'pattern': r'((?:QQ|Qq|qq)\s*[：:]?\s*)(\d{5,12})(?!\d)',
             'handler': self._mask_qq, 'group': 2},
            {'type': '组织机构代码',
             'pattern': r'(?<![0-9A-Z-])([0-9A-Z]{8}-[0-9A-Z])(?![0-9A-Z-])',
             'handler': self._mask_org_code, 'group': 1},
            {'type': '统一社会信用代码',
             'pattern': r'((?:统一社会信用代码|社会信用代码|信用代码)\s*[：:]?\s*)([0-9A-Z]{18})',
             'handler': self._mask_credit_code, 'group': 2, 'validate': credit_confidence},
            {'type': '银行账号',
             'pattern': r'((?:银行账号|开户账号|账户号码|银行卡号|收款账号|付款账号|卡号)\s*[：:]?\s*)([0-9]{12,24})',
             'handler': self._mask_bank_card, 'group': 2, 'validate': bank_confidence},
            {'type': '银行账号',
             'pattern': r'(?<!\d)(\d{14,20})(?!\d)',
             'handler': self._mask_bank_card, 'group': 1, 'validate': bank_confidence},
            {'type': '统一社会信用代码',
             'pattern': r'(?<![0-9A-Z])(9[0-9A-Z]{17})(?![0-9A-Z])',
             'handler': self._mask_credit_code_bare, 'group': 1, 'validate': credit_confidence},
            {'type': '案号',
             'pattern': r'[（(]?\d{4}[）)]?(?![年月日])[\u4e00-\u9fa5]{1,10}\d{0,6}[\u4e00-\u9fa5]{0,6}\d{1,6}号',
             'handler': self._mask_case_number},
            {'type': '车牌号',
             'pattern': r'(?<![A-Za-z0-9])[\u4e00-\u9fa5][A-Z][A-Z0-9]{5,6}(?![\dA-Za-z])',
             'handler': self._mask_license_plate},
            {'type': '出生日期',
             'pattern': r'((?:出生日期|出生年月|生日|出生于|生于)\s*[：:]?\s*)(\d{4}年\d{1,2}月\d{1,2}日)|(\d{4}年\d{1,2}月\d{1,2}日)\s*(?:出生|生)',
             'handler': self._mask_birthdate},
            {'type': '人名',
             'pattern': r'(原告|被告|上诉人|被上诉人|第三人|申请执行人|被执行人|委托诉讼代理人|委托代理人|法定代表人|法定代理人|负责人|联系人|审判员|审判长|代理审判员|代理审判长|人民陪审员|书记员)[：:，,，\s]*[\u4e00-\u9fa5]{2,4}(?=[，,。.\s（(的]|\u3001|$)',
             'handler': self._mask_person_name},
            {'type': '公司名',
             'pattern': r'[\u4e00-\u9fa5（）\(\)]{4,30}(?:有限公司|股份有限公司|集团公司|有限责任公司|合伙企业)|[\u4e00-\u9fa5]{4,20}(?:律师事务所|会计师事务所|资产评估事务所)|(?<![\u4e00-\u9fa5A-Za-z0-9])[\u4e00-\u9fa5]{3,6}公司',
             'handler': self._mask_company_name},
            {'type': '地址',
             'pattern': r'(住所地|住址|地址|位于)[：:]?\s*[\u4e00-\u9fa5]{1,3}(?:省|自治区)[\u4e00-\u9fa5\s]{1,10}(?:市)[\u4e00-\u9fa5\s]{1,10}(?:区|县|市)[\u4e00-\u9fa5\d\-（\(\)）\s]{5,40}(?:号|室|层)|[\u4e00-\u9fa5]{1,3}(?:省|自治区)[\u4e00-\u9fa5\s]{1,10}(?:市)[\u4e00-\u9fa5\s]{1,10}(?:区|县|市)[\u4e00-\u9fa5\d\-（\(\)）\s]{5,40}(?:号|室|层)|(?:[\u4e00-\u9fa5]{2,8}(?:市|区|县|镇))[\u4e00-\u9fa5]*(?:路|街|大道|巷)[\u4e00-\u9fa5\d\-（\(\)）\s]{2,29}(?:号|室|层|栋|幢)(?:\d+)?',
             'handler': self._mask_address},
            {'type': '金额（中文大写）',
             'pattern': r'(?<![\d零壹贰叁肆伍陆柒捌玖拾])(?:人民币|美金|港币)?[零壹贰叁肆伍陆柒捌玖拾][零壹贰叁肆伍陆柒捌玖拾佰仟万亿元整亿]*(?:元|圆)?(?:整)?',
             'handler': self._mask_amount},
            {'type': '金额',
             'pattern': r'[$¥]?(?:\d{1,3}(?:,\d{3})*|\d+)(?:\.\d{1,2})?(?:[万千亿])?(?:元|美元|欧元|英镑|港币)(?![.\d万千亿])',
             'handler': self._mask_amount},
            {'type': '金额（口语化）',
             'pattern': r'(?<!\d)(\d+(?:\.\d+)?)[万千亿](?![.\d万千亿])(?!像素|股|人|户|平方米|平米|瓦|公里|粉丝|预算|年薪|月薪|彩礼)',
             'handler': self._mask_amount},
            {'type': '其他证件',
             'pattern': r'(?:护照|护照号|港澳通行证|往来港澳通行证|港澳居民来往内地通行证|台湾居民来往大陆通行证|台胞证|驾驶证|驾驶证号|驾驶证号码|军官证|士兵证|警官证|工作证|营业执照|营业执照号|营业执照号码|税务登记证号|税务登记号)\s*[：:]?\s*[0-9A-Za-z]{4,20}',
             'handler': self._mask_other_cert},
        ]
        if self._mask_all_dates:
            rules.append({'type': '日期',
                          'pattern': r'(?<!\d)(\d{4}年\d{1,2}月\d{1,2}日)(?!\d)',
                          'handler': self._mask_date})
        return rules


# ============================================================
# SecureDesensitizer — 内存安全包装层
# ============================================================

class SecureDesensitizer(Desensitizer):
    """安全增强版脱敏器 — 在标准脱敏基础上增加纵深防御措施。

    与标准 Desensitizer 的区别：
    - 脱敏完成后尽力清空传入文本对象的内存引用
    - 触发垃圾回收以尽早释放中间字符串

    局限性（Python 字符串不可变）：
    - 无法真正擦除内存中的原始字符串（字符串不可变，旧对象可能仍被引用）
    - 这是"尽力而为"的纵深防御，不是绝对的内存擦除
    - 如需真正的内存安全，请在硬件安全模块 (HSM) 或机密计算环境中运行
    """

    def __init__(self, security_level: str = 'strict', mask_all_dates: bool = False):
        super().__init__(mask_all_dates=mask_all_dates)
        self._security_level = security_level
        self._secure_mode = security_level in ('strict', 'high')
        self._text_refs = []  # 跟踪传入的文本引用，便于后续清理

    def mask(self, text: str) -> MaskResult:
        """对文本执行规则层脱敏（安全增强版）"""
        if self._secure_mode:
            self._text_refs.append(text)

        result = super().mask(text)

        if self._secure_mode:
            self._purge_text_refs()
        return result

    def mask_with_ner(self, text: str, ner_backend=None) -> MaskResult:
        """规则层 + 本地 NER 脱敏（安全增强版）"""
        if self._secure_mode:
            self._text_refs.append(text)

        result = super().mask_with_ner(text, ner_backend)

        if self._secure_mode:
            self._purge_text_refs()
        return result

    def _safe_replace(self, text: str, pattern: str, replacement: str,
                      typ: str, original_group: int = 0,
                      validate=None) -> str:
        """安全替换（安全增强版）：替换完成后尝试清除原字符串引用"""
        result = super()._safe_replace(
            text, pattern, replacement, typ, original_group, validate=validate
        )

        if self._secure_mode:
            try:
                text = ''
            except Exception:
                pass

        return result

    def _safe_replace_wechat(self, original: str, prefix: str = '') -> str:
        """记录微信号替换（安全增强版）"""
        result = super()._safe_replace_wechat(original, prefix)
        if self._secure_mode:
            try:
                original = ''
            except Exception:
                pass
        return result

    def _record_addr(self, addr: str, prefix: str = '') -> str:
        """记录地址替换（安全增强版）"""
        result = super()._record_addr(addr, prefix)
        if self._secure_mode:
            try:
                addr = ''
            except Exception:
                pass
        return result

    def _purge_text_refs(self):
        """清空所有跟踪的文本引用并触发垃圾回收。"""
        import gc
        for i in range(len(self._text_refs)):
            try:
                self._text_refs[i] = ''
            except Exception:
                pass
        self._text_refs.clear()
        gc.collect()

    def flush(self):
        """手动触发内存清理（如多次调用 mask 后集中清理）。"""
        self._purge_text_refs()
        import gc
        gc.collect()


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

## 待脱敏文本（请处理以下内容）

{rule_masked_text}"""


def make_llm_prompt(rule_masked_text: str) -> str:
    """生成LLM脱敏提示词，供Reasonix Skill调用"""
    return LLM_PROMPT_TEMPLATE.replace('{rule_masked_text}', rule_masked_text)


# ============================================================
# 零信任映射表加密（AES-256-GCM + PBKDF2）
# ============================================================

def _get_mapping_password() -> str:
    """获取映射表加密密码。优先级：环境变量 > 交互式输入。

    环境变量：DESENSITIZER_MAPPING_PASSWORD
    交互式输入：使用 getpass（不回显）
    """
    password = os.environ.get('DESENSITIZER_MAPPING_PASSWORD', '')
    if password:
        return password

    # 交互式输入
    try:
        import getpass
        password = getpass.getpass('🔑 请输入映射表加密密码（不显示）：')
        if not password:
            sys.exit('❌ 密码不能为空')
        confirm = getpass.getpass('🔑 请再次输入密码确认：')
        if password != confirm:
            sys.exit('❌ 两次输入的密码不一致')
        return password
    except Exception as e:
        sys.exit(f'❌ 无法读取密码（请设置环境变量 DESENSITIZER_MAPPING_PASSWORD）：{e}')


def save_mapping_encrypted(mapping_content: str, filepath: str) -> bytes:
    """使用 AES-256-GCM + PBKDF2 加密映射表。

    加密方案：
    - PBKDF2HMAC(SHA256, 600,000次迭代) 从密码+随机盐派生 32字节 AES 密钥
    - AES-256-GCM 认证加密（带 12 字节随机 nonce）
    - 文件格式：salt(32B) + nonce(12B) + ciphertext

    密码来源：
    - 环境变量 DESENSITIZER_MAPPING_PASSWORD（推荐用于自动化）
    - 或交互式 getpass 输入（不 echo）
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
    except ImportError:
        sys.exit('❌ 需要安装 cryptography: pip3 install cryptography')

    password = _get_mapping_password()

    # 生成随机盐和随机 nonce
    salt = os.urandom(32)
    nonce = os.urandom(12)

    # PBKDF2 密钥派生
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,
    )
    key = kdf.derive(password.encode('utf-8'))

    # AES-256-GCM 加密
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, mapping_content.encode('utf-8'), None)

    # 合并：salt + nonce + ciphertext
    output = salt + nonce + ciphertext

    with open(filepath, 'wb') as f:
        f.write(output)

    # 清理内存中的密码和密钥
    password = ''
    key = b'\x00' * 32

    return salt  # 返回 salt（用于密码验证，不包含密钥）


def decrypt_mapping_encrypted(filepath: str, password: str) -> str:
    """解密 AES-256-GCM 加密的映射表。

    Args:
        filepath: 加密文件路径
        password: 解密密码（明文字符串，使用后立即清零）

    Returns:
        解密后的映射表内容（字符串）
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
    except ImportError:
        sys.exit('❌ 需要安装 cryptography: pip3 install cryptography')

    with open(filepath, 'rb') as f:
        data = f.read()

    # 检查是否是旧版 Fernet 格式（迁移提示）
    if len(data) < 44:  # salt(32) + nonce(12) 至少 44 字节
        sys.exit(
            '⚠️  此文件可能是旧版 Fernet 加密格式（v2.0），不兼容当前 AES-GCM 格式。\n'
            '   请使用旧版 desensitize.py 解密后重新加密。\n'
            '   旧版命令：python desensitize.py decrypt -f <文件> -k <Fernet密钥>'
        )

    salt = data[:32]
    nonce = data[32:44]
    ciphertext = data[44:]

    # PBKDF2 密钥派生
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,
    )
    key = kdf.derive(password.encode('utf-8'))

    # AES-GCM 解密
    try:
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        sys.exit('❌ 解密失败：密码错误或文件已损坏')

    # 清理内存中的密码和密钥
    password = ''
    key = b'\x00' * 32

    return plaintext.decode('utf-8')


# ============================================================
# 文件名自动脱敏
# ============================================================

def sanitize_filename(filepath: str) -> str:
    """自动将文件名中的敏感信息替换为脱敏占位符。

    对文件名的 basename 部分（不含目录）执行规则层脱敏，
    保留扩展名和目录路径不变。

    示例：
        "金进跃诉张三合同.docx" → "[当事人甲]诉[当事人乙]合同.docx"
        "北京华信科技有限公司_判决书.pdf" → "[公司]_判决书.pdf"

    注意：
    - 规则层可能无法识别所有类型的人名/公司名（如英文名、简称）
    - 这是"尽力而为"的辅助功能，建议手动检查结果
    """
    dir_part = os.path.dirname(filepath)
    basename = os.path.basename(filepath)

    # 分离名称和扩展名
    name, ext = os.path.splitext(basename)

    # 对名称部分执行规则层脱敏
    d = Desensitizer()
    result = d.mask(name)

    sanitized_name = result.text
    sanitized_basename = sanitized_name + ext

    if dir_part:
        return os.path.join(dir_part, sanitized_basename)
    return sanitized_basename


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
        # 只提取正文段落文本（每段一行，保持结构映射）
        paragraphs = [p.text for p in doc.paragraphs]
        # 表格文本附加在末尾
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
# 文件写入（保留原格式 .txt → .txt, .docx → .docx）
# ============================================================

def write_desensitized_file(input_path: str, output_path: str, masked_text: str):
    """将脱敏后的文本写出，尽量保留原文件格式"""
    in_ext = os.path.splitext(input_path)[1].lower()
    out_ext = os.path.splitext(output_path)[1].lower()

    if out_ext == '.docx' or (out_ext == '' and in_ext == '.docx'):
        # 输出为 .docx：基于原文档逐段替换，保留结构
        try:
            from docx import Document
            from docx.shared import Pt
        except ImportError:
            sys.exit('❌ 需要安装 python-docx: pip3 install python-docx')

        orig_doc = Document(input_path)
        lines = masked_text.split('\n')

        # 逐段替换
        para_idx = 0
        for para in orig_doc.paragraphs:
            if para_idx < len(lines):
                para.clear()
                run = para.add_run(lines[para_idx])
                para_idx += 1

        # 处理表格
        for table in orig_doc.tables:
            for row in table.rows:
                for cell in row.cells:
                    if para_idx < len(lines):
                        for para in cell.paragraphs:
                            para.clear()
                            if para_idx < len(lines):
                                para.add_run(lines[para_idx])
                                para_idx += 1

        # 处理页眉/页脚
        try:
            for section in orig_doc.sections:
                if section.header:
                    for para in section.header.paragraphs:
                        para.clear()
                if section.footer:
                    for para in section.footer.paragraphs:
                        para.clear()
        except Exception:
            pass

        # 清理文档元数据
        try:
            props = orig_doc.core_properties
            props.author = ''
            props.last_modified_by = ''
            props.category = ''
            props.comments = ''
            props.content_status = ''
            props.identifier = ''
            props.keywords = ''
            props.language = ''
            props.revision = 0
            props.subject = ''
            props.title = ''
            props.version = ''
        except Exception:
            pass

        # 设置文件权限
        orig_doc.save(output_path)
        try:
            os.chmod(output_path, 0o600)  # 仅当前用户可读写
        except Exception:
            pass
        return output_path

    else:
        # 默认输出纯文本
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(masked_text)
        return output_path


# ============================================================
# 还原（restore）— 用映射表把脱敏文本还原为原文
# ============================================================

def parse_mapping_text(content: str) -> List[Mapping]:
    """从 Markdown 映射表或 JSON 映射表中解析出 Mapping 列表。

    支持 desensitize.py 自身输出的两种格式：
    - MaskResult.to_markdown()：'| 序号 | 原始值 | 替换值 | 类型 | 出现次数 |' 表格
    - MaskResult.to_json()：{"mapping": [{"original":..., "replacement":..., ...}]}
    """
    stripped = content.strip()
    if not stripped:
        return []

    # JSON 格式
    if stripped.startswith('{'):
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError:
            return []
        mappings = []
        for item in data.get('mapping', []):
            mappings.append(Mapping(
                original=item.get('original', ''),
                replacement=item.get('replacement', ''),
                type=item.get('type', ''),
                count=int(item.get('count', 1) or 1),
                order=int(item.get('order', 0) or 0),
            ))
        return mappings

    # Markdown 表格格式
    mappings = []
    for line in stripped.splitlines():
        line = line.strip()
        if not line.startswith('|'):
            continue
        cells = [c.strip() for c in line.strip('|').split('|')]
        if len(cells) < 3:
            continue
        if cells[0] in ('序号', '') or set(cells[0]) == {'-'}:
            continue  # 表头或分隔线
        original = cells[1]
        replacement = cells[2]
        if not original or not replacement:
            continue
        typ = cells[3] if len(cells) > 3 else ''
        count = int(cells[4]) if len(cells) > 4 and cells[4].isdigit() else 1
        # Markdown 序号列即首次出现顺序（第 i 行）
        order = int(cells[0]) if cells[0].isdigit() else 0
        mappings.append(Mapping(original=original, replacement=replacement,
                                type=typ, count=count, order=order))
    return mappings


def restore_text(masked_text: str, mappings: List[Mapping]) -> str:
    """用映射表把占位符还原为原始值。

    策略：
    1. 按占位符长度降序处理，避免长占位符（如 [当事人甲（原告）]）
       被短占位符（如 [当事人甲]）先替换掉一部分。
    2. 同一占位符多次出现（如多个 [金额]）时，按映射条目的
       "首次出现顺序"与原文出现顺序逐一配对，确保还原准确。
    """
    # 按占位符分组，组内按首次出现顺序排队
    groups = {}
    for m in mappings:
        if not m.replacement or not m.original:
            continue
        groups.setdefault(m.replacement, []).append(m)
    for q in groups.values():
        q.sort(key=lambda m: m.order)

    # 长占位符优先替换
    for placeholder, queue in sorted(groups.items(),
                                     key=lambda kv: len(kv[0]), reverse=True):
        if len(queue) == 1:
            masked_text = masked_text.replace(placeholder, queue[0].original)
            continue
        # 同一占位符多次出现：按顺序逐一配对
        queue_idx = 0
        out = []
        pos = 0
        while True:
            found = masked_text.find(placeholder, pos)
            if found == -1:
                out.append(masked_text[pos:])
                break
            out.append(masked_text[pos:found])
            if queue_idx < len(queue):
                out.append(queue[queue_idx].original)
                queue_idx += 1
            else:
                # 映射表条目不足（理论上不应发生），保留占位符并警告由调用方处理
                out.append(placeholder)
            pos = found + len(placeholder)
        masked_text = ''.join(out)
    return masked_text


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

  # v2.1: 零信任加密映射表（密码不输出到终端）
  export DESENSITIZER_MAPPING_PASSWORD="your-password"
  python desensitize.py mask -f 合同.docx --save-mapping 映射表.enc --encrypt-mapping

  # v2.1: 内存安全增强模式
  python desensitize.py mask -f 合同.docx --secure

  # 文件名自动脱敏（默认启用）
  python desensitize.py mask -f 金进跃诉张三合同.docx
  # → 输出: [当事人甲]诉[当事人乙]合同_desensitized.docx

  # 解密映射表（v2.1 AES-GCM）
  python desensitize.py decrypt -f 映射表.enc -p "your-password"

  # v2.2: 用映射表还原脱敏文本（律师庭审/归档等需要原文时）
  python desensitize.py restore -f 脱敏后.txt -m 映射表.md
  python desensitize.py restore -f 脱敏后.docx -m 映射表.enc -o 还原.docx
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='子命令')

    # mask 命令
    mask_parser = subparsers.add_parser('mask', help='执行规则层脱敏')
    mask_parser.add_argument('-f', '--file', help='输入文件路径（默认从stdin读取）')
    mask_parser.add_argument('-o', '--output', help='输出文件路径（默认自动生成，如输入为.docx则输出同名的_desensitized.docx）')
    mask_parser.add_argument('--json', action='store_true', help='以JSON格式输出')
    mask_parser.add_argument('--mapping', action='store_true', help='仅输出脱敏映射表')
    mask_parser.add_argument('--save-mapping', help='脱敏映射表另存为文件（⚠️ 包含原始值，建议配合 --encrypt-mapping 使用）')
    mask_parser.add_argument('--encrypt-mapping', action='store_true', help='对映射表进行 AES-256 加密保存（需配合 --save-mapping 使用）')
    mask_parser.add_argument('--secure', action='store_true', default=False, help='启用内存安全增强模式（尽力清空原始文本引用）')
    mask_parser.add_argument('--security-level', default='strict', choices=['strict', 'high', 'standard'],
                             help='安全等级：strict/high（启用纵深防御）、standard（默认，无额外内存清理）')
    mask_parser.add_argument('--no-sanitize-filename', action='store_true', default=False, help='禁用输出文件名自动脱敏')
    mask_parser.add_argument('--all-dates', action='store_true', default=False,
                             help='把文中所有"年月日"日期也替换为 [日期]（默认只处理出生日期）')
    mask_parser.add_argument('--ner-backend', default=None,
                             choices=['regex', 'spacy', 'huggingface', 'llm'],
                             help='规则层后追加本地 NER 层：spacy（需中文模型）/ huggingface（需 transformers）/ llm（本地 Ollama）')
    mask_parser.add_argument('--ner-model', default=None,
                             help='NER 模型名（如 zh_core_web_trf / qwen2.5，按后端默认取）')
    mask_parser.add_argument('--ner-endpoint', default=None,
                             help='LLM 后端端点（默认 http://localhost:11434/api/generate）')

    # scan 命令
    scan_parser = subparsers.add_parser('scan', help='扫描敏感信息（不替换）')
    scan_parser.add_argument('-f', '--file', help='输入文件路径（默认从stdin读取）')
    scan_parser.add_argument('--json', action='store_true', help='以JSON格式输出')

    # llm-prompt 命令
    llm_parser = subparsers.add_parser('llm-prompt', help='生成LLM脱敏提示词（规则层+LLM提示）')
    llm_parser.add_argument('-f', '--file', help='输入文件路径（默认从stdin读取）')
    llm_parser.add_argument('--all-dates', action='store_true', default=False,
                            help='把文中所有"年月日"日期也替换为 [日期]（默认只处理出生日期）')

    # decrypt 命令
    decrypt_parser = subparsers.add_parser('decrypt', help='解密加密的映射表文件')
    decrypt_parser.add_argument('-f', '--file', required=True, help='加密的映射表文件路径')
    decrypt_parser.add_argument('-k', '--key', help='Fernet 解密密钥（v2.0 旧格式兼容，不推荐）')
    decrypt_parser.add_argument('-p', '--password', help='AES-GCM 解密密码（v2.1+，优先使用。也可通过环境变量 DESENSITIZER_MAPPING_PASSWORD 设置）')
    decrypt_parser.add_argument('-o', '--output', help='输出路径（默认输出到 stdout）')

    # restore 命令
    restore_parser = subparsers.add_parser('restore', help='用映射表把脱敏文本还原为原文（庭审、归档等需要原文时使用）')
    restore_parser.add_argument('-f', '--file', required=True, help='脱敏后的文件路径（.txt / .docx）')
    restore_parser.add_argument('-m', '--mapping', required=True, help='映射表文件（.md 表格 / .json / 加密 .enc）')
    restore_parser.add_argument('-p', '--password', help='加密映射表密码（也可用环境变量 DESENSITIZER_MAPPING_PASSWORD）')
    restore_parser.add_argument('-o', '--output', help='还原后的输出路径（默认输出到 stdout）')

    args = parser.parse_args()

    # 读取输入（支持 .txt / .docx / .pdf）
    if hasattr(args, 'file') and args.file:
        # 文件名自动脱敏检查
        basename = os.path.basename(args.file)
        name_hint = re.findall(r'[\u4e00-\u9fa5]{2,4}(?:诉|与|vs|VS|\.)', basename)
        if name_hint:
            no_sanitize = hasattr(args, 'no_sanitize_filename') and args.no_sanitize_filename
            if no_sanitize:
                print('⚠️  警告：文件名可能包含客户信息（{}）'.format('、'.join(name_hint[:3])))
                print('⚠️  已通过 --no-sanitize-filename 禁用自动脱敏，请手动检查')
            else:
                sanitized_name = sanitize_filename(basename)
                print(f'🔄 文件名已自动脱敏：{basename} → {sanitized_name}')
                # 将脱敏后的文件名信息保存，供后续输出路径使用
                args._sanitized_basename = sanitized_name
        else:
            args._sanitized_basename = None

        text = read_text_from_file(args.file)
    else:
        text = sys.stdin.read()

    d = Desensitizer(mask_all_dates=getattr(args, 'all_dates', False))

    # 如果启用了内存安全增强，使用 SecureDesensitizer
    secure_mode = False
    if hasattr(args, 'secure') and args.secure:
        secure_mode = True
    if hasattr(args, 'security_level') and args.security_level in ('strict', 'high'):
        secure_mode = True

    if secure_mode:
        level = args.security_level if hasattr(args, 'security_level') else 'strict'
        d = SecureDesensitizer(security_level=level,
                               mask_all_dates=getattr(args, 'all_dates', False))
        if sys.stderr.isatty():
            print(f'🔒 内存安全增强模式已启用 (security_level={level})', file=sys.stderr)
            print(f'   ⚠️  Python 字符串不可变，内存清理为"尽力而为"的纵深防御', file=sys.stderr)

    if args.command == 'mask':
        ner = None
        if getattr(args, 'ner_backend', None):
            from ner_interface import LegalNER
            ner_kwargs = {}
            if args.ner_model:
                ner_kwargs['model'] = args.ner_model
            if args.ner_backend == 'llm' and args.ner_endpoint:
                ner_kwargs['endpoint'] = args.ner_endpoint
            ner = LegalNER(backend=args.ner_backend, **ner_kwargs)
            if sys.stderr.isatty():
                print(f'🤖 本地 NER 层已启用（{ner.backend_name}）', file=sys.stderr)
        try:
            result = d.mask_with_ner(text, ner) if ner else d.mask(text)
        except NotImplementedError as e:
            sys.exit(f'❌ {e}')
        except ImportError as e:
            sys.exit(f'❌ NER 后端依赖缺失：{e}')

        # 保存映射表到文件（如果指定了 --save-mapping）
        if hasattr(args, 'save_mapping') and args.save_mapping:
            mapping_content = result.to_markdown()
            mapping_path = args.save_mapping

            if hasattr(args, 'encrypt_mapping') and args.encrypt_mapping:
                # AES-256-GCM + PBKDF2 加密保存（v2.1 零信任方案）
                try:
                    save_mapping_encrypted(mapping_content, mapping_path)
                except ImportError:
                    sys.exit('❌ 需要安装 cryptography: pip3 install cryptography')
                print(f'🔐 映射表已 AES-256-GCM 加密保存: {mapping_path}')
                print(f'🔑 解密时需要输入相同的密码')
                print(f'   💡 设置环境变量 DESENSITIZER_MAPPING_PASSWORD 可跳过交互式输入')
            else:
                # 明文保存（默认行为，发出警告）
                with open(mapping_path, 'w', encoding='utf-8') as f:
                    f.write(mapping_content)
                print(f'⚠️ ⚠️ ⚠️  映射表已保存（明文）: {mapping_path}')
                print(f'⚠️  警告：该文件包含原始敏感信息（身份证号、手机号等）！')
                print(f'⚠️  切勿上传到任何AI服务或网络！')
                print(f'⚠️  建议使用 --encrypt-mapping 参数加密保存')

        # 输出到文件（如果指定了 -o 或输入是文件）
        output_path = None
        if hasattr(args, 'output') and args.output:
            output_path = args.output
        elif hasattr(args, 'file') and args.file and not args.json and not args.mapping:
            # 优先使用脱敏后的文件名（由 sanitize_filename 生成）
            sanitized_basename = getattr(args, '_sanitized_basename', None)
            if sanitized_basename:
                dir_part = os.path.dirname(args.file)
                name, ext = os.path.splitext(sanitized_basename)
                if dir_part:
                    output_path = os.path.join(dir_part, f'{name}_desensitized{ext}')
                else:
                    output_path = f'{name}_desensitized{ext}'
            else:
                base, ext = os.path.splitext(args.file)
                output_path = f'{base}_desensitized{ext if ext else ".txt"}'

        if output_path:
            write_desensitized_file(args.file, output_path, result.text)
            print(f'✅ 脱敏后文件已保存: {output_path}')
        else:
            # 输出到 stdout
            if args.mapping:
                print(result.to_markdown())
            elif args.json:
                print(result.to_json())
            else:
                print(result.text)

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
        print('=' * 60)
        print('⚠️  安全警告：以下内容包含半脱敏数据（人名、公司名、金额可能仍在）')
        print('⚠️  如果将此提示词发送给云端 AI（如 ChatGPT/Claude），')
        print('⚠️  上述敏感信息将被传输到第三方服务器。')
        print('⚠️  建议：先检查确认无敏感信息后使用，或使用本地 LLM（Ollama 等）')
        print('=' * 60)
        print()
        print(make_llm_prompt(result.text))

    elif args.command == 'decrypt':
        # 读取完整文件数据用于格式检测
        with open(args.file, 'rb') as f:
            file_data = f.read()

        # 自动检测加密格式：新 AES-GCM vs 旧 Fernet
        # Fernet 加密文件：token 的 base64 编码以 gAAAAA 开头
        # AES-GCM：前 32 字节是随机 salt，无固定模式
        is_fernet = file_data.startswith(b'gAAAAA') and len(file_data) < 2000

        if is_fernet or (args.key and not args.password):
            # 旧版 Fernet 解密（向后兼容）
            if not args.key:
                sys.exit(
                    '⚠️  检测到旧版 Fernet 加密格式（v2.0）。\n'
                    '   请使用 -k 参数提供 Fernet 解密密钥。\n'
                    '   或重新用 v2.0 工具解密后，用 v2.1 重新加密。'
                )
            from cryptography.fernet import Fernet
            key = args.key.encode('utf-8') if not args.key.startswith('b') else eval(args.key)
            cipher = Fernet(key)
            decrypted = cipher.decrypt(file_data)
            print('⚠️  使用旧版 Fernet 格式解密成功。建议用 v2.1 的 AES-GCM 重新加密。', file=sys.stderr)
        else:
            # 新版 AES-GCM 解密
            password = args.password or os.environ.get('DESENSITIZER_MAPPING_PASSWORD', '')
            if not password:
                import getpass
                password = getpass.getpass('🔑 请输入映射表解密密码（不显示）：')
                if not password:
                    sys.exit('❌ 密码不能为空')
            decrypted = decrypt_mapping_encrypted(args.file, password).encode('utf-8')
            password = ''

        if args.output:
            with open(args.output, 'w', encoding='utf-8') as out_f:
                out_f.write(decrypted.decode('utf-8') if isinstance(decrypted, bytes) else decrypted)
            print(f'✅ 已解密: {args.output}')
        else:
            print(decrypted.decode('utf-8') if isinstance(decrypted, bytes) else decrypted)

    elif args.command == 'restore':
        # 读取脱敏后的文本（支持 .txt / .docx / .pdf）
        masked_text = read_text_from_file(args.file)

        # 读取映射表：加密 .enc 需要解密，其余按文本解析
        ext = os.path.splitext(args.mapping)[1].lower()
        if ext == '.enc':
            password = args.password or os.environ.get('DESENSITIZER_MAPPING_PASSWORD', '')
            if not password:
                import getpass
                password = getpass.getpass('🔑 请输入映射表解密密码（不显示）：')
                if not password:
                    sys.exit('❌ 密码不能为空')
            content = decrypt_mapping_encrypted(args.mapping, password)
            password = ''
        else:
            with open(args.mapping, 'r', encoding='utf-8') as f:
                content = f.read()

        mappings = parse_mapping_text(content)
        if not mappings:
            sys.exit('❌ 未能从映射表解析出任何条目（支持 .md 表格 / .json / 加密 .enc）')

        restored = restore_text(masked_text, mappings)
        if args.output:
            write_desensitized_file(args.file, args.output, restored)
            print(f'✅ 已还原 {len(mappings)} 个映射条目，保存至: {args.output}')
        else:
            print(restored)

    else:
        parser.print_help()


if __name__ == '__main__':
    main()
