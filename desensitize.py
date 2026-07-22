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

    def __init__(self, security_level: str = 'strict'):
        super().__init__()
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

    def _safe_replace(self, text: str, pattern: str, replacement: str,
                      typ: str, original_group: int = 0) -> str:
        """安全替换（安全增强版）：替换完成后尝试清除原字符串引用"""
        result = super()._safe_replace(text, pattern, replacement, typ, original_group)

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
# 脱敏规则引擎
# ============================================================

class Desensitizer:
    """法律文书脱敏器 — 规则引擎层"""

    def __init__(self):
        # 实体归一化解析器（用于人名/公司名的角色绑定）
        self._resolver = EntityResolver()
        
        # 已替换的记录，避免重复替换
        self._replaced = {}   # original -> (replacement, type)
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
        text = self._mask_person_name(text)    # 人名（角色词上下文）
        text = self._mask_company_name(text)   # 公司名
        text = self._mask_address(text)        # 地址
        text = self._mask_amount(text)         # 金额（带单位的大额数字）

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
        self._resolver.reset()
        self._replaced = {}
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
        """微信号：匹配有前缀 或 独立出现的微信号模式"""
        # 微信号: xxx 或 微信: xxx（有前缀，带冒号）
        text = re.sub(
            r'(微信号|微信)\s*[：:]\s*([a-zA-Z][a-zA-Z0-9_]{4,19})',
            lambda m: self._safe_replace_wechat(m.group(2), m.group(1)),
            text
        )
        # 独立微信号：字母开头 + 字母数字下划线，6-20位
        # 使用 [a-zA-Z0-9_] 而非 \w 避免匹配中文
        # 排除邮箱（含@）、URL、纯数字
        text = re.sub(
            r'(?<![a-zA-Z0-9_@/.])([a-zA-Z][a-zA-Z0-9_]{5,19})(?![a-zA-Z0-9_@]|\.com|\.cn)',
            lambda m: self._safe_replace_wechat(m.group(1)),
            text
        )
        return text

    def _safe_replace_wechat(self, original: str, prefix: str = '') -> str:
        """记录微信号替换"""
        self._replaced[original] = ('[微信号]', '微信号')
        self._stats['微信号'] = self._stats.get('微信号', 0) + 1
        return f'{prefix}：[微信号]' if prefix else '[微信号]'

    def _mask_qq(self, text: str) -> str:
        """QQ号"""
        text = re.sub(
            r'[Qq][Qq]\s*[：:]?\s*(\d{5,12})',
            lambda m: '[QQ号]',
            text
        )
        return text

    def _mask_bank_card(self, text: str) -> str:
        """银行卡号：14-20位纯数字（覆盖各银行不同长度）"""
        # 注意：排除前面已匹配的身份证号(18位)、手机号(11位)的上下文
        # 常见银行卡长度：招行16位、建行19位、部分旧卡15位、企业账户20位
        return self._safe_replace(
            text,
            r'(?<!\d)(\d{14,20})(?!\d)',
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
                    self._replaced[canonical] = (placeholder, '人名')
                    self._stats['人名'] = self._stats.get('人名', 0) + 1
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
                        return f'{role} {placeholder}'
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
            self._replaced[name] = (placeholder, '公司名')
            self._stats['公司名'] = self._stats.get('公司名', 0) + 1
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
            r'(?<!\w)([\u4e00-\u9fa5]{3,6})公司(?![\u4e00-\u9fa5])',
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
            lambda m: self._record_addr(m.group(2), m.group(1)),
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
        self._replaced[addr.replace(' ', '')] = ('[地址]', '地址')
        self._stats['地址'] = self._stats.get('地址', 0) + 1
        return f'{prefix}：[地址]' if prefix else '[地址]'

    def _mask_amount(self, text: str) -> str:
        """
        金额匹配：大额货币数值（人民币/美元/欧元等）
        匹配格式：¥2,350,000元  236,000,000.00元  80万  3.6万  500美元  80万
                 伍佰万元整  贰亿叁仟陆佰万元整  人民币伍佰万元
        排除：普通数字、日期、股票数量（带"股"）、百分比（带%）
        """
        # 中文大写金额：零壹贰叁肆伍陆柒捌玖拾佰仟万亿元整
        text = self._safe_replace(
            text,
            r'(?:人民币|美金|港币)?[零壹贰叁肆伍陆柒捌玖拾佰仟万亿元整亿]+(?:元|圆)?(?:整)?',
            '[金额]',
            '金额'
        )
        # 带"元/美元/欧元"等单位的完整金额
        text = self._safe_replace(
            text,
            r'(?:¥)?(?:\d{1,3}(?:,\d{3})*|\d+)(?:\.\d{1,2})?(?:[万千亿])?(?:元|美元|欧元|英镑|港币)(?![.\d万千亿])',
            '[金额]',
            '金额'
        )
        # 口语化金额：X万 / X.X万（无"元"后缀，如"借我80万""3.6万利息"）
        text = self._safe_replace(
            text,
            r'(?<!\d)(\d+(?:\.\d+)?)[万千亿](?![.\d万千亿])',
            '[金额]',
            '金额'
        )
        return text


    def _get_all_rules(self):
        """返回所有规则（用于scan）"""
        return [
            ('身份证号', r'\d{17}[\dXx]', self._mask_id_card),
            ('手机号', r'1[3-9]\d{9}', self._mask_phone),
            ('固定电话', r'0\d{2,3}[-\s]?\d{7,8}', self._mask_landline),
            ('邮箱', r'[\w.+-]+@[\w-]+\.[\w.-]+', self._mask_email),
            ('银行账号', r'\d{14,20}', self._mask_bank_card),
            ('统一社会信用代码', r'[0-9A-Z]{18}', self._mask_credit_code),
            ('案号', r'\(?\d{4}\)?[\u4e00-\u9fa5]{1,10}\(?\d{1,6}\)?\d{0,3}号?', self._mask_case_number),
            ('车牌号', r'[\u4e00-\u9fa5][A-Z][A-Z0-9]{5,6}', self._mask_license_plate),
            ('日期', r'\d{4}年\d{1,2}月\d{1,2}日', self._mask_date),
            ('人名', r'(原告|被告|法定代表人|委托诉讼代理人|审判员|书记员)[：:]\s*[\u4e00-\u9fa5]{2,3}', self._mask_person_name),
            ('公司名', r'[\u4e00-\u9fa5]{3,30}(?:有限公司|公司|集团|事务所)', self._mask_company_name),
            ('地址', r'[\u4e00-\u9fa5]{1,3}省[\u4e00-\u9fa5\s]{1,10}市[\u4e00-\u9fa5\s]{1,10}(?:区|县)[\u4e00-\u9fa5\d\s\-]{5,40}(?:号|室|层)', self._mask_address),
            ('金额', r'(?:¥)?(?:\d{1,3}(?:,\d{3})*|\d+)(?:\.\d{1,2})?(?:[万千亿])?(?:元|美元|欧元|英镑|港币)(?![.\d万千亿])', self._mask_amount),
            ('微信号', r'[a-zA-Z][a-zA-Z0-9_]{5,19}', self._mask_wechat),
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

    # scan 命令
    scan_parser = subparsers.add_parser('scan', help='扫描敏感信息（不替换）')
    scan_parser.add_argument('-f', '--file', help='输入文件路径（默认从stdin读取）')
    scan_parser.add_argument('--json', action='store_true', help='以JSON格式输出')

    # llm-prompt 命令
    llm_parser = subparsers.add_parser('llm-prompt', help='生成LLM脱敏提示词（规则层+LLM提示）')
    llm_parser.add_argument('-f', '--file', help='输入文件路径（默认从stdin读取）')

    # decrypt 命令
    decrypt_parser = subparsers.add_parser('decrypt', help='解密加密的映射表文件')
    decrypt_parser.add_argument('-f', '--file', required=True, help='加密的映射表文件路径')
    decrypt_parser.add_argument('-k', '--key', help='Fernet 解密密钥（v2.0 旧格式兼容，不推荐）')
    decrypt_parser.add_argument('-p', '--password', help='AES-GCM 解密密码（v2.1+，优先使用。也可通过环境变量 DESENSITIZER_MAPPING_PASSWORD 设置）')
    decrypt_parser.add_argument('-o', '--output', help='输出路径（默认输出到 stdout）')

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

    d = Desensitizer()

    # 如果启用了内存安全增强，使用 SecureDesensitizer
    secure_mode = False
    if hasattr(args, 'secure') and args.secure:
        secure_mode = True
    if hasattr(args, 'security_level') and args.security_level in ('strict', 'high'):
        secure_mode = True

    if secure_mode:
        level = args.security_level if hasattr(args, 'security_level') else 'strict'
        d = SecureDesensitizer(security_level=level)
        if sys.stderr.isatty():
            print(f'🔒 内存安全增强模式已启用 (security_level={level})', file=sys.stderr)
            print(f'   ⚠️  Python 字符串不可变，内存清理为"尽力而为"的纵深防御', file=sys.stderr)

    if args.command == 'mask':
        result = d.mask(text)

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

    else:
        parser.print_help()


if __name__ == '__main__':
    main()
