"""
法律实体识别模块 (Legal Entity Recognition Interface)
=====================================================

设计目标：
  提供一个统一的实体识别接口，可接入不同后端：
  - 正则引擎（当前已实现）
  - spaCy 模型
  - HuggingFace Transformers
  - 本地 LLM（Ollama 等）
  - 云端 LLM API

使用方式：
  from ner_interface import LegalNER, Entity, EntityType
  
  ner = LegalNER(backend='regex')  # 默认使用正则引擎
  entities = ner.extract("原告金进跃，被告杭州鼎盛房地产开发有限公司")
  # → [Entity(PERSON, "金进跃"), Entity(COMPANY, "杭州鼎盛房地产开发有限公司")]

与 desensitize.py 的集成：
  from ner_interface import LegalNER
  from desensitize import Desensitizer
  
  d = Desensitizer()
  d.set_ner_backend(LegalNER(backend='spacy', model='zh_core_web_trf'))
  result = d.mask_with_ner(text)
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Tuple, Protocol
import re


# ═══════════════════════════════════════════════════════════
# 1. 实体类型枚举
# ═══════════════════════════════════════════════════════════

class EntityType(str, Enum):
    """法律文书中的实体类型"""
    PERSON   = 'PERSON'    # 自然人姓名（当事人、法官、证人等）
    COMPANY  = 'COMPANY'   # 公司/机构/组织名称
    COURT    = 'COURT'     # 法院名称
    LAWYER   = 'LAWYER'    # 律师姓名（与 PERSON 区分）
    ADDRESS  = 'ADDRESS'   # 地址信息
    
    # 扩展预留（后续可补充）
    AMOUNT   = 'AMOUNT'     # 金额
    ID_CARD  = 'ID_CARD'    # 身份证号
    PHONE    = 'PHONE'      # 手机号
    BANK     = 'BANK_CARD'  # 银行账号
    CASE_NO  = 'CASE_NO'    # 案号
    DATE     = 'DATE'       # 日期


# ═══════════════════════════════════════════════════════════
# 2. 实体数据模型
# ═══════════════════════════════════════════════════════════

@dataclass
class Entity:
    """一个识别出的法律实体"""
    type: EntityType          # 实体类型
    text: str                 # 原始文本
    start: int                # 在原文中的起始位置
    end: int                  # 在原文中的结束位置
    confidence: float = 1.0   # 置信度 (0.0 ~ 1.0)
    metadata: dict = field(default_factory=dict)  # 额外信息（如角色、上下文等）

    def to_dict(self) -> dict:
        return {
            'type': self.type.value,
            'text': self.text,
            'start': self.start,
            'end': self.end,
            'confidence': self.confidence,
            'metadata': self.metadata,
        }

    def __repr__(self) -> str:
        return f"Entity({self.type.value}, '{self.text}', conf={self.confidence:.2f})"


# ═══════════════════════════════════════════════════════════
# 3. 实体识别结果
# ═══════════════════════════════════════════════════════════

@dataclass
class ExtractionResult:
    """一次实体提取的完整结果"""
    text: str                       # 原始文本
    entities: List[Entity]          # 识别出的实体列表
    backend: str = 'unknown'        # 使用的后端名称
    latency_ms: float = 0.0         # 处理耗时（毫秒）
    
    def by_type(self, entity_type: EntityType) -> List[Entity]:
        """按类型筛选实体"""
        return [e for e in self.entities if e.type == entity_type]
    
    def to_dict(self) -> dict:
        return {
            'entities': [e.to_dict() for e in self.entities],
            'backend': self.backend,
            'latency_ms': self.latency_ms,
        }


# ═══════════════════════════════════════════════════════════
# 4. 后端抽象接口
# ═══════════════════════════════════════════════════════════

class NERBackend(Protocol):
    """NER 后端必须实现的接口"""
    
    def extract(self, text: str) -> ExtractionResult:
        """从文本中提取法律实体"""
        ...
    
    @property
    def name(self) -> str:
        """后端名称"""
        ...


# ═══════════════════════════════════════════════════════════
# 5. 内置正则后端（演示用，实际由 desensitize.py 提供）
# ═══════════════════════════════════════════════════════════

class RegexNERBackend:
    """
    基于正则表达式的 NER 后端。
    作为演示实现，完整版由 desensitize.py 的规则引擎提供。
    """
    
    def __init__(self):
        self._name = 'regex-builtin'
    
    @property
    def name(self) -> str:
        return self._name
    
    def extract(self, text: str) -> ExtractionResult:
        import time
        t0 = time.time()
        
        entities = []
        
        # PERSON：仅匹配角色词 + 冒号/空格后的 2-3 字姓名
        # 分隔符可为空（如"原告金进跃"）、冒号（"原告：金进跃"）或逗号
        for m in re.finditer(
            r'(原告|委托诉讼代理人|委托代理人|法定代表人|法定代理人|审判员|书记员)[：:，,，\s]*([\u4e00-\u9fa5]{2,3})(?=[，,。.\s（(]|的|$)',
            text
        ):
            entities.append(Entity(
                type=EntityType.PERSON,
                text=m.group(2),
                start=m.start(2),
                end=m.end(2),
                confidence=0.95,
                metadata={'role': m.group(1)}
            ))
        
        # COMPANY：公司/机构名称
        for m in re.finditer(
            r'([\u4e00-\u9fa5（）\(\)]{2,30}(?:有限公司|股份有限公司|集团公司|有限责任公司|合伙企业|律师事务所|会计师事务所))',
            text
        ):
            # 排除公司名开头的人物角色词
            name = m.group(1)
            if any(name.startswith(role) for role in ['原告','被告','法定代表人','委托诉讼代理人']):
                continue
            entities.append(Entity(
                type=EntityType.COMPANY,
                text=m.group(1),
                start=m.start(1),
                end=m.end(1),
                confidence=0.9,
            ))
        
        # COURT：XX法院
        for m in re.finditer(
            r'([\u4e00-\u9fa5]{2,10}(?:人民法院|中级人民法院|高级人民法院|最高法院|海事法院|仲裁委员会))',
            text
        ):
            entities.append(Entity(
                type=EntityType.COURT,
                text=m.group(1),
                start=m.start(1),
                end=m.end(1),
                confidence=0.95,
            ))
        
        # LAWYER：XX律师事务所 + 律师姓名
        for m in re.finditer(
            r'((?:[\u4e00-\u9fa5]{2,10}(?:律师事务所|律所))[\u4e00-\u9fa5]{2,3}律师)',
            text
        ):
            entities.append(Entity(
                type=EntityType.LAWYER,
                text=m.group(1),
                start=m.start(1),
                end=m.end(1),
                confidence=0.85,
            ))
        
        # ADDRESS：省/市/区/路/号（排除"住所地"等前缀）
        for m in re.finditer(
            r'([\u4e00-\u9fa5]{1,3}(?:省|自治区)[\u4e00-\u9fa5\s]{1,10}(?:市)[\u4e00-\u9fa5\s]{1,10}(?:区|县|市)[\u4e00-\u9fa5\d\-（\(）\)\s]{5,40}(?:号|室|层))',
            text
        ):
            addr = m.group(1).replace(' ', '')
            # 去掉开头的"住所地""住址""地址"等前缀
            for prefix in ['住所地','住址','地址']:
                if addr.startswith(prefix):
                    addr = addr[len(prefix):]
            if addr:
                entities.append(Entity(
                type=EntityType.ADDRESS,
                text=m.group(1).replace(' ', ''),
                start=m.start(1),
                end=m.end(1),
                confidence=0.85,
            ))
        
        # 去重：同一位置的取置信度最高的
        entities = self._deduplicate(entities)
        
        t1 = time.time()
        return ExtractionResult(
            text=text,
            entities=entities,
            backend=self._name,
            latency_ms=(t1 - t0) * 1000,
        )
    
    def _deduplicate(self, entities: List[Entity]) -> List[Entity]:
        """同一位置的实体，保留置信度最高的一个"""
        if not entities:
            return []
        # 按 (start, end) 分组
        by_pos = {}
        for e in entities:
            key = (e.start, e.end)
            if key not in by_pos or e.confidence > by_pos[key].confidence:
                by_pos[key] = e
        return list(by_pos.values())


# ═══════════════════════════════════════════════════════════
# 6. 预留后端桩（Stub）
# ═══════════════════════════════════════════════════════════

class SpacyNERBackend:
    """spaCy NER 后端桩 — 待接入"""
    
    def __init__(self, model: str = 'zh_core_web_trf'):
        self._model_name = model
        self._name = f'spacy-{model}'
    
    @property
    def name(self) -> str:
        return self._name
    
    def extract(self, text: str) -> ExtractionResult:
        raise NotImplementedError(
            "spaCy 后端尚未接入。\n"
            f"  安装: python -m spacy download {self._model_name}\n"
            "  接入后替换此处实现即可。"
        )


class HuggingFaceNERBackend:
    """HuggingFace NER 后端桩 — 待接入"""
    
    def __init__(self, model: str = 'bert-base-chinese'):
        self._model_name = model
        self._name = f'hf-{model}'
    
    @property
    def name(self) -> str:
        return self._name
    
    def extract(self, text: str) -> ExtractionResult:
        raise NotImplementedError(
            "HuggingFace 后端尚未接入。\n"
            f"  安装: pip install transformers\n"
            f"  模型: {self._model_name}\n"
            "  接入后替换此处实现即可。"
        )


class LLMNERBackend:
    """本地/云端 LLM NER 后端桩 — 待接入"""
    
    def __init__(self, 
                 endpoint: str = 'http://localhost:11434/api/generate',
                 model: str = 'qwen2.5',
                 prompt_template: Optional[str] = None):
        self._endpoint = endpoint
        self._model = model
        self._name = f'llm-{model}'
        
        # 默认提示词模板
        self._prompt_template = prompt_template or """请从以下法律文书中提取实体，按 JSON 格式返回：

{text}

实体类型：
- PERSON: 自然人姓名
- COMPANY: 公司/机构名称  
- COURT: 法院名称
- LAWYER: 律师姓名
- ADDRESS: 地址信息

返回格式：[{{"type": "PERSON", "text": "张三", "start": 0, "end": 2}}, ...]"""
    
    @property
    def name(self) -> str:
        return self._name
    
    def extract(self, text: str) -> ExtractionResult:
        raise NotImplementedError(
            "LLM 后端尚未接入。\n"
            f"  端点: {self._endpoint}\n"
            f"  模型: {self._model}\n"
            "  接入后替换此处实现即可。\n"
            "  支持：Ollama / OpenAI API / Claude API"
        )


# ═══════════════════════════════════════════════════════════
# 7. 统一入口 Facade
# ═══════════════════════════════════════════════════════════

class LegalNER:
    """
    法律实体识别统一入口
    
    用法：
        ner = LegalNER(backend='regex')
        result = ner.extract("原告金进跃，被告杭州鼎盛房地产开发有限公司")
        
        ner = LegalNER(backend='spacy', model='zh_core_web_trf')
        ner = LegalNER(backend='huggingface', model='bert-base-chinese')
        ner = LegalNER(backend='llm', model='qwen2.5')
    """
    
    BACKENDS = {
        'regex': RegexNERBackend,
        'spacy': SpacyNERBackend,
        'huggingface': HuggingFaceNERBackend,
        'llm': LLMNERBackend,
    }
    
    def __init__(self, backend: str = 'regex', **kwargs):
        if backend not in self.BACKENDS:
            raise ValueError(f"不支持的后端 '{backend}'，可选: {list(self.BACKENDS.keys())}")
        
        self._backend: NERBackend = self.BACKENDS[backend](**kwargs)
    
    @property
    def backend_name(self) -> str:
        return self._backend.name
    
    def extract(self, text: str) -> ExtractionResult:
        """从文本中提取实体"""
        return self._backend.extract(text)
    
    def extract_types(self, text: str, types: List[EntityType]) -> ExtractionResult:
        """仅提取指定类型的实体"""
        result = self._backend.extract(text)
        result.entities = [e for e in result.entities if e.type in types]
        return result
    
    def set_backend(self, backend: str, **kwargs):
        """切换后端"""
        self.__init__(backend, **kwargs)


# ═══════════════════════════════════════════════════════════
# 8. 与 desensitize.py 的集成点（设计方案）
# ═══════════════════════════════════════════════════════════

"""
集成方案：

1. 在 Desensitizer 类中添加 NER 支持：

    class Desensitizer:
        def __init__(self):
            ...
            self._ner = None  # LegalNER 实例
        
        def set_ner_backend(self, ner: LegalNER):
            self._ner = ner
        
        def mask_with_ner(self, text: str) -> MaskResult:
            # 先规则层脱敏
            result = self.mask(text)
            if not self._ner:
                return result
            
            # NER 识别剩余实体
            ner_result = self._ner.extract(result.text)
            
            # 替换 NER 识别出的实体
            for entity in ner_result.entities:
                placeholder = f'[{entity.type.value}]'
                result.text = result.text[:entity.start] + placeholder + result.text[entity.end:]
            
            return result

2. 使用流程：

    from ner_interface import LegalNER
    from desensitize import Desensitizer
    
    # 使用正则后端（内置，无需额外依赖）
    d = Desensitizer()
    d.set_ner_backend(LegalNER(backend='regex'))
    result = d.mask_with_ner(text)
    
    # 使用 spaCy 后端（需要下载模型）
    d.set_ner_backend(LegalNER(backend='spacy', model='zh_core_web_trf'))
    
    # 使用本地 LLM（需要 Ollama）
    d.set_ner_backend(LegalNER(backend='llm', 
                                endpoint='http://localhost:11434/api/generate',
                                model='qwen2.5'))
"""


# ═══════════════════════════════════════════════════════════
# 9. 测试用例
# ═══════════════════════════════════════════════════════════

def demo():
    """演示用法"""
    print("=" * 50)
    print("法律实体识别模块 — 演示")
    print("=" * 50)
    
    # 正则后端（可用）
    ner = LegalNER(backend='regex')
    
    test_cases = [
        "原告金进跃，男，1985年8月15日出生",
        "被告杭州鼎盛房地产开发有限公司",
        "浙江省杭州市西湖区人民法院",
        "委托诉讼代理人赵敏，浙江泽大律师事务所律师",
        "住所地浙江省杭州市拱墅区莫干山路100号",
    ]
    
    for text in test_cases:
        result = ner.extract(text)
        print(f"\n输入: {text}")
        print(f"后端: {result.backend} ({result.latency_ms:.1f}ms)")
        for e in result.entities:
            print(f"  → {e.type.value:8s} | {e.text}")
    
    print("\n" + "=" * 50)
    print("其他后端待接入（当前为桩，调用会抛出 NotImplementedError）")
    print("  LegalNER(backend='spacy')       # 需要: python -m spacy download zh_core_web_trf")
    print("  LegalNER(backend='huggingface')  # 需要: pip install transformers")
    print("  LegalNER(backend='llm')          # 需要: Ollama / OpenAI API")
    print("=" * 50)


if __name__ == '__main__':
    demo()
