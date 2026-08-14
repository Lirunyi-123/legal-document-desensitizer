# -*- coding: utf-8 -*-
"""LLM 层回归测试：注入 mock LLM 响应，端到端验证（无需真实模型/网络）。"""

import json
import unittest
from unittest import mock

from desensitize import Desensitizer, restore_text, parse_mapping_text
from llm_layer import (
    LLMConfig, full_desensitize, parse_full_response, validate_llm_output,
    reorder_merged_mapping, LLMLayerError, build_full_prompt,
)


# 模拟 LLM 的"脱敏逻辑"：已知敏感词 → 占位符
MOCK_RULES = [
    ('张三', '[当事人丙]', '人名'),
    ('李四', '[当事人丁]', '人名'),
    ('王五', '[当事人戊]', '人名'),
    ('望京西园四区410楼', '[地址]', '地址'),
    ('因婚外情导致家庭破裂，并曾接受心理治疗', '[案情细节]', '案情细节'),
    ('华信置业', '[合同丙方]', '公司名'),
    ('鼎盛集团', '[合同丁方]', '公司名'),
]


def mock_llm_response(prompt, config=None):
    """模拟 LLM：从提示词中取出待处理文本，做确定性替换。"""
    marker = '### 待处理文本\n'
    text = prompt.split(marker, 1)[1] if marker in prompt else ''
    replacements = []
    for original, placeholder, typ in MOCK_RULES:
        if original in text:
            replacements.append({'original': original,
                                 'replacement': placeholder, 'type': typ})
            text = text.replace(original, placeholder)
    return (
        '### 脱敏后文本\n' + text + '\n\n'
        '### 补充映射表\n' + json.dumps(replacements, ensure_ascii=False)
    )


class TestLLMPipeline(unittest.TestCase):
    def setUp(self):
        self.config = LLMConfig(api='ollama', model='mock',
                                endpoint='http://127.0.0.1:11434')
        self._patcher = mock.patch('llm_layer.call_llm', side_effect=mock_llm_response)
        self._patcher.start()

    def tearDown(self):
        self._patcher.stop()

    def test_full_pipeline_covers_llm_only_items(self):
        text = ('原告：陈建国，男，身份证号110101198001011232。\n'
                '张三欠李四钱不还，双方约定在望京西园四区410楼当面核账。\n'
                '华信置业与鼎盛集团签订合作框架协议。\n'
                '原告称其因婚外情导致家庭破裂，并曾接受心理治疗。')
        result, warnings = full_desensitize(text, self.config)
        self.assertEqual(warnings, [])
        # 裸人名/无结构地址现在由规则层覆盖（不依赖 LLM 层）
        self.assertNotIn('张三', result.text)
        self.assertNotIn('李四', result.text)
        self.assertNotIn('望京西园', result.text)
        self.assertIn('[地址]', result.text)
        # 案情敏感细节必须由 LLM 层处理
        self.assertIn('[案情细节]', result.text)
        self.assertNotIn('婚外情', result.text)
        # 规则层占位符不受影响
        self.assertIn('[身份证号]', result.text)
        # 合并映射可无损还原
        restored = restore_text(result.text, parse_mapping_text(result.to_json()))
        self.assertEqual(restored, text)

    def test_shared_placeholder_order_merged(self):
        # 规则层与 LLM 层都产生 [地址]，合并后按原文顺序配对还原
        text = ('住所地浙江省杭州市西湖区文一西路1号。\n'
                '双方约定在望京西园四区410楼核账。')
        result, _ = full_desensitize(text, self.config)
        restored = restore_text(result.text, parse_mapping_text(result.to_json()))
        self.assertEqual(restored, text)

    def test_fail_safe_line_count_drift(self):
        def bad_response(prompt, config=None):
            text = prompt.split('### 待处理文本\n', 1)[1]
            return ('### 脱敏后文本\n' + text + '\n额外的一行\n\n'
                    '### 补充映射表\n[]')

        with mock.patch('llm_layer.call_llm', side_effect=bad_response):
            with self.assertRaises(LLMLayerError):
                full_desensitize('原告：陈建国。', self.config)

    def test_fail_safe_leaked_original(self):
        def leak_response(prompt, config=None):
            text = prompt.split('### 待处理文本\n', 1)[1]
            return ('### 脱敏后文本\n' + text + '\n\n'
                    '### 补充映射表\n'
                    '[{"original": "张三", "replacement": "[当事人丙]", "type": "人名"}]')

        with mock.patch('llm_layer.call_llm', side_effect=leak_response):
            # 文本中没有张三，但映射声称替换了 → 映射占位符未出现 → 仅告警
            result, warnings = full_desensitize('原告：陈建国。', self.config)
            self.assertEqual(result.text, '原告：[当事人甲（原告）]。')
            self.assertTrue(any('张三' in w for w in warnings))

    def test_call_llm_prompt_contains_rule_masked_text(self):
        prompt = build_full_prompt('原告：[当事人甲（原告）]。')
        self.assertIn('### 待处理文本', prompt)
        self.assertIn('[当事人甲（原告）]', prompt)

    def test_parse_full_response_missing_section(self):
        with self.assertRaises(LLMLayerError):
            parse_full_response('没有小节标记的乱输出')


class TestReorderMergedMapping(unittest.TestCase):
    def test_reorder_by_original_position(self):
        from desensitize import Mapping
        text = '甲方住所地A地址。乙方在望京B地址。'
        mappings = [
            Mapping(original='A地址', replacement='[地址]', type='地址', count=1, order=1),
            Mapping(original='B地址', replacement='[地址]', type='地址', count=1, order=2),
        ]
        out = reorder_merged_mapping(mappings, text)
        self.assertEqual([m.original for m in out], ['A地址', 'B地址'])
        self.assertEqual([m.order for m in out], [1, 2])


class TestCloudAPI(unittest.TestCase):
    """云端 OpenAI 兼容 API 通道（不发真实请求，全部 mock）。"""

    def test_chat_url_variants(self):
        from llm_layer import _chat_url
        cases = {
            'https://dashscope.aliyuncs.com/compatible-mode':
                'https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions',
            'https://api.deepseek.com':
                'https://api.deepseek.com/v1/chat/completions',
            'https://open.bigmodel.cn/api/paas/v4':
                'https://open.bigmodel.cn/api/paas/v4/chat/completions',
            'http://localhost:1234':
                'http://localhost:1234/v1/chat/completions',
        }
        for endpoint, expected in cases.items():
            self.assertEqual(_chat_url(endpoint), expected)

    def test_openai_call_sends_key_and_parses(self):
        from llm_layer import call_llm, LLMConfig
        captured = {}

        class FakeResp:
            def read(self):
                return json.dumps({
                    'choices': [{'message': {
                        'content': '### 脱敏后文本\nX\n\n### 补充映射表\n[]'}}]
                }).encode('utf-8')

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def fake_urlopen(req, timeout=180):
            captured['url'] = req.full_url
            captured['headers'] = dict(req.headers)
            captured['body'] = json.loads(req.data.decode('utf-8'))
            return FakeResp()

        with mock.patch('llm_layer.urllib.request.urlopen',
                        side_effect=fake_urlopen):
            out = call_llm('prompt', LLMConfig(
                api='openai', model='qwen-plus',
                endpoint='https://dashscope.aliyuncs.com/compatible-mode',
                api_key='sk-test-123'))

        self.assertIn('/v1/chat/completions', captured['url'])
        self.assertEqual(captured['headers']['Authorization'], 'Bearer sk-test-123')
        self.assertEqual(captured['body']['model'], 'qwen-plus')
        self.assertEqual(captured['body']['temperature'], 0.0)
        self.assertIn('### 脱敏后文本', out)

    def test_ollama_call_has_no_json_format(self):
        """Ollama 请求体不得带 format:'json'——full 提示词期望的是
        '### 脱敏后文本 … ### 补充映射表' 混合文本格式，强制 JSON 会破坏解析。"""
        from llm_layer import call_llm, LLMConfig
        captured = {}

        class FakeResp:
            def read(self):
                return json.dumps({
                    'response': '### 脱敏后文本\nX\n\n### 补充映射表\n[]'
                }).encode('utf-8')

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def fake_urlopen(req, timeout=180):
            captured['body'] = json.loads(req.data.decode('utf-8'))
            return FakeResp()

        with mock.patch('llm_layer.urllib.request.urlopen',
                        side_effect=fake_urlopen):
            out = call_llm('prompt', LLMConfig(
                api='ollama', model='mock',
                endpoint='http://127.0.0.1:11434'))

        self.assertNotIn('format', captured['body'])
        self.assertEqual(captured['body']['stream'], False)
        self.assertEqual(captured['body']['model'], 'mock')
        self.assertIn('### 脱敏后文本', out)


class TestV53LLMFixes(unittest.TestCase):
    """v5.3：LLM 合并映射 count/排序修复、补充映射表贪婪正则修复、往返校验。"""

    def setUp(self):
        self.config = LLMConfig(api='ollama', model='mock',
                                endpoint='http://127.0.0.1:11434')

    def _fake(self, mapping_rules):
        """构造一个确定性 mock LLM：按 mapping_rules 替换并输出 JSON 映射表。"""
        def respond(prompt, config=None):
            text = prompt.split('### 待处理文本\n', 1)[1]
            items = []
            for original, replacement, typ in mapping_rules:
                if original in text:
                    text = text.replace(original, replacement)
                    items.append({'original': original,
                                  'replacement': replacement, 'type': typ})
            return ('### 脱敏后文本\n' + text + '\n\n'
                    '### 补充映射表\n' + json.dumps(items, ensure_ascii=False))
        return respond

    def test_shared_placeholder_count_not_inflated(self):
        """规则层与 LLM 层共用 [地址]：LLM 条目 count 只取规则层文本中
        original 的出现次数，不是占位符在 LLM 输出中的总数。"""
        text = ('住所地浙江省杭州市西湖区文一西路1号。\n'
                '另有约见地点为村口老槐树旁。')
        with mock.patch('llm_layer.call_llm',
                        side_effect=self._fake(
                            [('村口老槐树旁', '[地址]', '地址')])):
            result, warnings = full_desensitize(text, self.config)
        self.assertEqual(warnings, [])
        llm_item = [m for m in result.mapping
                    if m.original == '村口老槐树旁']
        self.assertEqual(len(llm_item), 1)
        self.assertEqual(llm_item[0].count, 1)  # 修复前会误计为 2
        self.assertEqual(sum(m.count for m in result.mapping),
                         result.stats['总替换次数'])
        restored = restore_text(result.text,
                                parse_mapping_text(result.to_json()))
        self.assertEqual(restored, text)

    def test_reorder_repeated_original_interleaved(self):
        """同一原始值多次出现且与其它条目交错：逐次推进扫描取第 n 次位置。"""
        from desensitize import Mapping
        text = '甲方住所：A地址。乙方住所：B地址。丙方住所：A地址。'
        mappings = [
            Mapping(original='A地址', replacement='[地址]', type='地址',
                    count=1, order=1),
            Mapping(original='B地址', replacement='[地址]', type='地址',
                    count=1, order=2),
            Mapping(original='A地址', replacement='[地址]', type='地址',
                    count=1, order=3),
        ]
        out = reorder_merged_mapping(mappings, text)
        self.assertEqual([m.original for m in out],
                         ['A地址', 'B地址', 'A地址'])
        self.assertEqual([m.order for m in out], [1, 2, 3])

    def test_repeated_original_full_roundtrip(self):
        """同一 LLM 原始值多次出现：count=2，合并映射还原逐字节一致。"""
        text = '原告自述曾因婚外情与配偶争吵，婚外情对象为同事。'
        with mock.patch('llm_layer.call_llm',
                        side_effect=self._fake(
                            [('婚外情', '[案情细节]', '案情细节')])):
            result, warnings = full_desensitize(text, self.config)
        self.assertEqual(warnings, [])
        item = [m for m in result.mapping if m.original == '婚外情']
        self.assertEqual(len(item), 1)
        self.assertEqual(item[0].count, 2)
        self.assertEqual(result.stats['总替换次数'], 2)
        restored = restore_text(result.text,
                                parse_mapping_text(result.to_json()))
        self.assertEqual(restored, text)

    def test_parse_full_response_json_only_after_marker(self):
        """脱敏后文本小节里出现 [{...}] 形态时，JSON 数组只在
        '### 补充映射表' 标记之后搜索，避免贪婪正则跨小节错配。"""
        response = ('### 脱敏后文本\n'
                    '正文包含疑似数组形态：[{"x": 1}] 但属于正文，不得误匹配。\n\n'
                    '### 补充映射表\n'
                    '[{"original": "张三", "replacement": "[当事人丙]", '
                    '"type": "人名"}]')
        masked, items = parse_full_response(response)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]['original'], '张三')
        self.assertIn('不得误匹配', masked)


if __name__ == '__main__':
    unittest.main()
