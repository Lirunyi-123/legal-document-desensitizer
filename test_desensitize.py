# -*- coding: utf-8 -*-
"""v2.2 回归测试（纯标准库，python -m unittest test_desensitize）"""

import unittest

from desensitize import (
    Desensitizer, SecureDesensitizer,
    parse_mapping_text, restore_text,
    _is_valid_id_checksum, _is_valid_credit_code, _luhn_check,
)  # 导入成功即验证类定义顺序修复


class TestRuleLayerFixes(unittest.TestCase):
    def setUp(self):
        self.d = Desensitizer()

    def test_law_firm_license_not_credit_code(self):
        result = self.d.mask('执业许可证号：31110000E000123456')
        self.assertIn('[律师执业证号]', result.text)
        for m in result.mapping:
            self.assertNotEqual(m.type, '统一社会信用代码')

    def test_credit_code_labeled_and_bare_9(self):
        result = self.d.mask('统一社会信用代码：91110108MA01ABC123；另一个 91330105MA27XABC1D')
        self.assertEqual(result.text.count('[统一社会信用代码]'), 2)

    def test_id_with_context(self):
        result = self.d.mask('身份证号110101198001011234')
        self.assertIn('身份证号[身份证号]', result.text)

    def test_18_digit_bank_card_not_id(self):
        result = self.d.mask('账户622202020001234567')
        self.assertIn('[银行账号]', result.text)
        self.assertNotIn('身份证号', result.text)

    def test_birthdate_only_by_default(self):
        result = self.d.mask('签订日期：2024年1月15日，男，1985年8月15日出生')
        self.assertIn('2024年1月15日', result.text)   # 普通日期保留
        self.assertIn('[出生日期]', result.text)      # 出生日期脱敏

    def test_all_dates_flag(self):
        result = Desensitizer(mask_all_dates=True).mask('签订日期：2024年1月15日')
        self.assertIn('[日期]', result.text)

    def test_per_value_count(self):
        result = self.d.mask('A 13800138000 B 13800138000 C 13912345678')
        by_original = {m.original: m.count for m in result.mapping}
        self.assertEqual(by_original.get('13800138000'), 2)
        self.assertEqual(by_original.get('13912345678'), 1)
        self.assertEqual(result.stats['总替换次数'], 3)

    def test_wechat_and_qq_recorded(self):
        result = self.d.mask('微信号：lawyer_wang，QQ：12345678')
        types = {m.type for m in result.mapping}
        self.assertIn('微信号', types)
        self.assertIn('QQ号', types)

    def test_email_not_broken_by_phone_rule(self):
        result = self.d.mask('13800138000@qq.com')
        self.assertIn('[邮箱]', result.text)
        self.assertNotIn('[手机号]@', result.text)

    def test_case_number(self):
        result = self.d.mask('案号：(2024)京0108民初12345号')
        self.assertIn('案号：[案号]', result.text)

    def test_license_plate_not_wechat(self):
        result = self.d.mask('我开保时捷粤B88888去')
        self.assertIn('[车牌号]', result.text)
        self.assertNotIn('[微信号]', result.text)

    def test_entity_resolver_still_works(self):
        result = self.d.mask('原告：陈建国。被告：杭州鼎盛房地产开发有限公司。陈建国再次出现。')
        self.assertIn('[当事人甲（原告）]', result.text)
        self.assertIn('[合同乙方]', result.text)
        for m in result.mapping:
            if m.original == '陈建国':
                self.assertEqual(m.replacement, '[当事人甲（原告）]')

    def test_secure_mode_with_all_dates(self):
        d = SecureDesensitizer(security_level='strict', mask_all_dates=True)
        result = d.mask('身份证号110101198001011234，日期2024年1月15日')
        self.assertIn('[身份证号]', result.text)
        self.assertIn('[日期]', result.text)

    def test_scan_covers_key_types(self):
        text = '执业证号：111012023123456789；手机13800138000；QQ：12345678；身份证号110101198001011234'
        types = {f['type'] for f in self.d.scan(text)}
        self.assertIn('律师执业证号', types)
        self.assertIn('手机号', types)
        self.assertIn('QQ号', types)
        self.assertIn('身份证号', types)


class TestChecksumValidation(unittest.TestCase):
    """GB 11643 / GB 32100 / Luhn 校验码"""

    def test_id_checksum_valid(self):
        # 手工推导：前17位加权和 120，120 % 11 = 10 → 校验码 '2'
        self.assertTrue(_is_valid_id_checksum('110101198001011232'))

    def test_id_checksum_invalid(self):
        self.assertFalse(_is_valid_id_checksum('110101198001011234'))

    def test_credit_code_checksum(self):
        # GB 32100 公开示例：91350100M000100Y43 通过校验
        self.assertTrue(_is_valid_credit_code('91350100M000100Y43'))
        self.assertFalse(_is_valid_credit_code('91350100M000100Y4X'))

    def test_luhn(self):
        # 标准 Luhn 测试卡号
        self.assertTrue(_luhn_check('4111111111111111'))
        self.assertTrue(_luhn_check('4012888888881881'))
        self.assertFalse(_luhn_check('4111111111111112'))


class TestV22NewRules(unittest.TestCase):
    def setUp(self):
        self.d = Desensitizer()

    def test_passport_not_wechat(self):
        result = self.d.mask('护照：E12345678')
        self.assertIn('[护照号]', result.text)
        self.assertNotIn('[微信号]', result.text)

    def test_driving_license_type(self):
        result = self.d.mask('驾驶证号330106198001011234')
        self.assertIn('[驾驶证号]', result.text)
        for m in result.mapping:
            self.assertNotEqual(m.type, '身份证号')

    def test_org_code(self):
        result = self.d.mask('组织机构代码69920000-2')
        self.assertIn('[组织机构代码]', result.text)

    def test_account_context(self):
        result = self.d.mask('收款账号：6222020200012345678')
        self.assertIn('收款账号：[银行账号]', result.text)

    def test_amount_full_match(self):
        result = self.d.mask('尾款80万元应于三日内支付')
        self.assertIn('尾款[金额]应于三日内支付', result.text)
        for m in result.mapping:
            if m.type == '金额':
                self.assertEqual(m.original, '80万元')

    def test_amount_not_pixel_or_share(self):
        result = self.d.mask('设备60万像素，持股8万股')
        self.assertIn('60万像素', result.text)
        self.assertIn('8万股', result.text)

    def test_fullwidth_case_number(self):
        result = self.d.mask('本院（2025）浙民终123号民事判决书')
        self.assertIn('[案号]', result.text)

    def test_scan_has_confidence(self):
        findings = self.d.scan('身份证号110101198001011232')
        self.assertIn('confidence', findings[0])
        self.assertGreater(findings[0]['confidence'], 0.9)

    def test_wechat_without_colon(self):
        result = self.d.mask('双方确认微信号lawyer_wang888为联络方式')
        self.assertIn('微信号[微信号]', result.text)

    def test_address_prefix_no_leak(self):
        result = self.d.mask('住所地浙江省杭州市拱墅区莫干山路100号')
        self.assertIn('住所地[地址]', result.text)
        self.assertNotIn('浙江省', result.text)
        self.assertNotIn('拱墅区', result.text)

    def test_scan_dedup_overlap(self):
        # 身份证号不应同时被记为银行账号
        findings = self.d.scan('身份证号110101198001011232')
        types = [f['type'] for f in findings]
        self.assertEqual(types.count('身份证号'), 1)
        self.assertNotIn('银行账号', types)


class TestRestore(unittest.TestCase):
    """mask → 映射表 → restore 无损往返"""

    def _roundtrip(self, text):
        d = Desensitizer()
        r = d.mask(text)
        restored = restore_text(r.text, parse_mapping_text(r.to_json()))
        self.assertEqual(restored, text)

    def test_restore_basic(self):
        self._roundtrip('原告：陈建国，男，身份证号110101198001011232，手机13800138000。')

    def test_restore_repeated_amounts(self):
        # 多个 [金额] 按原文顺序配对
        self._roundtrip('尾款80万元、违约金人民币伍佰万元整，另借3.6万利息。')

    def test_restore_birthdate_suffix(self):
        self._roundtrip('原告1985年8月15日出生，住浙江省杭州市西湖区文一西路1号。')

    def test_restore_from_markdown(self):
        d = Desensitizer()
        r = d.mask('原告：陈建国。尾款80万元。')
        restored = restore_text(r.text, parse_mapping_text(r.to_markdown()))
        self.assertEqual(restored, '原告：陈建国。尾款80万元。')

    def test_restore_person_no_delimiter(self):
        # 无分隔符人名不插空格，还原后与原文完全一致
        self._roundtrip('原告陈建国，被告李四。')

    def test_restore_address_with_prefix(self):
        # 带"住所地"前缀的地址：脱敏整体替换、还原完全一致
        self._roundtrip('住所地：浙江省杭州市西湖区文一西路1号。')


class TestNerIntegration(unittest.TestCase):
    """mask_with_ner（regex 后端，无额外依赖）"""

    def test_mask_with_ner_regex_backend(self):
        from ner_interface import LegalNER
        d = Desensitizer()
        result = d.mask_with_ner(
            '原告：陈建国，被告：杭州鼎盛房地产开发有限公司。',
            LegalNER(backend='regex'),
        )
        self.assertIn('[当事人甲（原告）]', result.text)
        self.assertIn('[合同乙方]', result.text)

    def test_regex_ner_backend_extract(self):
        from ner_interface import LegalNER
        ner = LegalNER(backend='regex')
        result = ner.extract('原告金进跃，被告杭州鼎盛房地产开发有限公司')
        types = {e.type.value for e in result.entities}
        self.assertIn('PERSON', types)
        self.assertIn('COMPANY', types)


class TestBareNamesAndUnstructuredAddress(unittest.TestCase):
    """v2.4 规则层增强：裸人名 + 无层级地址 + 全文一致"""

    def setUp(self):
        self.d = Desensitizer()

    def test_bare_names_consistency_with_role_seed(self):
        # 角色词识别的名字向裸出现处传播，全文同一占位符
        result = self.d.mask('原告：陈建国。陈建国再次到庭陈述。原告陈建国称双方系朋友。')
        self.assertEqual(result.text.count('[当事人甲（原告）]'), 3)
        self.assertNotIn('陈建国', result.text)

    def test_bare_names_without_role(self):
        result = self.d.mask('张三欠李四钱不还')
        self.assertNotIn('张三', result.text)
        self.assertNotIn('李四', result.text)
        for m in result.mapping:
            if m.type == '人名':
                self.assertIn(m.original, ('张三', '李四'))

    def test_three_char_and_compound_names(self):
        result = self.d.mask('欧阳雪梅与王小明签订合同，欧阳雪梅称王小明已付款。')
        self.assertNotIn('欧阳雪梅', result.text)
        self.assertNotIn('王小明', result.text)
        # 同一人同一个占位符
        ph = [m.replacement for m in result.mapping if m.original == '欧阳雪梅']
        self.assertEqual(len(set(ph)), 1)

    def test_role_rule_not_cross_line(self):
        # 跨行"原告及其\n委托…""被告不应\n承担…"不得吞词
        result = self.d.mask('原告及其\n委托诉讼代理人赵敏。\n被告不应\n承担逾期交房违约责任。')
        self.assertNotIn('及其', {m.original for m in result.mapping if m.type == '人名'})
        self.assertNotIn('承担', {m.original for m in result.mapping if m.type == '人名'})
        self.assertIn('[委托代理人]', result.text)

    def test_common_words_not_names(self):
        result = self.d.mask('陈述事实经过后，双方对借款金额无异议，诉讼费由被告承担，原告抚养权问题另行处理。')
        names = {m.original for m in result.mapping if m.type == '人名'}
        for w in ('陈述', '金额', '承担', '抚养'):
            self.assertNotIn(w, names)

    def test_unstructured_address(self):
        result = self.d.mask('双方约定在望京西园四区410楼当面核账，莫干山路100号是注册地。')
        self.assertEqual(result.text.count('[地址]'), 2)
        self.assertNotIn('望京西园', result.text)

    def test_disable_bare_names(self):
        d = Desensitizer(bare_names=False)
        result = d.mask('原告：陈建国。张三欠李四钱不还。')
        self.assertIn('[当事人甲（原告）]', result.text)  # 角色名仍脱敏
        self.assertIn('张三', result.text)  # 裸人名关闭

    def test_bare_names_restore_roundtrip(self):
        text = '原告：陈建国。张三欠李四钱不还，双方约定在望京西园四区410楼核账。'
        r = self.d.mask(text)
        restored = restore_text(r.text, parse_mapping_text(r.to_json()))
        self.assertEqual(restored, text)


if __name__ == '__main__':
    unittest.main()
