# -*- coding: utf-8 -*-
"""v2.1 合并版回归测试（纯标准库，python -m unittest test_desensitize）"""

import unittest

from desensitize import Desensitizer, SecureDesensitizer  # 导入成功即验证类定义顺序修复


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


if __name__ == '__main__':
    unittest.main()
