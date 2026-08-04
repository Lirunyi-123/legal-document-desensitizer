# -*- coding: utf-8 -*-
"""
合成语料管线 — 号码生成器（v3.0，内化自 rizzo-pii 的 generate_synthetic_pii.py）
=============================================================================

核心原则（对齐脱敏 skill 的 v2.2 校验码体系，与 desensitize.py 的校验器
完全一致）：
- 用**代码**生成数学上合法的号码：身份证（GB 11643-1999 第18位校验码）、
  统一社会信用代码（GB 32100-2015）、银行卡（Luhn）、手机号、案号、车牌。
- 脱敏 skill 的规则层"无标签身份证要求校验码/出生日期、信用代码裸号 9 开头、
  银行卡宁替勿漏"，因此生成的号码构造上合法 → 评测时规则层必然命中，
  不是"碰运气"。
- LLM 永远不写真实号码：模板只放 {SLOT} 占位符（见 llm_template_bank.py），
  本模块负责注入合法值并自动标注期望（expect_masked / expect_kept）。

输出（`python3 generate_synthetic_pii.py`，默认红队语料）：
  测试/合成语料.jsonl —— 与测试/红队语料库.jsonl 同 schema，可直接喂 evaluate.py
  --bio N：输出 BIO 训练语料（tokens + bio_labels，同 rizzo 格式）
"""

import json
import random
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]   # legal-document-desensitizer/
DEFAULT_REDTEAM = ROOT / '测试' / '合成语料.jsonl'
DEFAULT_BIO = ROOT / '测试' / '合成语料_bio.jsonl'

# --------------------------------------------------------------------------- #
# 校验表（与 desensitize.py 逐项一致，保证"生成=可验证"）
# --------------------------------------------------------------------------- #
_ID_WEIGHTS = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
_ID_CHECK_CODES = '10X98765432'
_CREDIT_ALPHABET = '0123456789ABCDEFGHJKLMNPQRTUWXY'
_CREDIT_WEIGHTS = [1, 3, 9, 27, 19, 26, 16, 17, 20, 29, 25, 13, 8, 24, 10, 30, 28]

# 真实存在的县级行政区划码（前6位），保证身份证区域码合法
ID_AREAS = [
    '110101', '110105', '310101', '330106', '330110', '330122', '342622',
    '340102', '350202', '440106', '440305', '441900', '320102', '320505',
    '370102', '370202', '510107', '510104', '500103', '610113', '210102',
    '210202', '220102', '230102', '120101', '130102', '140102', '150102',
    '410102', '420102', '430102', '450103', '460106', '520102', '530102',
    '540102', '610102', '620102', '630102', '640102', '650102',
]

# 省份简称（车牌第1位）
PROV_SHORT = ['京', '津', '沪', '渝', '冀', '豫', '云', '辽', '黑', '湘', '皖',
              '鲁', '新', '苏', '浙', '赣', '鄂', '桂', '甘', '晋', '蒙', '陕',
              '吉', '闽', '贵', '粤', '青', '藏', '川', '宁', '琼']
_PLATE_LETTERS = 'ABCDEFGHJKLMNPRSTUVWXYZ'     # 车牌字母（无 I O Q）

# --------------------------------------------------------------------------- #
# 中文词库（姓 + 名 + 公司 + 地址 + 法院）
# --------------------------------------------------------------------------- #
SURNAMES = (
    '赵钱孙李周吴郑王冯陈褚卫蒋沈韩杨朱秦尤许何吕施张孔曹严华金魏陶姜'
    '戚谢邹喻柏水窦章云苏潘葛奚范彭郎鲁韦昌马苗凤花方俞任袁柳酆鲍史唐'
    '费廉岑薛雷贺倪汤滕殷罗毕郝邬安常乐于时傅皮卞齐康伍余元卜顾孟平黄'
    '和穆萧尹姚邵湛汪祁毛禹狄米贝明臧计伏成戴谈宋茅庞熊纪舒屈项祝董梁'
    '杜阮蓝闵席季麻强贾路娄危江童颜郭梅盛林刁钟徐邱骆高夏蔡田樊胡凌霍'
    '虞万支柯昝管卢莫经房裘缪干解应宗丁宣贲邓郁单杭洪包诸左石崔吉钮龚'
    '程嵇邢滑裴陆荣翁荀羊於惠甄曲家封芮羿储靳汲邴糜松井段富巫乌焦巴弓'
    '牧隗山谷车侯宓蓬全郗班仰秋仲伊宫宁仇栾暴甘钭厉戎祖武符刘景詹束龙'
    '叶幸司韶郜黎蓟薄印宿白怀蒲邰从鄂索咸籍赖卓蔺屠蒙池乔阴郁胥能苍双'
    '闻莘党翟谭贡劳逄姬申扶堵冉宰郦雍却璩桑桂濮牛寿通边扈燕冀浦尚农温'
    '庄晏柴瞿阎充慕连茹习宦艾鱼容向古易慎戈廖庾终暨居衡步都耿满弘匡国'
    '文寇广禄阙东欧殳沃利蔚越夔隆师巩厍聂晁勾敖融冷訾辛阚那简饶空曾毋'
    '沙乜养鞠须丰巢关蒯相查后荆红游竺权逯盖益桓公'
)
GIVEN_1 = '伟芳娜敏静丽强磊军洋勇艳杰娟涛明超秀兰霞平刚桂英华玉萍红娥玲建华'
GIVEN_2 = '建国志强文斌海燕永辉国庆晓梅雪琴桂香玉兰秀英建华思远浩然子墨雨欣'
CITY_NAMES = ['杭州', '北京', '上海', '广州', '深圳', '苏州', '南京', '武汉', '成都',
              '重庆', '天津', '西安', '郑州', '长沙', '合肥', '南昌', '福州', '济南',
              '青岛', '沈阳', '长春', '哈尔滨', '昆明', '贵阳', '南宁', '海口']
PROVINCES = ['浙江省', '北京市', '上海市', '广东省', '江苏省', '四川省', '湖北省',
             '湖南省', '安徽省', '山东省', '辽宁省', '福建省']
DISTRICTS = ['余杭区', '西湖区', '朝阳区', '浦东新区', '天河区', '南山区', '鼓楼区',
             '姑苏区', '武侯区', '江汉区', '芙蓉区', '蜀山区', '历下区', '和平区',
             '玄武区', '滨江区', '上城区', '拱墅区']
STREETS = ['文一西路', '莫干山路', '延安路', '中山北路', '人民大道', '解放路',
           '建国路', '复兴路', '望江路', '钱塘江路', '西溪路', '古墩路', '天目山路',
           '体育场路', '凤起路', '庆春路', '环城西路', '石祥路']
COURTS = ['人民法院', '中级人民法院', '高级人民法院']
COMPANY_TAILS = ['有限公司', '股份有限公司', '集团有限公司', '房地产开发有限公司',
                 '建设工程有限公司', '科技股份有限公司', '商贸有限公司', '物流有限公司']
COMPANY_HEADS = ['鼎盛', '华临', '方汇', '宝冶', '合生东宇', '金进', '万达', '恒大',
                 '绿地', '万科', '中海', '保利', '融创', '碧桂园', '华夏幸福', '中交',
                 '中铁', '中建', '招商', '华润', '绿城', '滨江', '德信', '旭辉']
ADDR_UNITS = ['1号', '5号', '100号', '88号', '36号', '12幢', '3幢2单元502室', '8幢',
              '2幢1单元301室', '6号', '9号', '15幢', '7号', '45号']


# 姓氏表：优先采用规则层（desensitize.py）的姓氏表——合成人名必须落在规则层
# 能识别的姓氏范围内（裸人名/角色词人名都按姓氏表判定），评测基线才成立；
# 内置标准百家姓仅作为规则层不可用时的回退。
def _effective_surnames():
    try:
        import sys as _sys
        _sys.path.insert(0, str(ROOT))
        import desensitize  # noqa: F401
        return ''.join(sorted(desensitize._SURNAMES)), list(desensitize._COMPOUND_SURNAMES)
    except Exception:
        return SURNAMES, []


SURNAME_POOL, COMPOUND_SURNAME_POOL = _effective_surnames()

# --------------------------------------------------------------------------- #
# 号码生成器（全部构造上合法）
# --------------------------------------------------------------------------- #
def gen_id_card(rng):
    """GB 11643-1999 合法身份证：区域码 + 出生日期 + 顺序码 + 校验位。"""
    area = rng.choice(ID_AREAS)
    y = rng.randint(1950, 2005)
    m = rng.randint(1, 12)
    d = rng.randint(1, 28)
    body = f'{area}{y:04d}{m:02d}{d:02d}{rng.randint(0, 999):03d}'
    total = sum(int(body[i]) * _ID_WEIGHTS[i] for i in range(17))
    return body + _ID_CHECK_CODES[total % 11]


def gen_credit_code(rng):
    """GB 32100-2015 合法统一社会信用代码：9 + 机构类别 + 6位区划 + 9位主体 + 校验。"""
    kind = rng.choice('123456789')
    area6 = rng.choice(ID_AREAS)
    body = '9' + kind + area6 + ''.join(
        rng.choice(_CREDIT_ALPHABET) for _ in range(9))
    total = sum(_CREDIT_ALPHABET.index(ch) * _CREDIT_WEIGHTS[i]
                for i, ch in enumerate(body))
    return body + _CREDIT_ALPHABET[(31 - total % 31) % 31]


def gen_bank_card(rng):
    """Luhn 合法银行卡号（16 或 19 位）。"""
    n = rng.choice((16, 19))
    digits = [rng.randint(0, 9) for _ in range(n - 1)]
    # Luhn 校验位：从右往左第 1、3、5…（1-indexed）位乘 2
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 0:
            x = d * 2
            total += x - 9 if x > 9 else x
        else:
            total += d
    check = (10 - total % 10) % 10
    return ''.join(map(str, digits)) + str(check)


def gen_mobile(rng):
    return f'1{rng.choice("3456789")}{rng.randint(0, 99999999):08d}'


def gen_case_number(rng):
    year = rng.randint(2018, 2025)
    court = rng.choice(['京0108', '浙0110', '沪0115', '粤0106', '皖0401', '苏0105'])
    kind = rng.choice(['民初', '民终', '刑初', '行初', '执'])
    num = rng.randint(100, 99999)
    return f'({year}){court}{kind}{num}号'


def gen_plate(rng):
    letters = ''.join(rng.choice(_PLATE_LETTERS) for _ in range(rng.choice((5, 6))))
    return rng.choice(PROV_SHORT) + rng.choice(_PLATE_LETTERS) + letters


def gen_person_name(rng):
    """人名：规则层姓氏表 + 常见名，保证可被规则层识别。

    默认不生成单字名（规则层裸人名启发式要求 2~4 字；单字名是刻意盲区）。
    复姓配 1 字名（3 字，真实分布主流），单姓配 1~2 字名（2~3 字）：
    4 字名（复姓+2字名）超出规则层姓名形态判定，不进入基准语料。
    """
    if COMPOUND_SURNAME_POOL and rng.random() < 0.1:
        s = rng.choice(COMPOUND_SURNAME_POOL)
        return s + rng.choice(GIVEN_1)                    # 复姓 + 1 字名
    s = rng.choice(SURNAME_POOL)
    if rng.random() < 0.45:
        given = rng.choice(GIVEN_1)                       # 2 字名（单字名）
    else:
        given = rng.choice(GIVEN_2) + rng.choice(GIVEN_1) # 3 字名（双字名）
    return s + given


def gen_company(rng):
    head = rng.choice(COMPANY_HEADS)
    tail = rng.choice(COMPANY_TAILS)
    return f'{rng.choice(CITY_NAMES)}{head}{tail}'


def gen_address(rng):
    prov = rng.choice(PROVINCES)
    city = rng.choice(CITY_NAMES)
    dist = rng.choice(DISTRICTS)
    street = rng.choice(STREETS)
    unit = rng.choice(ADDR_UNITS)
    return f'{prov}{city}市{dist}{street}{unit}'


def gen_amount(rng):
    n = rng.choice((5000, 30000, 125000, 480000, 1250000, 3500000, 9600000, 12345678))
    return f'人民币{n:,}元'.replace(',', '')


def gen_date(rng):
    y = rng.randint(2015, 2025)
    m = rng.randint(1, 12)
    d = rng.randint(1, 28)
    return f'{y}年{m}月{d}日'


def gen_court(rng):
    return f'{rng.choice(CITY_NAMES)}市{rng.choice(COURTS)}'


def gen_email(rng):
    name = gen_person_name(rng)
    return f'{name}@{rng.choice(("163.com", "qq.com", "sina.com", "example.cn"))}'


# --------------------------------------------------------------------------- #
# 槽位注入：{SLOT} → (文本, label|None)
# label=None 表示保留项（不脱敏，如法院、普通日期）
# --------------------------------------------------------------------------- #
# 语义型槽位：同一模板内复用同一值（保证"同一人统一占位符"的评测）
# 号码型槽位：每次出现重新生成
_SEMANTIC_SLOTS = {'当事人甲', '当事人乙', '当事人丙', '当事人丁', '公司甲', '公司乙'}
# label 与 desensitize.py 的规则类型对齐（evaluate.py 按 type 分组）
_SLOT_LABELS = {
    '当事人甲': '人名', '当事人乙': '人名', '当事人丙': '人名', '当事人丁': '人名',
    '身份证': '身份证号', '手机号': '手机号', '银行账号': '银行账号',
    '信用代码': '统一社会信用代码', '公司甲': '公司名', '公司乙': '公司名',
    '地址': '地址', '案号': '案号', '金额': '金额', '车牌': '车牌号',
    '邮箱': '邮箱', '出生日期': '出生日期',
}

_SLOT_GEN = {
    '身份证': gen_id_card, '手机号': gen_mobile, '银行账号': gen_bank_card,
    '信用代码': gen_credit_code, '地址': gen_address, '案号': gen_case_number,
    '金额': gen_amount, '车牌': gen_plate, '邮箱': gen_email,
    '出生日期': gen_date,
    # 保留项（label=None，不脱敏）：普通日期与法院名
    '日期': gen_date, '法院': gen_court,
}

# 保留项槽位：注入值但不进 expect_masked，进 expect_kept
KEEP_SLOTS = {'日期', '法院'}


def _person_slot(prefix):
    """当事人/公司槽位：语义型生成器。"""
    if prefix.startswith('公司'):
        return gen_company
    return gen_person_name


def _slot_generator(slot):
    if slot in _SLOT_GEN:
        return _SLOT_GEN[slot]
    if slot in _SEMANTIC_SLOTS:
        return _person_slot(slot)
    return None


def fill_template(template, rng):
    """把模板里的 {SLOT} 全部注入合法值，返回 (文本, entities, kept)。

    entities = [(value, label, start, end)]（PII，label 非 None）；
    kept = [(value, 类型)]（保留项，如普通日期/法院名，应保持原样）。
    同一语义槽位（{当事人甲}）在模板中出现多次 → 复用同一值。
    """
    text, entities, kept = '', [], []
    semantic_vals = {}
    for part in re.split(r'(\{[A-Za-z\u4e00-\u9fa5]+\})', template):
        if not part:
            continue
        m = re.fullmatch(r'\{([A-Za-z\u4e00-\u9fa5]+)\}', part)
        if not m:
            text += part
            continue
        slot = m.group(1)
        gen = _slot_generator(slot)
        if gen is None:
            raise ValueError(f'未知槽位 {slot}（槽位白名单见 llm_template_bank.py）')
        if slot in _SEMANTIC_SLOTS and slot in semantic_vals:
            value = semantic_vals[slot]
        else:
            value = gen(rng)
            semantic_vals[slot] = value
        start = len(text)
        text += value
        label = _SLOT_LABELS.get(slot)
        if label:
            entities.append((value, label, start, len(text)))
        elif slot in KEEP_SLOTS:
            kept.append((value, '日期' if slot == '日期' else '法院名称'))
    return text, entities, kept


def render_redteam_case(tid, template, rng, idx):
    """渲染成红队语料用例（evaluate.py 同 schema，自动填 expect_masked/kept）。"""
    text, entities, kept = fill_template(template, rng)
    masked = [{'type': label, 'value': value}
              for value, label, _, _ in entities]
    kept_items = [{'type': typ, 'value': value} for value, typ in kept]
    return {
        'id': f'syn_{idx:04d}',
        'note': '合成语料（代码注入合法校验值，自动标注期望）',
        'text': text,
        'expect_masked': masked,
        'expect_kept': kept_items,
        'expect_absent': [],
        'llm_only': [],
        'source': 'synthetic',
        'template_id': tid,
    }


def render_bio_case(tid, template, rng):
    """渲染成 BIO 训练语料（tokens + bio_labels，同 rizzo 输出格式）。"""
    text, entities, _ = fill_template(template, rng)
    token_re = re.compile(r'[\w\u4e00-\u9fa5]+|[^\w\u4e00-\u9fa5\s]', re.UNICODE)
    tokens, spans = [], []
    for m in token_re.finditer(text):
        tokens.append(m.group())
        spans.append((m.start(), m.end()))
    labels = []
    for ts, te in spans:
        tag = 'O'
        for value, label, es, ee in entities:
            if es <= ts and te <= ee:
                tag = ('B-' if ts == es else 'I-') + label
                break
        labels.append(tag)
    return {
        'source_text': text, 'language': 'zh', 'template_id': tid,
        'entities': [{'value': v, 'label': l, 'start': s, 'end': e}
                     for v, l, s, e in entities],
        'tokens': tokens, 'bio_labels': labels,
    }


def load_external_templates(path=None):
    """加载 LLM 生成的模板（llm_template_bank.py 输出）。"""
    if path is None:
        path = ROOT / 'synthetic' / 'legal_templates.json'
    if not Path(path).exists():
        return []
    out = []
    for t in json.load(open(path, encoding='utf-8')):
        slots = set(re.findall(r'\{([A-Za-z\u4e00-\u9fa5]+)\}', t.get('text', '')))
        if slots and not (slots - set(_SLOT_LABELS) - _SEMANTIC_SLOTS):
            out.append(t['text'])
    return out


def main():
    import argparse
    ap = argparse.ArgumentParser(description='合成语料生成（号码合法、期望自动标注）')
    ap.add_argument('-n', type=int, default=60, help='生成条数（默认 60）')
    ap.add_argument('--seed', type=int, default=42, help='随机种子（默认 42，可复现）')
    ap.add_argument('--red-team', default=str(DEFAULT_REDTEAM),
                    help='红队语料输出路径（evaluate.py 直接可用）')
    ap.add_argument('--bio', default='', help='同时输出 BIO 训练语料到该路径（留空不输出）')
    ap.add_argument('--templates', default='',
                    help='额外模板 JSON（llm_template_bank.py 输出），默认读 synthetic/legal_templates.json')
    args = ap.parse_args()

    rng = random.Random(args.seed)
    from pathlib import Path as _P
    templates = TEMPLATES + load_external_templates(args.templates or None)
    if not templates:
        sys.exit('❌ 没有可用模板（内置模板缺失或外部模板槽位不合法）')

    Path(args.red_team).parent.mkdir(parents=True, exist_ok=True)
    n_masked = {}
    with open(args.red_team, 'w', encoding='utf-8') as f:
        for i in range(args.n):
            tid = rng.randrange(len(templates))
            case = render_redteam_case(tid, templates[tid], rng, i)
            for it in case['expect_masked']:
                n_masked[it['type']] = n_masked.get(it['type'], 0) + 1
            f.write(json.dumps(case, ensure_ascii=False) + '\n')

    print(f'✅ 红队语料 {args.n} 条 -> {args.red_team}')
    print('   类型分布（expect_masked）：')
    for t, c in sorted(n_masked.items(), key=lambda kv: -kv[1]):
        print(f'     {t:<14}{c}')
    print(f'   内置模板 {len(TEMPLATES)} 个'
          f' + 外部模板 {len(templates) - len(TEMPLATES)} 个')

    if args.bio:
        Path(args.bio).parent.mkdir(parents=True, exist_ok=True)
        with open(args.bio, 'w', encoding='utf-8') as f:
            for i in range(args.n):
                tid = rng.randrange(len(templates))
                f.write(json.dumps(render_bio_case(tid, templates[tid], rng),
                                   ensure_ascii=False) + '\n')
        print(f'✅ BIO 训练语料 {args.n} 条 -> {args.bio}')


# --------------------------------------------------------------------------- #
# 内置中文法律文书模板（占位符 = 白名单槽位；法院/普通日期为保留项）
# --------------------------------------------------------------------------- #
TEMPLATES = [
    # 民事判决书
    '原告{当事人甲}，男，身份证号{身份证}，住{地址}。\n'
    '被告{公司甲}，住所地{地址}，统一社会信用代码{信用代码}，法定代表人{当事人乙}。\n'
    '原告{当事人甲}向本院提出诉讼请求：判令被告{公司甲}支付货款{金额}元。\n'
    '本院于{日期}立案受理，案号{案号}，适用简易程序公开开庭进行了审理。\n'
    '本院认为，原告{当事人甲}与被告{公司甲}之间的买卖合同关系合法有效。\n'
    '判决如下：一、被告{公司甲}于本判决生效之日起十日内支付原告{当事人甲}货款{金额}元；\n'
    '二、案件受理费由被告{公司甲}负担。\n'
    '审判长：{当事人丙}，审判员：{当事人丁}。',

    # 民间借贷纠纷判决书
    '原告{当事人甲}与被告{当事人乙}民间借贷纠纷一案，本院于{日期}立案后，依法适用普通程序审理。\n'
    '原告{当事人甲}诉称：被告{当事人乙}于{日期}向其借款{金额}元，约定于{日期}归还。\n'
    '经审理查明：原告{当事人甲}通过银行账号{银行账号}向被告{当事人乙}转账{金额}元。\n'
    '本院认为，借款合同系双方真实意思表示，合法有效。被告{当事人乙}未按期还款，构成违约。\n'
    '判决如下：被告{当事人乙}应于判决生效后十日内偿还原告{当事人甲}借款本金{金额}元及利息。',

    # 行政处罚决定书
    '当事人：{当事人甲}，身份证号{身份证}，住{地址}。\n'
    '经查，当事人{当事人甲}于{日期}在{地址}从事无照经营，违法所得{金额}元。\n'
    '本局于{日期}向当事人送达《行政处罚告知书》，案号{案号}，当事人未提出陈述申辩。\n'
    '依据相关法律法规，本局决定：责令当事人{当事人甲}停止违法行为，并处罚款{金额}元。\n'
    '当事人如不服本决定，可于收到本决定书之日起六十日内申请行政复议。',

    # 建设工程施工合同
    '发包人（甲方）：{公司甲}，统一社会信用代码{信用代码}，住所地{地址}。\n'
    '承包人（乙方）：{公司乙}，统一社会信用代码{信用代码}，住所地{地址}。\n'
    '依照相关法律规定，甲乙双方就{地址}项目施工事宜，经协商一致签订本合同。\n'
    '合同价款为人民币{金额}元，采用固定总价。甲方应于{日期}前支付预付款{金额}元至乙方账户{银行账号}。\n'
    '乙方项目负责人：{当事人甲}，联系电话{手机号}。',

    # 调解书
    '本院于{日期}立案受理了原告{当事人甲}诉被告{当事人乙}合同纠纷一案，案号{案号}。\n'
    '经本院主持调解，双方当事人自愿达成如下协议：\n'
    '一、被告{当事人乙}于{日期}前向原告{当事人甲}支付{金额}元；\n'
    '二、双方就本案再无其他争议。\n'
    '上述协议符合法律规定，本院予以确认。',

    # 微信聊天记录（沟通类；人名后接动词"称"提供强上下文）
    '{当事人甲}称：{公司甲}那笔{金额}元的货款什么时候到账？\n'
    '{当事人乙}称：财务说本周五之前转，打到尾号{银行账号}的账户。\n'
    '{当事人甲}称：发票寄到{地址}。\n'
    '{当事人乙}称：收到，{日期}前开好。',

    # 财产保全申请书（含车牌/出生日期）
    '申请人：{当事人甲}，男，{出生日期}出生，住{地址}，联系电话{手机号}。\n'
    '被申请人：{公司甲}，住所地{地址}。\n'
    '请求事项：请求贵院依法查封被申请人{公司甲}名下车辆（车牌号{车牌}）及银行存款。\n'
    '事实与理由：申请人与被申请人因合同纠纷诉至贵院，案号{案号}。\n'
    '为确保判决执行，特申请财产保全。',

    # 律师函
    '致：{公司甲}\n'
    '本律师接受{当事人甲}委托（身份证号{身份证}），就贵公司拖欠货款事宜致函如下：\n'
    '贵公司于{日期}与我方委托人签订供货合同，约定货款{金额}元。\n'
    '截至本函发出之日，贵公司仍欠付{金额}元，我方委托人多次催讨未果。\n'
    '限贵公司于收到本函之日起七日内付清欠款，逾期本律师将依法提起诉讼。',

    # 劳动合同/劳动仲裁
    '申请人：{当事人甲}，身份证号{身份证}，住{地址}，联系电话{手机号}。\n'
    '被申请人：{公司甲}，住所地{地址}，统一社会信用代码{信用代码}。\n'
    '仲裁请求：一、裁决被申请人支付申请人工资{金额}元；二、裁决被申请人补缴社会保险。\n'
    '事实与理由：申请人于{日期}入职被申请人处，双方未签订书面劳动合同。\n'
    '被申请人拖欠申请人{日期}至{日期}期间工资共计{金额}元。',

    # 刑事判决书（简）
    '公诉机关：{法院}。\n'
    '被告人{当事人甲}，男，{出生日期}出生，身份证号{身份证}，住{地址}。\n'
    '被告人{当事人甲}以非法占有为目的，诈骗他人财物{金额}元，数额巨大，其行为已构成诈骗罪。\n'
    '判决如下：被告人{当事人甲}犯诈骗罪，判处有期徒刑三年，并处罚金{金额}元。\n'
    '如不服本判决，可在接到判决书的第二日起十日内提起上诉。',

    # 侵权责任纠纷
    '原告{当事人甲}诉被告{当事人乙}机动车交通事故责任纠纷一案，本院于{日期}立案，案号{案号}。\n'
    '被告{当事人乙}驾驶车牌号{车牌}的车辆与原告{当事人甲}发生碰撞，造成原告受伤。\n'
    '经本院主持调解，被告{当事人乙}赔偿原告{当事人甲}医疗费、误工费等共计{金额}元。\n'
    '上述款项应于{日期}前付至原告账户{银行账号}。',
]


if __name__ == '__main__':
    main()
