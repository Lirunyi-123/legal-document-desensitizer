# -*- coding: utf-8 -*-
"""
PDF 真·涂黑脱敏（v3.0，内化自 rizzo-pii 的 pdf_export.py，适配中文语义边界）
======================================================================

`redact_pdf(pdf_bytes, pairs)` 对原 PDF 做**真·涂黑**（不是画个矩形盖住）：

- 字符级精确匹配：页面按 rawdict 逐字符建立索引（每字符带 bbox），
  值用正则锚定**中文/字母/数字词边界**——"张三"不会涂掉"张三丰"里的子串，
  "DE" 不会涂进 "CORDELLA"。
- 容忍排版/OCR 噪声：值内相邻字符间容忍空白与换行（"汪 瑜"、"审 判 员"、
  PDF 提取文本的行尾换行都能命中），多 token 间要求至少一个空白。
- 真删除：`page.apply_redactions()` 从 content stream 移除文字，而非覆盖；
  **版式保留**，占位符以白色文字写在涂黑块上。
- 连带清理所有藏 PII 的位置：元数据/XMP、批注（评论/便签/FreeText）、
  表单字段值（AcroForm widget）、书签标题、内嵌附件（整体移除）。

安全语义（宁可不交付，不交付"假脱敏"）：
1. **residual 校验**：输出后把所有占位符对应的原文在"输出 PDF 的全部可读文本"
   里再搜一遍（用与涂黑相同的容忍正则），若仍可读 → 抛错拒绝交付。
2. **零命中拒绝**：若整份 PDF 文本层一处都找不到待脱敏值（典型：扫描件、
   文字在图片里）→ 抛错，绝不产出"看起来脱敏了其实没有"的 PDF。
3. **过短值跳过并警告**：少于 2 个汉字/字母数字的值（如 "1"、"C"）全文搜索
   会涂掉大片无辜文本，跳过并进 `report["skipped"]`，由调用方提示用户。

用法（CLI 集成在 desensitize.py mask 命令，`--pdf-redact` 或 -o 指定 .pdf）：
    python3 desensitize.py mask -f 判决书.pdf --pdf-redact -o 判决书_redacted.pdf
"""

import re

import fitz  # PyMuPDF

_CJK = '\u4e00-\u9fa5'
# 词边界字符：中文、字母、数字（全角括号/标点不算，值内部可含"（原告）"）
_BOUNDARY_RE = re.compile(r'[\u4e00-\u9fa5A-Za-z0-9]')

# 涂黑块与占位符文字的配色：品牌紫 + 白字（一眼可辨，供律师复核）
REDACT_FILL = (0.486, 0.227, 0.620)
REDACT_TEXT = (1.0, 1.0, 1.0)


class PdfError(ValueError):
    """用法/安全语义错误（PDF 无效、受保护、零命中、residual 残留）。"""


# --------------------------------------------------------------------------- #
# 匹配模式
# --------------------------------------------------------------------------- #
def _norm(s):
    """空白压缩 + casefold：匹配前的统一归一化。"""
    return re.sub(r'\s+', ' ', (s or '').strip()).casefold()


def _too_noisy(value):
    """值过短/无辨识度：汉字+字母数字合计 < 2 → 全文搜索会误涂大片文本。"""
    core = re.sub(r'\s', '', _norm(value))
    return len(_BOUNDARY_RE.findall(core)) < 2


def _value_pattern(value):
    """字符级精确匹配 + 容忍行内空白/换行。

    边界策略（中文场景与意大利语不同——人名紧贴上下文，如"原告陈建国"，
    没有空格分词）：
    - 数字/字母标识符（身份证号、银行卡、案号…）：前后加数字/字母边界，
      防止 "1234567" 误配 "12345678" 里的子串；
    - 含中文的短语（人名/公司名/地址…）：**不加中文词边界**（会因紧贴
      "原告"、"被告" 而全军覆没），改由调用方"值长优先排序 + 已涂矩形
      跳过（_covered）"防止短值先涂掉长值（如 "张三" 不会破坏
      "张三丰"——长值先涂，短值的矩形已被覆盖而跳过）。
    - token 内部逐字符 `\\s*`（OCR 空格 "汪 瑜"、PDF 行尾换行都命中），
      多 token 间 `\\s+`。
    """
    toks = [t for t in _norm(value).split(' ') if t]
    if not toks:
        return None
    parts = [r'\s*'.join(re.escape(c) for c in tok) for tok in toks]
    body = r'\s+'.join(parts)
    if re.fullmatch(r'[0-9A-Za-z][0-9A-Za-z\s.,\-:/]*', _norm(value)):
        return re.compile(r'(?<![0-9A-Za-z])' + body + r'(?![0-9A-Za-z])',
                          re.IGNORECASE)
    return re.compile(body, re.IGNORECASE)


# --------------------------------------------------------------------------- #
# 页面字符索引 + 匹配矩形
# --------------------------------------------------------------------------- #
def _page_char_index(page):
    """(文本, [每字符 bbox])：rawdict 逐字符，行尾 newline 记 None。"""
    raw = page.get_text('rawdict')
    chars, boxes = [], []
    for block in raw.get('blocks', []):
        if block.get('type') != 0:          # 只取文本块
            continue
        for line in block.get('lines', []):
            for span in line.get('spans', []):
                for ch in span.get('chars', []):
                    c = ch.get('c') or ''
                    for cc in c:            # ligature → 多字符同 bbox
                        chars.append(cc)
                        boxes.append(fitz.Rect(ch['bbox']))
            chars.append('\n')
            boxes.append(None)
    return ''.join(chars), boxes


def _match_rects(boxes, m):
    """命中字符的 bbox，按行（垂直重叠）合并为矩形组。"""
    rects, cur = [], None
    for i in range(m.start(), m.end()):
        b = boxes[i]
        if b is None or b.is_empty:
            continue
        if cur is None:
            cur = fitz.Rect(b)
        elif b.y0 < cur.y1 and b.y1 > cur.y0:      # 同一行
            cur |= b
        else:
            rects.append(cur)
            cur = fitz.Rect(b)
    if cur is not None and not cur.is_empty:
        rects.append(cur)
    return rects


def _rect_area(r):
    """矩形面积（兼容 PyMuPDF 1.26 rebased 实现移除了 get_area()）。"""
    try:
        return r.get_area()
    except AttributeError:
        return r.width * r.height


def _covered(rect, taken, thr=0.85):
    """rect 是否几乎全被之前涂黑覆盖（避免长值涂完短值重复涂）。"""
    area = _rect_area(rect)
    if area <= 0:
        return True
    for t in taken:
        inter = fitz.Rect(rect)
        inter.intersect(t)
        if not inter.is_empty and _rect_area(inter) / area >= thr:
            return True
    return False


def _fit_fontsize(text, rect, max_fs=10.0, min_fs=4.0):
    """占位符文字在矩形内的字号（0 = 放不下，只涂黑不写字）。

    中文占位符用全角估算（中文字符宽 ≈ 字号）；ASCII 用字体度量。
    """
    if not text:
        return 0
    cjk = len(re.findall(r'[\u4e00-\u9fa5]', text))
    ascii_n = len(text) - cjk
    try:
        w_ascii10 = fitz.get_text_length('M' * max(ascii_n, 1),
                                         fontname='helv', fontsize=10.0)
    except Exception:
        w_ascii10 = 0.0
    w10 = cjk * 10.0 + w_ascii10
    if w10 <= 0:
        return 0
    fs = min(max_fs, rect.height * 0.82, 10.0 * max(rect.width - 2.0, 0.0) / w10)
    return round(fs, 1) if fs >= min_fs else 0


def _add_redact_annot(page, rect, text, fontsize, fill, text_color):
    """add_redact_annot：优先关掉对角线 X（不遮挡占位符）。

    占位符含中文（[当事人甲（原告）]），不能用 base14 的 helv（Latin-1，
    中文会变成 ?）：用内置 CJK 字体 china-s。
    """
    kw = dict(text=text, fontname='china-s', fontsize=fontsize,
              align=fitz.TEXT_ALIGN_CENTER, fill=fill, text_color=text_color)
    try:
        return page.add_redact_annot(rect, cross_out=False, **kw)
    except TypeError:
        return page.add_redact_annot(rect, **kw)


# --------------------------------------------------------------------------- #
# 清理 apply_redactions() 管不到的角落
# --------------------------------------------------------------------------- #
def _sub_all(patterns, s):
    n = 0
    for pat, ph in patterns:
        s, k = pat.subn(ph, s)
        n += k
    return s, n


def _scrub_metadata(doc):
    """清空经典元数据 + XMP（作者/标题等常藏 PII）。"""
    try:
        doc.set_metadata({
            'title': '', 'author': '', 'subject': '', 'keywords': '',
            'creationDate': '', 'modDate': '', 'trapped': '',
            'creator': 'legal-document-desensitizer',
            'producer': 'legal-document-desensitizer',
        })
    except Exception:
        pass
    f = getattr(doc, 'del_xml_metadata', None) or getattr(doc, 'delXmlMetadata', None)
    if f:
        try:
            f()
        except Exception:
            pass


def _scrub_annots(page, patterns):
    """批注内容/标题（评论、便签、FreeText）：get_text() 不可见，必清。"""
    done = 0
    try:
        annots = list(page.annots())
    except Exception:
        return 0
    for a in annots:
        try:
            if a.type[0] == fitz.PDF_ANNOT_REDACT:      # 我们自己的涂黑，跳过
                continue
            info = a.info
            new = dict(info)
            hit = 0
            for k in ('content', 'subject', 'title'):
                if info.get(k):
                    new[k], k_hit = _sub_all(patterns, info[k])
                    hit += k_hit
            if hit:
                a.set_info(new)
                a.update()
                done += hit
        except Exception:
            continue
    return done


def _scrub_widgets(page, patterns):
    """表单字段值（AcroForm）：脱敏后仍可读，必须替换。"""
    done = 0
    try:
        widgets = list(page.widgets())
    except Exception:
        return 0
    for w in widgets:
        try:
            val = w.field_value
            if not isinstance(val, str) or not val:
                continue
            new, hit = _sub_all(patterns, val)
            if hit:
                w.field_value = new
                w.update()
                done += hit
        except Exception:
            continue
    return done


def _scrub_toc(doc, patterns):
    """书签标题（常复刻含人名的章节标题）。"""
    try:
        toc = doc.get_toc(simple=True)
    except Exception:
        return 0
    if not toc:
        return 0
    done, new_toc = 0, []
    for entry in toc:
        lvl, title, pg = entry[0], entry[1], entry[2]
        title, hit = _sub_all(patterns, title or '')
        done += hit
        new_toc.append([lvl, title, pg])
    if done:
        try:
            doc.set_toc(new_toc)
        except Exception:
            return 0
    return done


def _strip_embedded(doc):
    """内嵌附件：格式不可枚举，整体移除。"""
    removed = 0
    try:
        names = list(doc.embfile_names())
    except Exception:
        return 0
    for name in names:
        try:
            doc.embfile_del(name)
            removed += 1
        except Exception:
            continue
    return removed


def _readable_text(doc):
    """输出 PDF 的全部可读文本：页面 + 批注 + 表单 + 书签（residual 校验基准）。"""
    parts = []
    for page in doc:
        parts.append(page.get_text())
        try:
            for a in page.annots():
                if a.type[0] == fitz.PDF_ANNOT_REDACT:
                    continue
                info = a.info
                parts.extend(str(info.get(k) or '') for k in ('content', 'subject', 'title'))
        except Exception:
            pass
        try:
            for w in page.widgets():
                if isinstance(w.field_value, str):
                    parts.append(w.field_value)
        except Exception:
            pass
    try:
        parts.extend(str(e[1] or '') for e in doc.get_toc(simple=True))
    except Exception:
        pass
    return '\n'.join(parts)


def _verify_residuals(pdf_bytes, items):
    """占位符对应的原文在输出里仍可读 → 涂黑失败（用同一容忍正则查）。"""
    with fitz.open(stream=pdf_bytes, filetype='pdf') as doc:
        text = _readable_text(doc)
    residual = []
    for ph, val in items:
        pat = _value_pattern(val)
        if pat and pat.search(text):
            residual.append(ph)
    return residual


# --------------------------------------------------------------------------- #
# 公开 API
# --------------------------------------------------------------------------- #
def redact_pdf(pdf_bytes, pairs):
    """原 PDF → 真·涂黑脱敏后的 PDF。

    pairs: [(占位符, 原始值), ...]（同一占位符可对应多个不同原始值，
    每个 pair 独立匹配，与 desensitize.py 的"每处一行"映射表语义一致）。
    返回 (bytes, report)；report 字段：
      occurrences    页面文本中涂掉的次数
      by_placeholder {占位符: 次数}
      not_found      无页面命中的占位符
      skipped        过短/无辨识度被跳过的值（仍留原样，必须提示用户）
      residual       输出后仍可读的值（非空即抛错前必然为空）
      annots/widgets/toc/embedded  各角落清理计数
    """
    if not isinstance(pairs, list) or not pairs:
        raise PdfError('映射表为空：请先运行 mask 再涂黑 PDF。')
    items = [(ph, v) for ph, v in pairs
             if isinstance(ph, str) and isinstance(v, str) and v.strip()]
    if not items:
        raise PdfError('映射表无效。')

    try:
        doc = fitz.open(stream=pdf_bytes, filetype='pdf')
    except Exception:
        raise PdfError('PDF 文件无效或已损坏。')
    if doc.needs_pass:
        doc.close()
        raise PdfError('PDF 受密码保护：请移除保护后重试。')

    # 值长优先：长值先涂，短值（如"张三"）不会先占掉长值（如"张三丰"）的矩形
    items.sort(key=lambda kv: -len(kv[1]))

    skipped, usable = [], []
    for ph, val in items:
        if _too_noisy(val):
            skipped.append(ph)
            continue
        pat = _value_pattern(val)
        if pat:
            usable.append((ph, val, pat))
        else:
            skipped.append(ph)

    by_ph = {ph: 0 for ph, _, _ in usable}
    patterns = [(pat, ph) for ph, _, pat in usable]
    total = n_annots = n_widgets = 0

    for page in doc:
        text, boxes = _page_char_index(page)
        taken = []
        if text.strip():
            for ph, _val, pat in usable:
                for m in pat.finditer(text):
                    rects = _match_rects(boxes, m)
                    placed_any, labeled = False, False
                    for r in rects:
                        if _covered(r, taken):
                            continue
                        fs = 0 if labeled else _fit_fontsize(ph, r)
                        _add_redact_annot(page, r, ph if fs else None,
                                          fs or 6, REDACT_FILL, REDACT_TEXT)
                        taken.append(fitz.Rect(r))
                        placed_any = True
                        labeled = labeled or bool(fs)
                    if placed_any:
                        by_ph[ph] += 1
                        total += 1
        if taken:
            page.apply_redactions()       # 真删除 content stream
        # 批注/表单不是 content stream，涂黑删不到，另行清理
        n_annots += _scrub_annots(page, patterns)
        n_widgets += _scrub_widgets(page, patterns)

    n_toc = _scrub_toc(doc, patterns)
    n_emb = _strip_embedded(doc)
    _scrub_metadata(doc)
    out = doc.tobytes(garbage=3, deflate=True)
    doc.close()

    # 安全语义 2：全文零命中 → 拒绝交付（典型：扫描件文字在图片里）
    if total == 0:
        raise PdfError(
            'PDF 文本层找不到任何待脱敏内容（共 {} 个待涂值）。'
            '这通常是扫描件（文字在图片里）——若交付将是一份"假脱敏"PDF，'
            '因此拒绝输出。请先对 PDF 做 OCR 后再脱敏。'.format(len(usable)))

    # 安全语义 1：residual 校验——输出里还能读到原文 → 拒绝交付
    residual = _verify_residuals(out, [(ph, v) for ph, v, _ in usable])
    if residual:
        raise PdfError(
            '涂黑后以下 {} 个值在输出 PDF 中仍可读（residual 校验失败），'
            '拒绝交付：{}'.format(len(residual), sorted(set(residual))[:10]))

    return out, {
        'occurrences': total,
        'by_placeholder': by_ph,
        'not_found': [ph for ph, n in by_ph.items() if n == 0],
        'skipped': skipped,
        'residual': [],
        'annots': n_annots,
        'widgets': n_widgets,
        'toc': n_toc,
        'embedded': n_emb,
    }
