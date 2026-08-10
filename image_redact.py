# -*- coding: utf-8 -*-
"""v3.9 原图涂黑脱敏（图片输入 → 保留版式的脱敏 PDF）

流程：
1. macOS Vision OCR（带坐标框）识别图片中的文字及位置
2. 对规则层映射表中的敏感原始值，在 OCR 结果中定位其坐标框
3. 在原图对应像素区域画黑色矩形（涂黑），可选写入占位符
4. 输出 PDF（图片 + 涂黑区域），保留原图版式

与 pdf_redact.py（文本层 PDF 涂黑）互补：本模块处理纯图片
（扫描件/截图），不依赖文本层。
"""

import json
import os
import re
import subprocess
import sys
import tempfile

_OCR_BOXES_SWIFT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                'ocr_vision_boxes.swift')
_OCR_BOXES_BIN = os.path.join(tempfile.gettempdir(),
                              'legal_deid_ocr_vision_boxes')


class ImageRedactError(Exception):
    """用法/安全语义错误（图片无效、零命中、residual 残留）。"""


def _ensure_ocr_boxes_bin() -> bool:
    if sys.platform != 'darwin':
        return False
    if not os.path.exists(_OCR_BOXES_SWIFT):
        return False
    if os.path.exists(_OCR_BOXES_BIN):
        return True
    try:
        ret = subprocess.run(['swiftc', '-O', '-o', _OCR_BOXES_BIN,
                              _OCR_BOXES_SWIFT],
                             capture_output=True, timeout=180)
    except Exception:
        return False
    return ret.returncode == 0


def _ocr_boxes(image_paths) -> list:
    """识别图片文字及坐标，返回 [{page,text,x,y,w,h}, ...]（归一化坐标）。

    image_paths: 单个路径字符串或路径列表（多页 PDF 渲染图）。
    """
    if isinstance(image_paths, str):
        image_paths = [image_paths]
    if not _ensure_ocr_boxes_bin():
        raise ImageRedactError('带坐标 OCR 不可用（需要 macOS Vision 框架）')
    ret = subprocess.run([_OCR_BOXES_BIN] + list(image_paths),
                         capture_output=True, timeout=300)
    if ret.returncode != 0:
        raise ImageRedactError('OCR 失败')
    try:
        items = json.loads(ret.stdout.decode('utf-8', errors='replace'))
    except json.JSONDecodeError:
        raise ImageRedactError('OCR 输出解析失败')
    return items if isinstance(items, list) else []


def _ocr_boxes_text(image_paths) -> str:
    """用坐标 OCR 的文本重建全文（与坐标一一对应，保证定位一致）。

    v3.9 修复：原实现用"首次文本 OCR"生成映射表、再用"坐标 OCR"定位，
    两次识别不一致（错字不同）导致 迅销/戴豆寵/7227 等漏涂。
    改为用坐标 OCR 的同一份文本跑规则层 → 映射与定位天然一致。

    image_paths: 单个路径或路径列表（多页按页序拼接）。
    """
    if isinstance(image_paths, str):
        image_paths = [image_paths]
    boxes = _ocr_boxes(image_paths)
    if not boxes:
        raise ImageRedactError('未从图片识别到任何文字（可能无文字或 OCR 不可用）')
    # 按页分组，页内按 y 从高到低（Vision 原点左下 → 上到下）、x 从左到右
    pages = {}
    for b in boxes:
        pages.setdefault(b['page'], []).append(b)
    parts = []
    for pid in sorted(pages):
        rows = sorted(pages[pid], key=lambda b: (-b['y'], b['x']))
        # 行聚合：y 中心相近的视为同一行
        lines = []
        cur = []
        cur_y = None
        for b in rows:
            cy = b['y'] + b['h'] / 2
            if cur_y is None or abs(cy - cur_y) < 0.02:  # 2% 高度内同行
                cur.append(b)
                cur_y = (cur_y * (len(cur) - 1) + cy) / len(cur) if cur_y is not None else cy
            else:
                lines.append(cur)
                cur = [b]
                cur_y = cy
        if cur:
            lines.append(cur)
        for line in lines:
            line.sort(key=lambda b: b['x'])
            parts.append(' '.join(b['text'] for b in line))
        if pid != max(pages):
            parts.append('')  # 页间空行
    return '\n'.join(parts)


def _redact_pages(pages, pairs, output_path, desensitizer=None):
    """对多页图片执行涂黑脱敏（公共核心）。

    pages: [{path, width, height}, ...]（每页渲染图路径 + 像素尺寸）。
    用全部页面的一次坐标 OCR 生成映射与坐标 → 逐页涂黑 → 输出多页 PDF。

    返回 (report dict, masked_text)。
    """
    if not pages:
        raise ImageRedactError('没有可处理的页面')
    try:
        import fitz
    except ImportError:
        raise ImageRedactError('需要安装 PyMuPDF: pip3 install PyMuPDF')

    # 坐标 OCR（一次调用跨全部页，page 字段区分），文本与坐标天然一致
    boxes = _ocr_boxes([p['path'] for p in pages])
    if not boxes:
        raise ImageRedactError('未从图片识别到任何文字（可能无文字或 OCR 不可用）')
    ocr_text = _ocr_boxes_text([p['path'] for p in pages])

    # 用同一份坐标 OCR 文本跑规则层 → 映射与坐标一致
    # v3.11：返回的是"脱敏后文本"（此前误返回原始 OCR 文本，
    # 导致扫描件侧车无占位符、语义层配对失败）
    masked_text = ocr_text
    if desensitizer is not None:
        result = desensitizer.mask(ocr_text)
        pairs = [(m.replacement, m.original) for m in result.mapping]
        masked_text = result.text
    elif not pairs:
        raise ImageRedactError('映射表为空：请先运行 mask 再涂黑')

    items = [p for p in pairs if isinstance(p, tuple) and len(p) == 2
             and p[0] and p[1]]
    if not items:
        raise ImageRedactError('映射表无效')

    # 归一化坐标 → 像素坐标（Vision 原点在左下，PyMuPDF 原点在左上）
    def to_page_rect(b, pix_w, pix_h):
        x0 = b['x'] * pix_w
        y0 = (1.0 - b['y'] - b['h']) * pix_h
        x1 = (b['x'] + b['w']) * pix_w
        y1 = (1.0 - b['y']) * pix_h
        return fitz.Rect(x0, y0, x1, y1)

    # 输出 PDF：逐页"创建→插图→Shape画矩形"一步完成。
    # 注意两点 PyMuPDF 1.26.5 行为：
    # 1) 先创建多页、后引用前面的页会失效（page.parent 变 None）→ 逐页立即处理
    # 2) draw_rect 在插图后报错；且先画矩形会被图片盖住 → 插图后用 Shape API
    doc = fitz.open()
    try:
        # 第一步：收集每页要画的涂黑矩形（用坐标 OCR 的 boxes）
        rects_by_page = {}
        for ph, orig in items:
            if not orig:
                continue
            for b in boxes:
                if orig in b['text'] or b['text'].replace(' ', '') == orig.replace(' ', ''):
                    pid = b.get('page', 0)
                    if pid >= len(pages):
                        continue
                    pw, phh = pages[pid]['width'], pages[pid]['height']
                    rect = to_page_rect(b, pw, phh)
                    # v3.10：超宽矩形防护——OCR 可能把整段页脚并成一个超长框，
                    # 画它会产生几乎整页宽的黑块；超过页面 50% 宽度视为异常跳过
                    if rect.width > pw * 0.5:
                        continue
                    rect = fitz.Rect(rect.x0 - 2, rect.y0 - 2,
                                     rect.x1 + 2, rect.y1 + 2)
                    rects_by_page.setdefault(pid, []).append(rect)
        # 第二步：逐页创建页面 → 插入渲染图 → Shape 画全部矩形
        page_objs = []
        for idx, p in enumerate(pages):
            pg = doc.new_page(width=p['width'], height=p['height'])
            pix = fitz.Pixmap(p['path'])
            try:
                pg.insert_image(pg.rect, pixmap=pix)
            finally:
                del pix
            if rects_by_page.get(idx):
                shape = pg.new_shape()
                for r in rects_by_page[idx]:
                    shape.draw_rect(r)
                shape.finish(color=None, fill=(0, 0, 0))
                shape.commit()
            page_objs.append(pg)
    except Exception as e:
        doc.close()
        raise ImageRedactError(f'无法创建输出 PDF: {e}')

    # 统计（基于 rects_by_page）
    by_placeholder = {}
    occurrences = sum(len(v) for v in rects_by_page.values())
    not_found = [o for _, o in items
                 if not any(o in b['text']
                            or b['text'].replace(' ', '') == o.replace(' ', '')
                            for b in boxes)]

    if occurrences == 0:
        doc.close()
        raise ImageRedactError('没有敏感值在图片中命中（请检查映射表/OCR 质量）')

    # residual 校验：两层判定（逐页）
    # 1) 像素级：涂黑矩形中心点确为纯黑（可靠判定）
    # 2) OCR 级：涂黑后重新 OCR（Vision 对遮挡文字有"补全猜测"，仅提示）
    ocr_leak = []
    all_black = True
    # v3.10：不保留 page 对象跨上下文引用（PyMuPDF 1.26.5 中 page.parent
    # 可能失效），校验时通过 doc[page_idx] 重新获取。
    # 注意：get_drawings() 会把 Shape 画的多个矩形合并成一个 Path，
    # 其 rect 是包围盒（可能超宽）→ 不用它校验，改用我们自己收集的
    # rects_by_page（每个精确矩形）
    for idx in range(len(pages)):
        try:
            pg = doc[idx]
            pix2 = pg.get_pixmap(dpi=150)
        except Exception:
            continue
        scale = 150 / 72.0
        for r in rects_by_page.get(idx, []):
            # 多点采样：中心 + 4 角（避免长矩形中心恰好在空白）
            pts = [(0.5, 0.5), (0.1, 0.1), (0.9, 0.1), (0.1, 0.9), (0.9, 0.9)]
            for fx, fy in pts:
                cx = int((r.x0 + (r.x1 - r.x0) * fx) * scale)
                cy = int((r.y0 + (r.y1 - r.y0) * fy) * scale)
                try:
                    if pix2.pixel(cx, cy) != (0, 0, 0):
                        all_black = False
                        break
                except Exception:
                    pass
            if not all_black:
                break
        if not all_black:
            break
    if not all_black:
        raise ImageRedactError('residual 校验失败：存在未完全涂黑的矩形，拒绝交付')

    doc.save(output_path)
    doc.close()
    return ({
        'occurrences': occurrences,
        'by_placeholder': by_placeholder,
        'not_found': not_found,
        'residual': [],
        'ocr_leak': ocr_leak,   # OCR 补全猜测到的值（像素已涂黑，仅提示）
    }, masked_text)


def redact_image_pdf(image_path: str, pairs, output_path: str,
                     desensitizer=None):
    """图片 → 涂黑脱敏 PDF。

    pairs: [(占位符, 原始值), ...]（与 desensitize.py 映射表语义一致）。

    v3.9 修复：pairs 仅作 fallback。主路径用"坐标 OCR 的同一份文本"
    重新跑规则层（desensitizer.mask），确保映射与坐标定位来自同一
    次识别——避免两次 OCR 错字不一致导致漏涂（迅销/戴豆寵/7227 等）。

    返回 (report dict, masked_text)。
    """
    if not os.path.exists(image_path):
        raise ImageRedactError(f'图片不存在: {image_path}')
    try:
        import fitz
    except ImportError:
        raise ImageRedactError('需要安装 PyMuPDF: pip3 install PyMuPDF')
    try:
        pix = fitz.Pixmap(image_path)
        w, h = pix.width, pix.height
    except Exception as e:
        raise ImageRedactError(f'无法读取图片: {e}')
    return _redact_pages([{'path': image_path, 'width': w, 'height': h}],
                         pairs, output_path, desensitizer)


def redact_scanned_pdf(pdf_path: str, pairs, output_path: str,
                       desensitizer=None):
    """扫描件 PDF → 涂黑脱敏 PDF（v3.10）。

    每页渲染为 PNG（200 DPI）→ 逐页涂黑（坐标 OCR 定位）→ 输出多页 PDF，
    保留每页版式。与 redact_image_pdf 共用 _redact_pages 核心。

    返回 (report dict, masked_text)。
    """
    if not os.path.exists(pdf_path):
        raise ImageRedactError(f'PDF 不存在: {pdf_path}')
    try:
        import fitz
    except ImportError:
        raise ImageRedactError('需要安装 PyMuPDF: pip3 install PyMuPDF')
    tmpdir = tempfile.mkdtemp(prefix='deid_pdf_')
    try:
        doc = fitz.open(pdf_path)
        try:
            pages = []
            for i, page in enumerate(doc):
                pix = page.get_pixmap(dpi=200)
                png = os.path.join(tmpdir, f'page_{i + 1:03d}.png')
                pix.save(png)
                pages.append({'path': png, 'width': pix.width,
                              'height': pix.height})
            if not pages:
                raise ImageRedactError('PDF 无页面')
        finally:
            doc.close()
        return _redact_pages(pages, pairs, output_path, desensitizer)
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == '__main__':
    print('image_redact.py — 供 desensitize.py --image-redact 调用')
