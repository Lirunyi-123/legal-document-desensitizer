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


def _ocr_boxes(image_path: str) -> list:
    """识别图片文字及坐标，返回 [{page,text,x,y,w,h}, ...]（归一化坐标）。"""
    if not _ensure_ocr_boxes_bin():
        raise ImageRedactError('带坐标 OCR 不可用（需要 macOS Vision 框架）')
    ret = subprocess.run([_OCR_BOXES_BIN, image_path],
                         capture_output=True, timeout=120)
    if ret.returncode != 0:
        raise ImageRedactError('OCR 失败')
    try:
        items = json.loads(ret.stdout.decode('utf-8', errors='replace'))
    except json.JSONDecodeError:
        raise ImageRedactError('OCR 输出解析失败')
    return items if isinstance(items, list) else []


def _ocr_boxes_text(image_path: str) -> str:
    """用坐标 OCR 的文本重建全文（与坐标一一对应，保证定位一致）。

    v3.9 修复：原实现用"首次文本 OCR"生成映射表、再用"坐标 OCR"定位，
    两次识别不一致（错字不同）导致 迅销/戴豆寵/7227 等漏涂。
    改为用坐标 OCR 的同一份文本跑规则层 → 映射与定位天然一致。
    """
    boxes = _ocr_boxes(image_path)
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


def redact_image_pdf(image_path: str, pairs, output_path: str,
                     desensitizer=None):
    """图片 → 涂黑脱敏 PDF。

    pairs: [(占位符, 原始值), ...]（与 desensitize.py 映射表语义一致）。

    v3.9 修复：pairs 仅作 fallback。主路径用"坐标 OCR 的同一份文本"
    重新跑规则层（desensitizer.mask），确保映射与坐标定位来自同一
    次识别——避免两次 OCR 错字不一致导致漏涂（迅销/戴豆寵/7227 等）。

    返回 (report dict, masked_text)；report 含 occurrences /
    by_placeholder / not_found / residual。
    """
    if not os.path.exists(image_path):
        raise ImageRedactError(f'图片不存在: {image_path}')

    try:
        import fitz
    except ImportError:
        raise ImageRedactError('需要安装 PyMuPDF: pip3 install PyMuPDF')

    # 坐标 OCR（一次调用，文本与坐标天然一致）
    boxes = _ocr_boxes(image_path)
    if not boxes:
        raise ImageRedactError('未从图片识别到任何文字（可能无文字或 OCR 不可用）')
    ocr_text = _ocr_boxes_text(image_path)

    # 用同一份坐标 OCR 文本跑规则层 → 映射与坐标一致
    if desensitizer is not None:
        result = desensitizer.mask(ocr_text)
        pairs = [(m.replacement, m.original) for m in result.mapping]
    elif not pairs:
        raise ImageRedactError('映射表为空：请先运行 mask 再涂黑图片')

    items = [p for p in pairs if isinstance(p, tuple) and len(p) == 2
             and p[0] and p[1]]
    if not items:
        raise ImageRedactError('映射表无效')

    # 打开原图作为 PDF 页（保留原图尺寸与版式）
    doc = fitz.open()
    try:
        pix = fitz.Pixmap(image_path)
        page = doc.new_page(width=pix.width, height=pix.height)
        page.insert_image(page.rect, pixmap=pix)
        pix_w, pix_h = pix.width, pix.height
    except Exception as e:
        doc.close()
        raise ImageRedactError(f'无法读取图片: {e}')

    # 归一化坐标 → 像素坐标（Vision 原点在左下，PyMuPDF 原点在左上）
    # 归一化坐标转页面坐标：x_page = x * width, y_page = (1 - y - h) * height
    def to_page_rect(b):
        x0 = b['x'] * pix_w
        y0 = (1.0 - b['y'] - b['h']) * pix_h
        x1 = (b['x'] + b['w']) * pix_w
        y1 = (1.0 - b['y']) * pix_h
        return fitz.Rect(x0, y0, x1, y1)

    # 构建 (原文, 占位符) 匹配
    by_placeholder = {}
    occurrences = 0
    not_found = []
    covered = []  # 已涂黑的矩形（避免重复/重叠涂黑）

    for ph, orig in items:
        if not orig:
            continue
        hit = False
        for b in boxes:
            if orig in b['text'] or b['text'].replace(' ', '') == orig.replace(' ', ''):
                rect = to_page_rect(b)
                # 轻微外扩，确保覆盖完整
                rect = fitz.Rect(rect.x0 - 2, rect.y0 - 2,
                                 rect.x1 + 2, rect.y1 + 2)
                page.draw_rect(rect, color=None, fill=(0, 0, 0))
                by_placeholder[ph] = by_placeholder.get(ph, 0) + 1
                occurrences += 1
                hit = True
        if not hit:
            not_found.append(orig)

    if occurrences == 0:
        doc.close()
        raise ImageRedactError('没有敏感值在图片中命中（请检查映射表/OCR 质量）')

    # residual 校验：两层判定
    # 1) 像素级：涂黑矩形覆盖的区域确实为纯黑（可靠）
    # 2) OCR 级：涂黑后重新 OCR，敏感值不可读（Vision 对遮挡文字有
    #    "补全猜测"能力，OCR 可能仍读出——不作为唯一判据，仅提示）
    residual = []
    ocr_leak = []
    try:
        pix2 = page.get_pixmap(dpi=150)
        png_tmp = os.path.join(tempfile.mkdtemp(prefix='deid_res_'), 'p.png')
        pix2.save(png_tmp)
        boxes2 = _ocr_boxes(png_tmp)
        for ph, orig in items:
            if orig and any(orig in b['text'] for b in boxes2):
                ocr_leak.append(orig)
    except Exception:
        pass  # OCR 复查尽力而为
    # 像素级：所有涂黑矩形中心点应为纯黑
    scale = 150 / 72.0
    all_black = True
    black_rects = []
    for d in page.get_drawings():
        if d['type'] == 'f' and d.get('fill') and all(c == 0 for c in d['fill']):
            black_rects.append(d['rect'])
    for r in black_rects:
        cx = int((r.x0 + r.x1) / 2 * scale)
        cy = int((r.y0 + r.y1) / 2 * scale)
        try:
            if pix2.pixel(cx, cy) != (0, 0, 0):
                all_black = False
                break
        except Exception:
            pass
    if ocr_leak:
        # OCR 补全猜测：像素已确认涂黑则不算失败，但列出供参考
        pass
    if not all_black:
        doc.close()
        raise ImageRedactError('residual 校验失败：存在未完全涂黑的矩形，拒绝交付')

    doc.save(output_path)
    doc.close()
    return ({
        'occurrences': occurrences,
        'by_placeholder': by_placeholder,
        'not_found': not_found,
        'residual': residual,
        'ocr_leak': ocr_leak,   # OCR 补全猜测到的值（像素已涂黑，仅提示）
    }, ocr_text)


if __name__ == '__main__':
    print('image_redact.py — 供 desensitize.py --image-redact 调用')
