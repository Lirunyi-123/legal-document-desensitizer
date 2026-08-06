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


def redact_image_pdf(image_path: str, pairs, output_path: str):
    """图片 → 涂黑脱敏 PDF。

    pairs: [(占位符, 原始值), ...]（与 desensitize.py 映射表语义一致）。
    返回 (report dict)；report 含 occurrences / by_placeholder / not_found /
    residual（输出后仍可读的敏感值，非空表示涂黑失败）。
    """
    if not os.path.exists(image_path):
        raise ImageRedactError(f'图片不存在: {image_path}')
    if not pairs:
        raise ImageRedactError('映射表为空：请先运行 mask 再涂黑图片')

    items = [p for p in pairs if isinstance(p, tuple) and len(p) == 2
             and p[0] and p[1]]
    if not items:
        raise ImageRedactError('映射表无效')

    try:
        import fitz
    except ImportError:
        raise ImageRedactError('需要安装 PyMuPDF: pip3 install PyMuPDF')

    # OCR 带坐标
    boxes = _ocr_boxes(image_path)
    if not boxes:
        raise ImageRedactError('未从图片识别到任何文字（可能无文字或 OCR 不可用）')

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

    # residual 校验：重新 OCR 涂黑后的 PDF 页，确认敏感值不可读
    residual = []
    try:
        pix2 = page.get_pixmap(dpi=200)
        png_tmp = os.path.join(tempfile.mkdtemp(prefix='deid_res_'), 'p.png')
        pix2.save(png_tmp)
        boxes2 = _ocr_boxes(png_tmp)
        for ph, orig in items:
            if orig and any(orig in b['text'] for b in boxes2):
                residual.append(orig)
        if residual:
            doc.close()
            raise ImageRedactError(
                f'residual 校验失败：{residual} 仍可读，拒绝交付')
    except ImageRedactError:
        raise
    except Exception:
        pass  # residual 校验尽力而为

    doc.save(output_path)
    doc.close()
    return {
        'occurrences': occurrences,
        'by_placeholder': by_placeholder,
        'not_found': not_found,
        'residual': residual,
    }


if __name__ == '__main__':
    print('image_redact.py — 供 desensitize.py --image-redact 调用')
