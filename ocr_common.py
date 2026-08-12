# -*- coding: utf-8 -*-
"""macOS Vision OCR 二进制的编译/缓存/自检共享实现。

desensitize.py（文本 OCR）与 image_redact.py（带坐标 OCR）此前各自维护一份
几乎相同的"编译 → 自检 → 回退缓存 → 回退常见目录"逻辑，统一到这里避免两处漂移。
"""

import os
import subprocess
import sys


_FONT_CANDIDATES = (
    '/System/Library/Fonts/Supplemental/Arial.ttf',
    '/System/Library/Fonts/Helvetica.ttc',
    '/System/Library/Fonts/PingFang.ttc',
    '/Library/Fonts/Arial Unicode.ttf',
)


def write_selftest_png(path: str) -> bool:
    """用 PIL + 系统字体绘制 'ABC 123' 并写成 PNG；成功返回 True。"""
    try:
        from PIL import Image, ImageDraw, ImageFont
    except ImportError:
        return False
    font_path = next((f for f in _FONT_CANDIDATES if os.path.exists(f)), None)
    if not font_path:
        return False
    try:
        img = Image.new('RGB', (720, 180), 'white')
        d = ImageDraw.Draw(img)
        font = ImageFont.truetype(font_path, 90)
        d.text((40, 40), 'ABC 123', fill='black', font=font)
        img.save(path)
        return True
    except Exception:
        return False


def compile_swift_bin(source: str, bin_path: str, module_cache_dir: str) -> bool:
    """重新编译 swift 源码到 bin_path；成功返回 True（自检由调用方完成）。"""
    os.makedirs(module_cache_dir, exist_ok=True)
    env = dict(os.environ)
    env['CLANG_MODULE_CACHE_PATH'] = module_cache_dir
    try:
        ret = subprocess.run(
            ['swiftc', '-O', '-o', bin_path, source],
            capture_output=True, timeout=180, env=env)
    except Exception:
        return False
    return ret.returncode == 0


def warn_fallback(reason: str) -> None:
    """OCR 缓存回退时输出一次提示（stderr），避免静默降级。"""
    print(f'⚠️  {reason}；如需彻底修复，请更新 Xcode Command Line Tools'
          '（xcode-select --install 或软件更新）', file=sys.stderr)


def ensure_bin(source: str, bin_path: str, fallback_dirs, module_cache_dir: str,
               verify, bin_label: str = 'OCR', warn=None) -> bool:
    """确保 OCR 二进制可用。

    顺序：缓存命中（且过自检）→ 重编译（且过自检）→ 回退已有缓存二进制 →
    回退常见缓存目录。verify(bin_path) 返回 True 表示自检通过；warn(reason)
    用于在回退降级时提示（不静默）。
    """
    if sys.platform != 'darwin':
        return False
    if not os.path.exists(source):
        return False
    if os.path.exists(bin_path) \
            and os.path.getmtime(bin_path) >= os.path.getmtime(source):
        if verify(bin_path):
            return True
    if compile_swift_bin(source, bin_path, module_cache_dir) and verify(bin_path):
        return True
    if os.path.exists(bin_path) and verify(bin_path):
        if warn:
            warn(f'重编译失败，沿用本机已有 {bin_label} 二进制')
        return True
    for d in fallback_dirs:
        alt = os.path.join(d, os.path.basename(bin_path))
        if os.path.exists(alt) and verify(alt):
            try:
                import shutil
                shutil.copy2(alt, bin_path)
                if warn:
                    warn(f'重编译失败，已复用 {d} 中可用的 {bin_label} 二进制')
                return True
            except OSError:
                return False
    return False
