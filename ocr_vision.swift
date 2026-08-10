// ocr_vision.swift — 用 macOS Vision 框架做中文/英文 OCR（串行版）
// 用法: ocr_vision <image1> <image2> ...
// 输出: 每张图片的识别文本，页之间以 "\n=====PAGE N=====\n" 分隔（N 从 1 起）
//
// 供 desensitize.py 在扫描件 PDF 无文本层时调用：
// Python 把 PDF 每页渲染为 PNG → 本脚本批量 OCR → 拼接文本
//
// 依赖: macOS 10.15+，无需安装任何工具（系统自带 Vision 框架）
//
// 2026-08-11 实战修复：
// 改用 VNImageRequestHandler(url:) 优先加载图片 —— 原先仅用 NSImage→cgImage
// 路径，对部分扫描件（PyMuPDF 渲染/抽取的图片）会返回 nilError 导致 OCR 为空；
// 现 URL 失败时再回退 cgImage 方式。

import Foundation
import Vision
import AppKit
import CoreGraphics

func ocrImage(url: URL, level: VNRequestTextRecognitionLevel = .accurate) -> String {
    let req = VNRecognizeTextRequest()
    req.recognitionLanguages = ["zh-Hans", "en-US"]
    req.recognitionLevel = level
    req.usesLanguageCorrection = true
    do {
        try VNImageRequestHandler(url: url, options: [:]).perform([req])
    } catch {
        return ""
    }
    var lines: [String] = []
    for obs in (req.results as? [VNRecognizedTextObservation]) ?? [] {
        if let t = obs.topCandidates(1).first {
            lines.append(t.string)
        }
    }
    return lines.joined(separator: "\n")
}

func ocrImage(cgImage: CGImage) -> String {
    let req = VNRecognizeTextRequest()
    req.recognitionLanguages = ["zh-Hans", "en-US"]
    req.recognitionLevel = .accurate
    req.usesLanguageCorrection = true
    do {
        try VNImageRequestHandler(cgImage: cgImage, options: [:]).perform([req])
    } catch {
        return ""
    }
    var lines: [String] = []
    for obs in (req.results as? [VNRecognizedTextObservation]) ?? [] {
        if let t = obs.topCandidates(1).first {
            lines.append(t.string)
        }
    }
    return lines.joined(separator: "\n")
}

// 按文件名排序（保证页码顺序），如 "page_001.png"
let files = CommandLine.arguments.dropFirst().sorted { a, b in
    a.localizedStandardCompare(b) == .orderedAscending
}

for (i, f) in files.enumerated() {
    if i > 0 { print("=====PAGE \(i + 1)=====") }
    let url = URL(fileURLWithPath: f)
    // 优先 URL 方式加载（对 PyMuPDF 渲染/抽取的扫描件更稳）；
    // URL 失败时回退 cgImage 方式（兼容部分特殊编码图片）。
    let text = ocrImage(url: url)
    if !text.isEmpty {
        print(text)
    } else {
        if let img = NSImage(contentsOfFile: f),
           let cg = img.cgImage(forProposedRect: nil, context: nil, hints: nil) {
            print(ocrImage(cgImage: cg))
        } else {
            print("")
        }
    }
}
