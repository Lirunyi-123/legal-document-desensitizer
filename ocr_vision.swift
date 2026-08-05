// ocr_vision.swift — 用 macOS Vision 框架做中文/英文 OCR（串行版）
// 用法: ocr_vision <image1> <image2> ...
// 输出: 每张图片的识别文本，页之间以 "\n=====PAGE N=====\n" 分隔（N 从 1 起）
//
// 供 desensitize.py 在扫描件 PDF 无文本层时调用：
// Python 把 PDF 每页渲染为 PNG → 本脚本批量 OCR → 拼接文本
//
// 依赖: macOS 10.15+，无需安装任何工具（系统自带 Vision 框架）

import Foundation
import Vision
import AppKit

// 按文件名排序（保证页码顺序），如 "page_001.png"
let files = CommandLine.arguments.dropFirst().sorted { a, b in
    a.localizedStandardCompare(b) == .orderedAscending
}

func ocr(_ path: String) -> String {
    guard let img = NSImage(contentsOfFile: path),
          let cg = img.cgImage(forProposedRect: nil, context: nil, hints: nil) else {
        return ""
    }
    let req = VNRecognizeTextRequest()
    req.recognitionLanguages = ["zh-Hans", "en-US"]
    req.recognitionLevel = .accurate
    req.usesLanguageCorrection = true
    do {
        try VNImageRequestHandler(cgImage: cg, options: [:]).perform([req])
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

for (i, f) in files.enumerated() {
    if i > 0 { print("=====PAGE \(i + 1)=====") }
    print(ocr(f))
}
