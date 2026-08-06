// ocr_vision_boxes.swift — 带坐标的 OCR（macOS Vision 框架）
// 用法: ocr_vision_boxes <image1> <image2> ...
// 输出: JSON 数组，每个元素:
//   { "page": N, "text": "...", "x": 0~1, "y": 0~1, "w": 0~1, "h": 0~1 }
// 坐标均为归一化值（0~1），原点在图片左下角（Vision 惯例）。
//
// 供 desensitize.py 的 --image-redact 使用：拿到敏感值的坐标框，
// 在原图对应像素区域涂黑，输出保留版式的脱敏 PDF。
//
// 依赖: macOS 10.15+，无需安装任何工具

import Foundation
import Vision
import AppKit

let files = CommandLine.arguments.dropFirst().sorted { a, b in
    a.localizedStandardCompare(b) == .orderedAscending
}

func ocr(_ path: String, pageIndex: Int) -> [[String: Any]] {
    guard let img = NSImage(contentsOfFile: path),
          let cg = img.cgImage(forProposedRect: nil, context: nil, hints: nil) else {
        return []
    }
    let req = VNRecognizeTextRequest()
    req.recognitionLanguages = ["zh-Hans", "en-US"]
    req.recognitionLevel = .accurate
    req.usesLanguageCorrection = true
    do {
        try VNImageRequestHandler(cgImage: cg, options: [:]).perform([req])
    } catch {
        return []
    }
    var items: [[String: Any]] = []
    for obs in (req.results as? [VNRecognizedTextObservation]) ?? [] {
        if let t = obs.topCandidates(1).first {
            let bb = obs.boundingBox
            items.append([
                "page": pageIndex,
                "text": t.string,
                "x": bb.origin.x,
                "y": bb.origin.y,
                "w": bb.size.width,
                "h": bb.size.height
            ])
        }
    }
    return items
}

var all: [[String: Any]] = []
for (i, f) in files.enumerated() {
    all.append(contentsOf: ocr(f, pageIndex: i))
}
if let data = try? JSONSerialization.data(withJSONObject: all,
                                          options: [.withoutEscapingSlashes]),
   let s = String(data: data, encoding: .utf8) {
    print(s)
}
