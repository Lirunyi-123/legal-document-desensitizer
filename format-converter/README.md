# format-converter — 法律文书格式转换核心

从 [FlyingMouse Format / 飞鼠格式](https://github.com/LaoFeng-mouse/flyingmouse-format)
（MIT License, Copyright (c) 2026 LaoFeng）抽取，**只保留对法律文书脱敏有帮助的
纯 JS 转换能力**，无 FFmpeg / LibreOffice / Poppler / Tesseract 外部引擎依赖，
npm install 后即可在本机直接运行。

## 能力矩阵（面向脱敏场景）

### 1. 文档类：docx → txt / md / html（mammoth，律师文书、合同常用）

```bash
node cli.js 合同.docx txt -o 合同.txt     # 纯文本（人名/金额/案号提取）
node cli.js 判决书.docx md -o 判决书.md   # Markdown（保留标题、列表）
```

脱敏工作流：docx → txt 后交给规则引擎/LLM 层做脱敏。

### 2. PDF 类：pdf → txt（pdfjs-dist，判决书、裁判文书常用）

```bash
node cli.js 判决书.pdf txt -o 判决书.txt
```

> 注意：仅支持**带文本层**的 PDF（电子版文书）。扫描件/图片型 PDF 无文本层，
> 提取结果为空——这类需先走脱敏工具的 OCR 通道（`--ocr`）再处理。

### 3. 文本类：txt / md / html / json / csv 互转

| 输入 \ 目标 | txt | md | html | json | csv |
|---|---|---|---|---|---|
| txt | ✓ | ✓ | ✓ | ✓ | ✓ |
| md | ✓ | ✓ | ✓ | ✓ | ✓ |
| html | ✓ | ✓ | ✓ | ✓ | ✓ |
| json | ✓ | ✓ | ✓ | ✓ | ✓ |
| csv | ✓ | ✓ | ✓ | ✓ | ✓ |

- HTML→MD 使用 Turndown，保留标题、列表、代码块与表格（含复杂表格安全序列化）
- MD→HTML 使用 marked，外部链接/图片经安全校验
- CSV→JSON 兼容 BOM、转义引号、字段内换行；JSON→CSV 扁平化嵌套对象
- 场景：网上复制的裁判文书（HTML）→ MD/TXT 后脱敏；当事人名单 CSV ↔ JSON

### 4. 图片类：png/jpg/webp/gif/avif/tiff 互转 + 单图→PDF（sharp）

```bash
node cli.js 扫描件.png pdf -o 扫描件.pdf   # 单图合 PDF
node cli.js photo.heic jpg                  # 手机照片转通用格式
```

- 动画 gif/webp 转静态格式时保留第一帧并给出提示
- JPEG 输出自动将透明区域合成白色背景
- 单图上限 50MP / 16384px（安全默认）

### 明确排除（与脱敏无关或需外部引擎）

音视频转换（FFmpeg）、Office 全格式互转（LibreOffice）、OCR（Tesseract）、
NCM/KGG 音乐解密、ZIP——如需这些能力请使用原版飞鼠格式。

## 安装

```bash
cd format-converter
npm install
```

依赖：`csv-parse`、`marked`、`turndown`、`sharp`、`mammoth`、`pdfjs-dist`
（需要 node >= 22.13，pdfjs-dist 6.x 与 sharp 0.35 的最低要求）。

## 用法

```bash
node cli.js <输入文件> <目标格式> [-o 输出路径] [-f]
```

- 输出默认写到输入文件同目录、同文件名 + 新扩展名
- `-o` 指定输出路径，`-f` 覆盖已存在文件
- 详见 `node cli.js --help`

## 测试

```bash
node test-cli.js
```

端到端覆盖：md/html/csv/json 互转、png/jpg/gif/tiff/pdf 图片转换、
docx→txt/md、pdf→txt、错误处理。

## 许可

本目录内的 `text-conversion.js` / `image-conversion.js` 来自 FlyingMouse Format
项目，MIT License，版权归 LaoFeng (c) 2026，完整许可见
`LICENSE-flyingmouse-format.txt`。`cli.js` / `package.json` 为本地封装。
