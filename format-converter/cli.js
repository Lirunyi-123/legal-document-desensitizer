#!/usr/bin/env node
/**
 * format-converter CLI — 法律文书格式转换（纯 JS 核心，无外部引擎依赖）
 *
 * 面向法律文书脱敏场景，支持：
 *   文本类（txt/md/html/json/csv 互转，含 HTML→MD 保留表格、JSON→CSV 扁平化）
 *   文档类（docx → txt/md/html，mammoth 引擎，律师文书/合同常用）
 *   PDF 类（pdf → txt，pdfjs-dist 引擎，判决书/裁判文书常用）
 *   图片类（png/jpg/webp/gif/avif/tiff 互转 + 单图→PDF，sharp 引擎，扫描件处理）
 *
 * 用法：
 *   node cli.js <input> <target> [-o output] [-f]
 *     -o, --output  指定输出路径（默认：输入同目录 + 新扩展名）
 *     -f, --force   覆盖已存在的输出文件
 *     -h, --help    显示帮助
 *
 * 示例：
 *   node cli.js 判决书.html md
 *   node cli.js 合同.docx txt -o 合同.txt
 *   node cli.js 判决书.pdf txt -o 判决书.txt
 *   node cli.js data.csv json
 *   node cli.js 扫描件.png pdf -o 扫描件.pdf
 */
const fs = require("fs");
const fsp = require("fs/promises");
const path = require("path");
const zlib = require("zlib");
const { pathToFileURL } = require("url");

const { htmlToMarkdown, markdownToHtml, csvToJsonObjects, jsonToCsv } = require("./text-conversion");
const { convertRasterImage } = require("./image-conversion");
const sharp = require("sharp");
const mammoth = require("mammoth");

// ---------- 格式分类 ----------
const TEXT_INPUT = new Set(["txt", "md", "markdown", "html", "htm", "json", "csv", "log", "xml", "yaml", "yml"]);
const TEXT_TARGETS = ["txt", "md", "html", "json", "csv"];
const DOCUMENT_INPUT = new Set(["docx"]);
const DOCUMENT_TARGETS = ["txt", "md", "html"];
const PDF_INPUT = new Set(["pdf"]);
const PDF_TARGETS = ["txt"];
const IMAGE_INPUT = new Set(["jpg", "jpeg", "png", "webp", "gif", "avif", "tif", "tiff", "bmp", "heic", "heif"]);
const IMAGE_TARGETS = ["png", "jpg", "webp", "gif", "avif", "tiff", "pdf"];

const HELP = `format-converter — 法律文书格式转换

用法: node cli.js <输入文件> <目标格式> [选项]

目标格式:
  文本类: ${TEXT_TARGETS.join(", ")}
  文档类(docx): ${DOCUMENT_TARGETS.join(", ")}
  PDF类: ${PDF_TARGETS.join(", ")}
  图片类: ${IMAGE_TARGETS.join(", ")}

选项:
  -o, --output <路径>  指定输出文件路径
  -f, --force          覆盖已存在的输出文件
  -h, --help           显示本帮助
`;

// ---------- 工具 ----------
function extOf(filePath) {
  return path.extname(filePath).slice(1).toLowerCase();
}

function baseName(filePath) {
  return path.basename(filePath, path.extname(filePath));
}

function targetExtFor(target) {
  return target === "jpg" ? "jpg" : target;
}

function normalizeExt(ext) {
  if (ext === "jpeg") return "jpg";
  if (ext === "htm") return "html";
  if (ext === "markdown") return "md";
  if (ext === "tif") return "tiff";
  return ext;
}

function escapeHtml(value) {
  return String(value).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function htmlToText(html) {
  return String(html)
    .replace(/<script[\s\S]*?<\/script>/gi, "")
    .replace(/<style[\s\S]*?<\/style>/gi, "")
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/(p|div|h[1-6]|li|tr|pre|blockquote)>/gi, "\n")
    .replace(/<[^>]+>/g, "")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

function parseJsonText(text) {
  try {
    return JSON.parse(text);
  } catch {
    // 尝试提取首尾 ```json 围栏
    const fenced = text.match(/```(?:json)?\s*([\s\S]*?)```/);
    if (fenced) return JSON.parse(fenced[1].trim());
    throw new Error("JSON 解析失败");
  }
}

// ---------- 文本转换（与 server.js convertText 一致的语义） ----------
async function convertText(inputPath, outputPath, target) {
  const raw = await fsp.readFile(inputPath, "utf8");
  const source = normalizeExt(extOf(inputPath));
  let converted = raw;

  if (target === "txt") {
    if (source === "html") converted = htmlToText(raw);
    else if (source === "json") converted = JSON.stringify(parseJsonText(raw), null, 2);
  } else if (target === "html") {
    if (source === "md") converted = markdownToHtml(raw);
    else if (source !== "html") {
      converted = `<!doctype html>
<html lang="zh-CN">
<head><meta charset="utf-8"><title>Converted text</title></head>
<body><pre>${escapeHtml(raw)}</pre></body>
</html>`;
    }
  } else if (target === "md") {
    if (source === "html") converted = htmlToMarkdown(raw);
    else if (source === "json") converted = "```json\n" + JSON.stringify(parseJsonText(raw), null, 2) + "\n```\n";
  } else if (target === "json") {
    if (source === "json") converted = JSON.stringify(parseJsonText(raw), null, 2);
    else if (source === "csv") converted = JSON.stringify(csvToJsonObjects(raw), null, 2);
    else converted = JSON.stringify({ text: raw }, null, 2);
  } else if (target === "csv") {
    if (source === "json") converted = jsonToCsv(raw);
    else converted = raw.split(/\r?\n/).map((line) => `"${line.replaceAll('"', '""')}"`).join("\n");
  }

  await fsp.writeFile(outputPath, converted, "utf8");
  return { category: "text", source, target };
}

// ---------- 图片转换 ----------
async function convertImage(inputPath, outputPath, target) {
  if (target === "pdf") {
    await convertImageToPdf(inputPath, outputPath);
    return { category: "image", source: normalizeExt(extOf(inputPath)), target, warnings: [] };
  }
  const result = await convertRasterImage(inputPath, outputPath, target === "jpg" ? "jpeg" : target);
  return { category: "image", source: normalizeExt(extOf(inputPath)), target, warnings: result.warnings };
}

// 单图 → PDF（手写 PDF 对象，zlib 内置，与 flyingmouse-format 的 convertImagesToPdf 同构）
function pdfAscii(value) {
  return Buffer.from(String(value), "latin1");
}

function pdfNumber(value) {
  const n = Number(value);
  return Number.isInteger(n) ? String(n) : n.toFixed(2);
}

async function readImageForPdf(inputPath) {
  const { data, info } = await sharp(inputPath, { limitInputPixels: 50_000_000 })
    .rotate()
    .flatten({ background: "#ffffff" })
    .toColorspace("srgb")
    .removeAlpha()
    .raw()
    .toBuffer({ resolveWithObject: true });

  const channels = info.channels || 3;
  let rgb = data;
  if (channels !== 3) {
    rgb = Buffer.alloc(info.width * info.height * 3);
    for (let pixel = 0; pixel < info.width * info.height; pixel += 1) {
      rgb[pixel * 3] = data[pixel * channels];
      rgb[pixel * 3 + 1] = data[pixel * channels + 1];
      rgb[pixel * 3 + 2] = data[pixel * channels + 2];
    }
  }

  return { width: info.width, height: info.height, data: zlib.deflateSync(rgb) };
}

async function convertImageToPdf(inputPath, outputPath) {
  const image = await readImageForPdf(inputPath);
  const pageWidth = Math.max(1, image.width);
  const pageHeight = Math.max(1, image.height);

  const objects = [];
  const addObject = (number, content) => {
    objects.push({ number, content: Buffer.isBuffer(content) ? content : pdfAscii(content) });
  };

  addObject(1, "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
  addObject(2, `2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n`);
  addObject(3, `3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${pdfNumber(pageWidth)} ${pdfNumber(pageHeight)}] /Resources << /XObject << /Im1 4 0 R >> >> /Contents 5 0 R >>
endobj
`);
  addObject(4, Buffer.concat([
    pdfAscii(`4 0 obj
<< /Type /XObject /Subtype /Image /Width ${image.width} /Height ${image.height} /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /FlateDecode /Length ${image.data.length} >>
stream
`),
    image.data,
    pdfAscii("\nendstream\nendobj\n")
  ]));
  const content = `q
${pdfNumber(pageWidth)} 0 0 ${pdfNumber(pageHeight)} 0 0 cm
/Im1 Do
Q
`;
  addObject(5, `5 0 obj
<< /Length ${Buffer.byteLength(content, "latin1")} >>
stream
${content}endstream
endobj
`);

  objects.sort((a, b) => a.number - b.number);
  const chunks = [pdfAscii("%PDF-1.4\n")];
  const offsets = [0];
  for (const object of objects) {
    offsets[object.number] = Buffer.concat(chunks).length;
    chunks.push(object.content);
  }

  const body = Buffer.concat(chunks);
  let xref = `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (let number = 1; number <= objects.length; number += 1) {
    xref += `${String(offsets[number]).padStart(10, "0")} 00000 n \n`;
  }
  const trailer = `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${body.length}\n%%EOF\n`;
  await fsp.writeFile(outputPath, Buffer.concat([body, pdfAscii(xref + trailer)]));
}

// ---------- 文档转换（docx，mammoth 纯 JS） ----------
async function convertDocument(inputPath, outputPath, target) {
  if (target === "txt") {
    const result = await mammoth.extractRawText({ path: inputPath });
    const text = (result.value || "").trim();
    if (!text) throw new Error("docx 转文本失败，未提取到任何内容。");
    await fsp.writeFile(outputPath, `${text}\n`, "utf8");
  } else if (target === "md") {
    const result = await mammoth.convertToHtml({ path: inputPath });
    const html = result.value || "";
    const markdown = createMarkdownFromHtml(html).trim();
    if (!markdown) throw new Error("docx 转 Markdown 失败，未提取到任何内容。");
    await fsp.writeFile(outputPath, `${markdown}\n`, "utf8");
  } else if (target === "html") {
    const result = await mammoth.convertToHtml({ path: inputPath });
    const html = result.value || "";
    if (!html.trim()) throw new Error("docx 转 HTML 失败，未提取到任何内容。");
    await fsp.writeFile(outputPath, html, "utf8");
  }
  return { category: "document", source: "docx", target };
}

function createMarkdownFromHtml(html) {
  const { createTurndownService } = require("./text-conversion");
  return createTurndownService().turndown(html);
}

// ---------- PDF 转换（pdfjs-dist 纯 JS） ----------
let cachedPdfjs = null;
async function loadPdfjs() {
  if (cachedPdfjs) return cachedPdfjs;
  const packageRoot = path.dirname(require.resolve("pdfjs-dist/package.json"));
  const spec = pathToFileURL(path.join(packageRoot, "legacy", "build", "pdf.mjs")).href;
  let mod;
  try {
    mod = await import(spec);
  } catch {
    mod = await import(pathToFileURL(path.join(packageRoot, "legacy", "build", "pdf.js")).href);
  }
  cachedPdfjs = mod.default || mod;
  return cachedPdfjs;
}

async function convertPdfToText(inputPath, outputPath) {
  const pdfjsLib = await loadPdfjs();
  const data = new Uint8Array(await fsp.readFile(inputPath));
  const loadingTask = pdfjsLib.getDocument({
    data,
    disableFontFace: true,
    useSystemFonts: true,
    isEvalSupported: false
  });
  const pdf = await loadingTask.promise;
  const pageTexts = [];
  try {
    for (let pageNumber = 1; pageNumber <= pdf.numPages; pageNumber += 1) {
      const page = await pdf.getPage(pageNumber);
      const content = await page.getTextContent();
      const text = content.items.map((item) => item.str || "").join(" ");
      pageTexts.push(text.replace(/\s+/g, " ").trim());
    }
  } finally {
    await loadingTask.destroy().catch(() => {});
  }
  await fsp.writeFile(outputPath, `${pageTexts.join("\n\n")}\n`, "utf8");
  return { category: "pdf", source: "pdf", target: "txt", pages: pdf.numPages };
}

// ---------- 主流程 ----------
async function main(argv) {
  const args = [...argv];
  const opts = { output: null, force: false };

  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "-h" || a === "--help") return console.log(HELP);
    if (a === "-f" || a === "--force") { opts.force = true; args.splice(i, 1); i--; continue; }
    if (a === "-o" || a === "--output") {
      opts.output = args[i + 1];
      if (!opts.output) throw new Error(`缺少 ${a} 参数值`);
      args.splice(i, 2); i--; continue;
    }
    if (a.startsWith("-")) throw new Error(`未知选项: ${a}`);
  }

  if (args.length < 2) {
    console.log(HELP);
    process.exitCode = args.length === 0 ? 0 : 2;
    return;
  }

  const [inputPath, targetRaw] = args;
  if (!fs.existsSync(inputPath)) throw new Error(`输入文件不存在: ${inputPath}`);

  const target = normalizeExt(targetRaw.toLowerCase());
  const sourceExt = extOf(inputPath);
  const isText = TEXT_INPUT.has(sourceExt) || TEXT_INPUT.has(normalizeExt(sourceExt));
  const isDocument = DOCUMENT_INPUT.has(sourceExt);
  const isPdf = PDF_INPUT.has(sourceExt);
  const isImage = IMAGE_INPUT.has(sourceExt);

  if (!isText && !isDocument && !isPdf && !isImage) {
    throw new Error(`不支持的输入格式: .${sourceExt}（支持 docx / pdf / 文本: ${[...TEXT_INPUT].join(",")} / 图片: ${[...IMAGE_INPUT].join(",")}）`);
  }

  const category = isImage ? "image" : isDocument ? "document" : isPdf ? "pdf" : "text";
  const targets = category === "image" ? IMAGE_TARGETS : category === "document" ? DOCUMENT_TARGETS : category === "pdf" ? PDF_TARGETS : TEXT_TARGETS;
  if (!targets.includes(target)) {
    throw new Error(`目标格式 ${target} 不支持 ${category} 类输入（可用: ${targets.join(", ")}）`);
  }

  const outputPath = opts.output || path.join(path.dirname(inputPath), `${baseName(inputPath)}.${targetExtFor(target)}`);
  if (fs.existsSync(outputPath) && !opts.force) {
    throw new Error(`输出文件已存在: ${outputPath}（使用 -f 覆盖）`);
  }

  const result = category === "image"
    ? await convertImage(inputPath, outputPath, target)
    : category === "document"
      ? await convertDocument(inputPath, outputPath, target)
      : category === "pdf"
        ? await convertPdfToText(inputPath, outputPath)
        : await convertText(inputPath, outputPath, target);

  console.log(`✓ ${path.basename(inputPath)} → ${path.basename(outputPath)} (${result.source} → ${target})`);
  if (result.pages) console.log(`  共 ${result.pages} 页`);
  if (result.warnings?.length) {
    for (const w of result.warnings) console.log(`  ⚠ ${w.messages.zhCN}`);
  }
}

main(process.argv.slice(2)).catch((err) => {
  console.error(`✗ ${err.message}`);
  process.exitCode = 1;
});
