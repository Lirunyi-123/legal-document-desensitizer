#!/usr/bin/env node
/**
 * format-converter 端到端自测
 * 运行: node test-cli.js
 */
const { execFileSync } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

const CLI = path.join(__dirname, "cli.js");
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "format-converter-test-"));
let pass = 0;
let fail = 0;

function run(args) {
  return execFileSync(process.execPath, [CLI, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
}

function check(name, cond, extra = "") {
  if (cond) { pass++; console.log(`  ✓ ${name}`); }
  else { fail++; console.error(`  ✗ ${name} ${extra}`); }
}

async function writeTestImage(file, format, size = 32) {
  const sharp = require("sharp");
  await sharp({
    create: {
      width: size,
      height: Math.max(8, Math.round(size * 0.75)),
      channels: 4,
      background: { r: 200, g: 100, b: 50, alpha: 1 }
    }
  })[format]().toFile(file);
}

async function main() {
try {
  console.log("== 文本转换 ==");
  const mdSrc = path.join(tmp, "sample.md");
  fs.writeFileSync(mdSrc, "# 标题\n\n- 项目甲\n- 项目乙\n\n| 列1 | 列2 |\n|---|---|\n| a | b |\n", "utf8");

  // md -> html
  const htmlOut = path.join(tmp, "sample.html");
  run([mdSrc, "html", "-o", htmlOut]);
  const html = fs.readFileSync(htmlOut, "utf8");
  check("md→html 包含 <h1>", html.includes("<h1"));
  check("md→html 包含表格", html.includes("<table"));

  // html -> md（表格往返）
  const mdBack = path.join(tmp, "sample-back.md");
  run([htmlOut, "md", "-o", mdBack]);
  const md2 = fs.readFileSync(mdBack, "utf8");
  check("html→md 表格保留", md2.includes("| a | b |"));

  // csv -> json
  const csvSrc = path.join(tmp, "data.csv");
  fs.writeFileSync(csvSrc, '姓名,金额\n"张三,李四",100\n王五,"200,500"\n', "utf8");
  const jsonOut = path.join(tmp, "data.json");
  run([csvSrc, "json", "-o", jsonOut]);
  const parsed = JSON.parse(fs.readFileSync(jsonOut, "utf8"));
  check("csv→json 字段数", Array.isArray(parsed) && parsed.length === 2);
  check("csv→json 转义引号", parsed[0]["姓名"] === "张三,李四" && parsed[1]["金额"] === "200,500");

  // json -> csv
  const csvBack = path.join(tmp, "data-back.csv");
  run([jsonOut, "csv", "-o", csvBack]);
  const csvText = fs.readFileSync(csvBack, "utf8");
  check("json→csv 保留表头", csvText.startsWith('"姓名","金额"'));

  // html -> txt
  const txtOut = path.join(tmp, "sample.txt");
  run([htmlOut, "txt", "-o", txtOut]);
  check("html→txt 去除标签", !fs.readFileSync(txtOut, "utf8").includes("<"));

  console.log("== 图片转换 ==");
  const pngSrc = path.join(tmp, "src.png");
  await writeTestImage(pngSrc, "png");

  const jpgOut = path.join(tmp, "out.jpg");
  run([pngSrc, "jpg", "-o", jpgOut]);
  const sharp = require("sharp");
  const jpgMeta = await sharp(jpgOut).metadata();
  check("png→jpg 尺寸保持", jpgMeta.width === 32 && jpgMeta.height === 24, `(${jpgMeta.width}x${jpgMeta.height})`);

  const pdfOut = path.join(tmp, "out.pdf");
  run([pngSrc, "pdf", "-o", pdfOut]);
  check("png→pdf 文件生成", fs.statSync(pdfOut).size > 100);

  const gifSrc = path.join(tmp, "anim.gif");
  await writeTestImage(gifSrc, "gif", 16);
  const pngOut2 = path.join(tmp, "anim.png");
  run([gifSrc, "png", "-o", pngOut2]);
  check("gif→png 转换成功", fs.statSync(pngOut2).size > 100);
  const tiffOut = path.join(tmp, "anim.tiff");
  run([gifSrc, "tiff", "-o", tiffOut]);
  check("gif→tiff 转换成功", fs.statSync(tiffOut).size > 100);

  console.log("== 文档转换 (docx) ==");
  const { PDFDocument } = await import("pdf-lib");
  const { Document: DocxDocument, Packer, Paragraph, TextRun } = await import("docx");

  // 用 docx 库生成真实 .docx
  const docxPath = path.join(tmp, "contract.docx");
  const doc = new DocxDocument({
    sections: [{
      children: [
        new Paragraph({ children: [new TextRun("借款合同")] }),
        new Paragraph({ children: [new TextRun("甲方：张三，身份证号 110101199001011234。")] }),
        new Paragraph({ children: [new TextRun("借款金额人民币拾万元整。")] })
      ]
    }]
  });
  const docxBuf = await Packer.toBuffer(doc);
  fs.writeFileSync(docxPath, docxBuf);
  run([docxPath, "txt", "-o", path.join(tmp, "contract.txt")]);
  const contractTxt = fs.readFileSync(path.join(tmp, "contract.txt"), "utf8");
  check("docx→txt 提取正文", contractTxt.includes("借款合同") && contractTxt.includes("张三"), contractTxt.slice(0, 60));
  run([docxPath, "md", "-o", path.join(tmp, "contract.md")]);
  const contractMd = fs.readFileSync(path.join(tmp, "contract.md"), "utf8");
  check("docx→md 提取正文", contractMd.includes("借款合同"));

  // 用 pdf-lib 生成真实 .pdf（标准字体不含中文字形，用英文验证提取管线）
  const pdfDoc = await PDFDocument.create();
  const pdfPage = pdfDoc.addPage([400, 200]);
  pdfPage.drawText("Civil Judgment", { x: 50, y: 150, size: 18 });
  pdfPage.drawText("Defendant: Li Si", { x: 50, y: 110, size: 12 });
  const pdfBuf = await pdfDoc.save();
  const pdfPath = path.join(tmp, "judgment.pdf");
  fs.writeFileSync(pdfPath, pdfBuf);
  run([pdfPath, "txt", "-o", path.join(tmp, "judgment.txt")]);
  const judgmentTxt = fs.readFileSync(path.join(tmp, "judgment.txt"), "utf8");
  check("pdf→txt 提取文本", judgmentTxt.includes("Civil Judgment"), judgmentTxt.slice(0, 60));

  console.log("== 错误处理 ==");
  const missing = path.join(tmp, "nope.docx");
  try {
    run([missing, "txt"]);
    check("不存在的文件报错", false);
  } catch (e) { check("不存在的文件报错", /输入文件不存在/.test(e.stderr)); }

  try {
    run([mdSrc, "mp4"]);
    check("不支持目标格式报错", false);
  } catch (e) { check("不支持目标格式报错", /目标格式 mp4 不支持/.test(e.stderr)); }

  console.log(`\n结果: ${pass} 通过, ${fail} 失败`);
  return fail ? 1 : 0;
} finally {
  fs.rmSync(tmp, { recursive: true, force: true });
}
}

main().then((code) => process.exit(code)).catch((err) => { console.error(err); process.exit(1); });
