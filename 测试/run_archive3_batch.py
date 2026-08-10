# -*- coding: utf-8 -*-
"""archive3 批量脱敏脚本：逐份文书 → 独立文件夹（阶段一规则层 + 阶段二语义层）。

用法: python3 run_archive3_batch.py [--docs 01,02,..] [--only-stage1]
"""
import glob
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(ROOT, "_corpus")
TOOL = "/Users/lirunyi/Downloads/法律文书脱敏工具/legal-document-desensitizer/desensitize.py"


def doc_kind(name: str) -> str:
    if "银行流水" in name:
        return "bank"
    if name.endswith(".pdf"):
        return "pdf"
    return "txt"


def main():
    only_stage1 = "--only-stage1" in sys.argv
    doc_filter = None
    if "--docs" in sys.argv:
        doc_filter = sys.argv[sys.argv.index("--docs") + 1].split(",")

    files = sorted(glob.glob(os.path.join(CORPUS, "*")))
    results = []
    for i, src in enumerate(files, 1):
        base = os.path.basename(src)
        num = base.split("_", 1)[0]
        if doc_filter and num not in doc_filter:
            continue
        name = os.path.splitext(base)[0]
        out_dir = os.path.join(ROOT, f"{num}_{name}")
        os.makedirs(out_dir, exist_ok=True)
        kind = doc_kind(base)

        # ---------- 阶段一：规则层 ----------
        if kind == "pdf":
            out1 = os.path.join(out_dir, f"{name}_desensitized.pdf")
            cmd = [sys.executable, TOOL, "mask", "-f", src, "-o", out1,
                   "--pdf-redact", "--review",
                   "--save-mapping", os.path.join(out_dir, "映射表_阶段一.md")]
            if "银行流水" in base:
                cmd.append("--table-aware")
        else:
            out1 = os.path.join(out_dir, f"{name}_desensitized.txt")
            cmd = [sys.executable, TOOL, "mask", "-f", src, "-o", out1,
                   "--review", "--save-mapping", os.path.join(out_dir, "映射表_阶段一.md")]
        r1 = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
        ok1 = r1.returncode == 0 and os.path.exists(out1)
        stage1_log = os.path.join(out_dir, "阶段一_日志.txt")
        with open(stage1_log, "w", encoding="utf-8") as f:
            f.write((r1.stdout or "") + "\n" + (r1.stderr or ""))

        # ---------- 阶段二：语义层 ----------
        ok2 = True
        stage2_log = os.path.join(out_dir, "阶段二_日志.txt")
        if ok1 and not only_stage1:
            mapping = os.path.join(out_dir, "映射表_阶段一.md")
            # PDF：语义层读取"掩码文本侧车"（涂黑 PDF 文本层重排后
            # 无法逐字节对齐，侧车保存了精确的掩码文本）
            out2 = os.path.join(out_dir, f"{name}_语义层.txt")
            sidecar = os.path.join(out_dir, f"{name}_desensitized_掩码文本.txt")
            sem_src = sidecar if (kind == "pdf" and os.path.exists(sidecar)) else out1
            cmd2 = [sys.executable, TOOL, "semantic", "-f", sem_src, "-m", mapping,
                    "-o", out2,
                    "--save-mapping", os.path.join(out_dir, "映射表_合并.md")]
            r2 = subprocess.run(cmd2, capture_output=True, text=True, timeout=3600)
            ok2 = r2.returncode == 0 and os.path.exists(out2)
            if not ok2 and "未能从映射表解析出任何条目" in (r2.stderr or "") + (r2.stdout or ""):
                # 模板类文书无敏感信息 → 映射表为空，属正常情况
                ok2 = True
                with open(os.path.join(out_dir, "阶段二_说明.txt"), "w",
                          encoding="utf-8") as f:
                    f.write("该文书为模板/无敏感信息，阶段一映射表为空，"
                            "语义层无需执行。\n")
            with open(stage2_log, "w", encoding="utf-8") as f:
                f.write((r2.stdout or "") + "\n" + (r2.stderr or ""))
        elif not ok1:
            with open(stage2_log, "w", encoding="utf-8") as f:
                f.write("阶段一失败，跳过阶段二")

        # ---------- 脱敏报告 ----------
        report = os.path.join(out_dir, "脱敏报告.md")
        with open(report, "w", encoding="utf-8") as f:
            f.write(f"# 脱敏报告：{base}\n\n")
            f.write(f"- 源文件：`_corpus/{base}`\n")
            f.write(f"- 阶段一（规则层）：{'✅ 成功' if ok1 else '❌ 失败'}\n")
            f.write(f"- 阶段二（语义层）：{'✅ 成功' if ok2 else '⏭️ 跳过/失败'}\n")
            f.write(f"- 输出目录：`archive3/{num}_{name}/`\n\n")
            if ok1:
                tail1 = (r1.stdout or "").strip().splitlines()
                f.write("## 阶段一日志（尾部）\n\n```\n" + "\n".join(tail1[-12:]) + "\n```\n")
            if ok2 and 'r2' in dir():
                tail2 = (r2.stdout or "").strip().splitlines()
                f.write("## 阶段二日志（尾部）\n\n```\n" + "\n".join(tail2[-12:]) + "\n```\n")
        results.append({"num": num, "name": base, "stage1": "ok" if ok1 else "fail",
                        "stage2": "ok" if ok2 else "skip/fail"})
        print(f"[{num}] {base} → stage1={'ok' if ok1 else 'FAIL'} stage2={'ok' if ok2 else 'skip'}")

    with open(os.path.join(ROOT, "batch_manifest.json"), "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()
