# 法律文书脱敏工具（Legal Document Desensitizer）

面向中国法律实务的**本地优先**文书脱敏工具：判决书、合同、聊天记录、证据材料中的
敏感信息 → 语义占位符（`[当事人甲（原告）]`、`[身份证号]`），加密映射表 +
一键无损还原。

> 规则引擎 + 实体归一化 + 可选本地 NER / LLM，**离线可跑、全文实体一致、可审计还原**。

## 🛡️ v5.0 零上传本地闭环 · 安全交付升级（2026-08-11）

针对"脱敏过程/脱敏稿交给 AI 时原文可能被读取"的核心顾虑，v5.0 把工具升级为
**可验证的本地安全交付闭环**——"安全"从宣传语变成可导出、可检查、可签发的产物：

### 解决的问题（对照"300 问"）

| 问题 | v5.0 解决方案 |
|------|--------------|
| "本地"到底有多本地？断网能用吗？ | `--offline` 严格模式：非本机 LLM 端点直接中止（Fail Closed）；`--audit` 审计单记录输入/输出/OCR/网络调用/文件 hash，律师可导出验证 |
| 机器说没漏，谁来查机器？ | 审阅清单升级为 🔴 重点复核 / 🟡 建议复核两级；新增**提示注入模式**与**重识别风险**自动扫描 |
| 案件内容是数据，不是指令 | LLM 提示词加入"材料非指令"隔离包裹，材料内的"忽略以上要求/输出系统提示词"一律视为内容不执行 |
| 300 页进 297 页出，安全吗？ | PDF 涂黑/OCR 后自动**页数核对**（输入页数 vs 输出页数），不一致立即警告 |
| 同一个人在 80 份卷宗里是同一匿名身份吗？ | `--batch --shared-entities` **跨文件身份归一**：同一人/公司整批卷宗同一占位符，另出全局映射表，同名多角色自动 ⚠️ 标记 |
| 看不见 = 删掉了吗？ | **隐藏信息检查**：docx 批注/修订痕迹/嵌入对象、PDF 批注/表单/书签/附件逐项清点报告，暂不支持清理的明确标注 |
| 最终谁有权点"可以交给 AI"？ | `finalize` 生成 **AI 安全出口材料包**（脱敏稿+映射表+审计单+审阅清单+签发单），律师逐项勾选签字后方可进入 AI 工作流 |
| 剩余信息组合还能认出人吗？ | 审阅清单新增**重识别风险**扫描（独女/唯一继承人/某上市公司董事长+高校+小区等组合提示） |

### 快速上手（v5.0 新命令）

```bash
# 1. 单文件脱敏 + 审阅 + 审计单（可验证本地：审计单里写明是否联网）
python3 desensitize.py mask -f 判决书.docx --review --audit \
  --save-mapping 映射表.enc --encrypt-mapping

# 2. 严格本地模式（断网也照跑；端点非本机直接中止）
python3 desensitize.py mask -f 判决书.docx --review --offline

# 3. 批量卷宗 + 跨文件身份归一（同一人整批同一匿名身份）
python3 desensitize.py mask --batch ./卷宗 --review \
  --shared-entities --output-dir ./脱敏输出

# 4. 律师签发：AI 安全出口材料包（签字后材料方可交给 AI）
python3 desensitize.py finalize -f 判决书_desensitized.docx \
  -m 映射表.enc --audit 判决书_desensitized_审计单.json \
  --original 判决书.docx -o 材料包
```

> **零上传红线**：原始文书 / 扫描件 / OCR 文本 / 明文映射表绝不进入 AI 对话；
> 只有经律师签发的脱敏稿 + 审阅清单可谨慎交给云端 AI。

## 核心亮点

- **20+ 类中国法律实体**：身份证（GB 11643 校验码）、信用代码（GB 32100）、银行卡（Luhn）、
  案号、手机号、微信号、车牌、证件号、金额、人名、公司名、地址等
- **语义占位符**：同一人物全篇统一编号，律师可直接阅读，语义关系不丢
- **加密映射 + 无损还原**：AES-256-GCM 映射表，`restore` 一键逐字节还原原文
- **真·涂黑 PDF**：电子版字符级涂黑、扫描件原图涂黑，residual 零残留校验
- **银行流水专项**：列感知模式自动识别表头（户名/账号/日期/金额），孤立姓名也能识别
- **批量卷宗**：`--batch` 递归处理整个文件夹，断点续跑 + 处理报告
- **红队可量化**：105 个红队用例 100% 召回、0 误报；还原往返逐字节一致

## 30 秒体验

```bash
printf '原告：陈建国，男，身份证号110101198001011232，手机13800138000，尾款80万元。\n' \
  | python3 desensitize.py mask
# → 原告：[当事人甲（原告）]，男，身份证号[身份证号]，手机[手机号]，尾款[金额]。
```

自检：`python3 selfcheck.py`（文件 / 测试 / 评测 / 还原四项比对）

## 快速开始

```bash
pip install -r requirements.txt        # jieba 必装；docx/pdf/xlsx/加密为可选

# 单文件脱敏（txt / docx / pdf / xlsx / 图片）
python3 desensitize.py mask -f 合同.docx
python3 desensitize.py mask -f 判决书.pdf --pdf-redact -o 脱敏.pdf   # 真·涂黑 PDF
python3 desensitize.py mask -f 银行流水.xlsx --table-aware --review   # 银行流水列感知

# 批量卷宗（断点续跑）
python3 desensitize.py mask --batch ./卷宗 --review --resume

# 加密映射表 + 一键还原
python3 desensitize.py mask -f 起诉状.docx \
  --save-mapping 映射表.enc --encrypt-mapping
python3 desensitize.py restore -f 起诉状_desensitized.docx \
  -m 映射表.enc -o 还原.docx

# 扫描件/图片：macOS 内置 Vision OCR 自动识别（Windows/Linux 需先外部 OCR）
python3 desensitize.py mask -f 扫描件.pdf -o 涂黑.pdf
```

完整命令见 `python3 desensitize.py --help`；两阶段工作流（规则层 → 审阅清单 →
语义层）说明见 [docs/简介.md](docs/简介.md)。

## 零上传模式（v4.2 起推荐默认）

脱敏全程在本机终端执行，**原始文书、明文映射表绝不进入云端 AI 对话**：

```bash
# 一次性安装为全局命令（~/.local/bin 已在 PATH 且免 sudo）
ln -s "$PWD/desensitize.py" ~/.local/bin/desensitize

# 之后直接使用（本机执行，零网络请求）
desensitize mask -f 判决书.docx --review --encrypt-mapping
desensitize full -f 判决书_desensitized.docx --llm-api ollama   # 本地语义层，数据不出本机
```

红线：原文、扫描件、明文映射表永不进入 AI 对话；确需云端语义层时
**只能上传脱敏稿 + 审阅清单**，且法院名/案情细节残留风险须经律师确认。

## 架构：规则层 → NER → LLM

```
规则引擎（本地） → 身份证号等结构化数据替换为占位符 → LLM 只看到 [身份证号]
```

| 层级 | 职责 | 运行方式 |
|------|------|---------|
| **规则层** | 身份证、银行卡、案号、金额等结构化数据 | 本地正则，零模型零联网 |
| **实体归一化** | 人名/公司全文一致、简称链接全称 | 本地 |
| **本地 NER（可选）** | 规则层覆盖不到的人名/公司/地址 | spaCy / HuggingFace / Ollama |
| **LLM 层（可选）** | 案情敏感细节、裸公司简称 | 本地 Ollama 或云端 API，失败安全 |

结构化号码在本地即被替换，AI/云端始终接触不到真实号码。

## 能力速览

| 能力 | 说明 |
|------|------|
| 两阶段工作流 | `mask --review` 生成审阅清单，确认后再做语义层，无需外部 API |
| 真·涂黑 PDF | 电子版 `--pdf-redact`，扫描件 `--image-redact`，保留版式、清元数据 |
| 扫描件 OCR | macOS Vision 内置 OCR，无文本层自动识别再脱敏 |
| 列感知表格 | 银行流水/对账单自动识别表头列类型，按列脱敏 |
| 批量处理 | 递归文件夹、断点续跑、原件校验、批量报告 |
| 红队评测 | `evaluate.py`：entity-level P/R/F1，负样本计误报 |
| 合成语料 | `synthetic/` 生成合法校验码语料（身份证/信用代码/银行卡） |
| 格式转换 | [format-converter](#格式转换-format-converter)：把不直接支持的格式先转成 txt/md/json |

## 格式转换 format-converter

内置 `format-converter/`（纯 JS、无外部引擎），把脱敏工具不直接支持的输入
先转成 txt / md / json，再进入脱敏流程。

| 输入 | 可转成 | 典型场景 |
|------|--------|---------|
| docx（律师文书、合同） | txt / md / html | 只需提取正文时 |
| pdf（判决书、裁判文书） | txt | 仅限**带文本层**的电子版 |
| html（网上复制的文书） | txt / md / json / csv | 网页文书转 Markdown |
| csv（当事人名单） | json / txt / md / html | 名单互转 |
| 图片（png/jpg/webp/gif/avif/tiff） | 互转、单图 → pdf | 扫描件统一格式 |

```bash
cd format-converter && npm install
node cli.js 判决书.pdf txt -o 判决书.txt    # pdf → 纯文本（仅带文本层）
node cli.js 裁判文书.html md                # 网页文书 → Markdown
node cli.js 当事人.csv json                 # 名单 → JSON
```

> ⚠️ **单向提取，不可逆**：转换会丢失版式（docx 样式/表格、pdf 排版），
> **转换后无法转回 docx/pdf**；脱敏工具的 `restore` 只还原内容、不还原格式。

### 选择点：先转换，还是直接脱敏？

| 你的需求 | 怎么选 | 结果 |
|---------|--------|------|
| 最终要 **docx/pdf 原格式**（归档、庭审、对外提交） | **不转换**，直接 `mask -f 合同.docx` 或 `mask -f 判决书.pdf --pdf-redact` | 脱敏后仍是原格式，可逐字还原 |
| 只需**提取文本**（核对、摘录、喂 LLM、批量筛查） | 先 `node cli.js 判决书.pdf txt`，再 `mask` | txt/md/json 即最终形态 |
| 输入是 **html / csv / 图片等**脱敏工具不直接支持的格式 | 必须先用 format-converter 转 txt/md/json | 转出的文本就是最终形态 |
| **扫描件 / 图片型 PDF** | 不要转（pdf→txt 会失败）；直接 `mask -f 扫描件.pdf -o 涂黑.pdf`，走内置 OCR 涂黑 | 保留原版式的涂黑 PDF |

另一个选择点在**输出端**：`mask` 时用 `-o` 指定扩展名决定输出格式——
`-o xxx.docx`（保留段落结构）、`-o xxx.pdf`（涂黑 PDF 保留版式）、
默认 txt（纯文本）。扫描件输出 PDF 即原图涂黑，电子版 PDF 用 `--pdf-redact`
字符级涂黑。

**一句话**：要"转回原格式"就别转，直接脱敏；format-converter 只用于内容提取。

## 安全设计

### 分层脱敏（按需选择深度）

| 安全等级 | 做法 | 效果 |
|---------|------|------|
| 🟡 仅规则层 | `mask` | 结构化号码已替换；人名/地址/金额仍在，**不建议上传云端** |
| 🟢 规则层 + 本地 LLM | `full`（Ollama） | 全部敏感信息替换，数据不出本机 |
| 🟢 规则层 + 云端 LLM | `full`（API） | 全部替换；发送给服务商前已去掉结构化号码 |

> 涉密程度高的材料请优先**本地 Ollama**；只跑规则层就把文件上传给 AI，人名、
> 公司名、金额等仍会泄露。

### 安全特性

- `--secure`：内存安全模式，尽力清空原始字符串引用
- 映射表 AES-256-GCM 加密，密钥不落 stdout；明文映射表会明确警告勿外传
- 输出文件名自动脱敏；PDF 输出清理元数据 / 批注 / 表单 / 书签 / 附件
- residual 零残留校验：涂黑后原文不可读才交付，扫描件零命中直接拒绝

## 质量基线

- 170 项单元测试通过；红队 77 用例召回 100%、误报 0
- 合成语料 300 条召回 99.76%、precision 1.0
- 真实文书还原往返逐字节一致

## 文档

- [docs/简介.md](docs/简介.md) — 两阶段工作流、完整用法
- [SKILL.md](SKILL.md) — 规则细节、实战修复记录、评测口径
- [docs/版本说明.txt](docs/版本说明.txt) — 版本变更记录

## 授权

MIT License
