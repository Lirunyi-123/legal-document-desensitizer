# 法律文书脱敏工具 (Legal Document Desensitizer)

规则引擎 + EntityResolver 实体归一化 + 本地 NER + LLM 混合脱敏工具，专为中国法律文书设计。

> **v2.2 新特性**：GB 11643/GB 32100 校验码 | 一键还原 restore | 红队评测 evaluate | 本地 NER 接入
> **v2.3 新特性**：full 完整脱敏流水线（规则层+本地LLM）| LLM 补充映射合并还原 | evaluate --llm 评测
> **v2.4 新特性**：裸人名 + 无层级地址进规则层 | 全文实体一致 | jieba 分词过滤
> **v2.1 新特性**：EntityResolver 实体归一化 | SecureDesensitizer 内存安全模式 | 零信任 AES-256-GCM 加密映射表 | 文件名自动脱敏

## 功能

一键脱敏法律文书中的敏感信息，支持 **.txt / .docx / .pdf** 三种格式：

| 数据类型 | 处理方式 |
|---------|---------|
| 身份证号、手机号、银行卡号、案号等 **结构化数据** | 规则引擎（正则匹配，本地运行） |
| 人名、公司名、地址、金额等 **非结构化信息** | LLM 语义识别（AI 处理） |

## 快速开始

```bash
# 安装依赖
pip install python-docx PyMuPDF

# 脱敏文件
python desensitize.py mask -f 合同.docx
python desensitize.py mask -f 证据.pdf
python desensitize.py mask -f 文档.txt

# 从管道输入
cat 文档.txt | python desensitize.py mask

# 仅扫描敏感信息
python desensitize.py scan -f 文档.docx

# 生成 LLM 脱敏提示词
python desensitize.py llm-prompt -f 文档.docx

# v2.1 内存安全模式
python desensitize.py mask -f 合同.docx --secure

# v2.1 零信任加密映射表（密码不输出到终端）
export DESENSITIZER_MAPPING_PASSWORD="your-password"
python desensitize.py mask -f 合同.docx --save-mapping 映射表.enc --encrypt-mapping

# v2.1 解密映射表
python desensitize.py decrypt -f 映射表.enc -p "your-password"

# v2.2 一键还原（庭审、归档需要原文时）
python desensitize.py restore -f 脱敏后.docx -m 映射表.enc -p "your-password" -o 还原.docx

# v2.2 红队评测（43 个用例，输出分类型召回率）
python3 evaluate.py --report 评测报告.md

# v2.2 本地 NER 层（可选：spaCy / HuggingFace / 本地 Ollama）
python desensitize.py mask -f 合同.docx --ner-backend spacy --ner-model zh_core_web_trf
python desensitize.py mask -f 合同.docx --ner-backend llm --ner-model qwen2.5

# v2.3 完整脱敏流水线（规则层 + 本地 LLM 二轮脱敏，覆盖裸人名/无结构地址/案情细节）
python desensitize.py full -f 判决书.docx --llm-api ollama --llm-model qwen2.5 \
  --save-mapping 映射表.enc --encrypt-mapping

# v2.3 LLM 评测模式（把 LLM 层覆盖项计入召回率）
python3 evaluate.py --llm-api ollama --llm-model qwen2.5 --report 评测报告.md

# JSON 格式输出
python desensitize.py mask --json -f 文档.docx

# 所有“年月日”日期也脱敏（默认只处理出生日期）
python desensitize.py mask -f 聊天记录.txt --all-dates
```

## 脱敏覆盖范围

### 规则层（18类）+ EntityResolver 实体归一化
身份证号、手机号、固定电话、服务电话（400/800）、邮箱、微信号、QQ号、银行卡号、统一社会信用代码、组织机构代码、案号、律师执业证号、车牌号、出生日期、金额、人名、公司名、地址、护照/港澳通行证/驾驶证等其他证件

### 本地 NER 层（可选，3 种后端）
spaCy（zh_core_web_trf）| HuggingFace（bert 系中文 NER）| 本地 Ollama（qwen2.5 等）——识别规则层覆盖不到的人名、公司名、地址、法院

### LLM层（5类）
自然人姓名、公司/机构名称、地址信息、金额、敏感案情细节（通过 `llm-prompt` 生成提示词）

## v2.3 完整脱敏流水线 full

一条命令跑完"规则层 + LLM 层"，把短板（裸人名、无结构地址、案情敏感细节）补上：

```bash
# Ollama（默认）
python desensitize.py full -f 判决书.docx --llm-model qwen2.5 \
  --save-mapping 映射表.enc --encrypt-mapping

# OpenAI 兼容本地服务（LM Studio / vLLM）
python desensitize.py full -f 判决书.docx --llm-api openai \
  --llm-endpoint http://localhost:1234 --llm-model local-model
```

执行流程：
1. **规则层**先把身份证/手机号等结构化数据替换为占位符
2. **LLM 层**只看到脱敏后的文本，识别并替换剩余敏感信息（裸人名、无省市区层级的地址、案情隐私细节、遗漏金额），输出"脱敏后全文 + 补充映射表"
3. **失败安全**：LLM 输出若增删行、改动已有占位符、声称替换的值仍残留原文，一律拒绝采用并中止，不产出未经验证的"完整脱敏"文档
4. **合并映射**：规则层与 LLM 层映射按原文位置统一排序，`restore` 一条命令无损还原

**数据安全**：默认仅连接本机 Ollama（localhost），规则层之后才发送文本。务必确认 endpoint 是本地或可信服务。

## 不部署本地模型：云端 API 方案（二选一即可）

**不想装 Ollama、不想下载模型？用云端 API 一样能跑 full。** 机器上什么都不用装，
只要有一个 API Key：

```bash
# 通义千问（阿里云百炼，新用户有免费额度）
export LLM_API_KEY="你的通义APIKey"
python3 desensitize.py full -f 判决书.docx --llm-api openai \
  --llm-model qwen-plus --llm-endpoint https://dashscope.aliyuncs.com/compatible-mode

# DeepSeek
export LLM_API_KEY="你的DeepSeekAPIKey"
python3 desensitize.py full -f 判决书.docx --llm-api openai \
  --llm-model deepseek-chat --llm-endpoint https://api.deepseek.com

# 智谱 GLM
export LLM_API_KEY="你的智谱APIKey"
python3 desensitize.py full -f 判决书.docx --llm-api openai \
  --llm-model glm-4-plus --llm-endpoint https://open.bigmodel.cn/api/paas/v4
```

也可用 `--llm-api-key "xxx"` 直接传 Key（会留在 shell 历史里，建议用环境变量）。

### 云端方案的安全边界（必须知道）

- 规则层先把身份证号、手机号、银行卡号等**结构化数据替换成占位符**，
  所以发送给云端的文本里没有这些号码
- 但**人名、地址、案情细节会发送给 API 服务商**——这取决于你对"数据出境/交给第三方"的接受度
- 涉密程度高的材料，请优先本地 Ollama 方案；可接受第三方处理时，云端方案零部署、开箱即用
- 评测照常可用：`python3 evaluate.py --llm-api openai --llm-model qwen-plus --llm-endpoint https://dashscope.aliyuncs.com/compatible-mode`

### 两个方案怎么选

| 方案 | 部署成本 | 数据去向 | 适用 |
|------|---------|---------|------|
| 本地 Ollama | 下载 4~5GB 模型，需 8GB+ 内存 | 不出本机 | 涉密材料、高隐私要求 |
| 云端 API | 零部署，注册拿 Key | 发送给服务商（已先脱敏结构化数据） | 无本地硬件、接受第三方处理 |

## v2.4 规则层增强：裸人名 + 无层级地址

**裸人名**（无需角色词）：姓氏 + 分词 + 频率/上下文启发式。
依赖中文分词库 jieba（`pip3 install jieba`）过滤"江省杭""付逾期"这类
嵌在长词里的假候选；每个姓氏位置只取最长合法候选（尾部吞动词、第二位
是数字的候选判非法），常见词（陈述/金额/范围）、公司/职务名
（张律师/华信置业/鼎盛集团）均有黑名单。

**全文一致**：角色词先识别的人名（如"原告：陈建国"）会自动传播到全文
裸出现处（"陈建国再次到庭"），同一人全篇同一个占位符；全新发现的裸人名
也通过 EntityResolver 保证一致，`restore` 无损还原。

**无层级地址**：新增两类模式——小区/花园/公寓/大厦/苑/村/镇/区 +
栋/单元/室/楼/号（"望京西园四区410楼"），以及路/街/大道 + 门牌号
（"莫干山路100号"）。

```bash
# 关闭裸人名启发式（只保留角色词人名 + 传播）
python3 desensitize.py mask -f 文件.docx --no-bare-names
```

实测（5 份真实法律文书压力测试集）：人名识别零误报、全文一致；
语料库结构化期望从 42 项提升到 50 项（新增裸人名、无层级地址、一致性用例）。
LLM 层现在只负责两类：**案情敏感细节** 与 **裸公司简称**。

### evaluate --llm 评测模式

```bash
python3 evaluate.py --llm-api ollama --llm-model qwen2.5
```

语料库中的 `llm_only` 条目（裸人名/无结构地址/案情细节）在 LLM 模式下成为硬性期望并计入召回率；
不传 `--llm-*` 时保持仅规则层评测，如实标注"LLM 层待覆盖项"。

## v2.2 新增能力

### 校验码验证（准确性）
- **身份证**：GB 11643-1999 第 18 位校验码，`scan` 输出置信度（校验码合法=1.0，仅出生日期合法=0.6）
- **统一社会信用代码**：GB 32100-2015 校验码（`91350100M000100Y43` 为官方示例通过码）
- **银行卡**：Luhn 算法，`scan` 标注置信度

### 一键还原 restore
用映射表（Markdown / JSON / AES-256-GCM 加密 .enc）把脱敏文本无损还原为原文：

```bash
python desensitize.py mask -f 起诉状.docx --save-mapping 映射表.enc --encrypt-mapping
python desensitize.py restore -f 起诉状_desensitized.docx -m 映射表.enc -o 还原.docx
```

映射表自动记录"首次出现顺序"，多个同类型占位符（如多个 `[金额]`）按原文顺序逐一配对，
往返还原与原文逐字节一致（含"1980年1月1日出生"这类上下文、无分隔符人名等边界）。

### 红队评测 evaluate
`测试/红队语料库.jsonl` 内置 43 个用例（19 类结构化数据 + 负样本），量化规则层表现：

```bash
python3 evaluate.py                          # 控制台报告
python3 evaluate.py --report 评测报告.md      # Markdown 报告
python3 evaluate.py --json 结果.json          # JSON 结果
```

当前基线（v2.2）：**43/43 用例通过，结构化召回率 100%，保留项误报 0，泄露 0**。
语料库可自行增删用例，作为脱敏质量回归基线——每次改动规则后跑一遍即可量化"有没有变差"。

### 本地 NER 接入
```bash
# spaCy（中文模型）
python desensitize.py mask -f 合同.docx --ner-backend spacy --ner-model zh_core_web_trf

# HuggingFace（中文 NER 模型）
python desensitize.py mask -f 合同.docx --ner-backend huggingface --ner-model ckiplab/bert-base-chinese-ner

# 本地 Ollama（数据不出本机）
python desensitize.py mask -f 合同.docx --ner-backend llm --ner-model qwen2.5
```

规则层先把身份证/手机号等替换为占位符，**本地模型看到的已经是脱敏后的文本**；
后端缺失时给出安装指引并优雅退出，不影响纯规则层使用。

## 安全设计

```
规则引擎（本地）→ 身份证号等替换为占位符 → LLM 只看到 [身份证号]
```

- 结构化数据在本地就被替换，AI 永远不会看到真实号码
- 脱敏映射表保存在本地，不上传
- 即使 LLM 在云端，也接触不到最敏感的信息

### v2.1 安全增强

- **SecureDesensitizer**：`--secure` 启用内存安全模式，脱敏后尽力清空原始字符串引用
- **零信任加密**：AES-256-GCM + PBKDF2 密码派生，密钥绝不输出到 stdout（修复 v2.0 Fernet 设计缺陷）
- **文件名自动脱敏**：输出文件时自动替换文件名中的敏感信息（可通过 `--no-sanitize-filename` 禁用）
- **EntityResolver**：同一人物/公司全文档统一占位符，公司简称自动链接到全称

### v2.1.1 行为说明（规则层修复）

- **身份证号**：带"身份证/证件"上下文时无条件替换；无标签的 18 位数字只有内嵌有效
  出生日期才归为身份证号，其余按银行账号处理，避免银行卡被误标。
- **统一社会信用代码**：无标签时要求以 9 开头，律所执业许可证（如 31110000E000123456）
  不再被误判为信用代码，而是按"执业许可证号"识别为 `[律师执业证号]`。
- **日期**：普通日期（合同签署日、开庭日等）默认**不**脱敏，只脱敏带"出生/生日/生于"
  上下文的日期；如确需全部日期脱敏，使用 `--all-dates`。
- **映射表计数**：出现次数按原始值统计（同值出现多次累加），不再是按类型合计。
- **微信号**：只匹配字母开头 6-20 位的合法格式，且不紧贴中文，避免把"粤B88888"
  这类车牌误当作微信号。
- **QQ号**：替换后同步记录进映射表。
- **修复 v2.1 无法运行的类定义顺序问题**（SecureDesensitizer 前向引用 Desensitizer）。

### ⚠️ 安全等级说明：请根据你的需求选择脱敏深度

本工具是分层脱敏系统，**不是一键魔法**。你脱敏到哪一层，取决于你对数据安全的判断：

| 安全等级 | 执行步骤 | 替换了什么 | 还剩什么未替换 | 能否上传给云端AI |
|---------|---------|-----------|---------------|----------------|
| 🔴 不脱敏 | 什么都不做 | 无 | 全部敏感信息 | ❌ 绝不可上传 |
| 🟡 仅规则层 | `python3 desensitize.py mask -f 文件.docx` | ✅ 身份证号、手机号、银行卡号、案号、日期等结构化信息 | ⚠️ 人名、公司名、地址、金额、案情细节尚在 | ⚠️ **有风险**，不建议上传 |
| 🟢 规则层 + LLM层(本地模型) | 规则层后，调用本地Ollama/LM Studio做LLM层脱敏 | ✅ 全部14类敏感信息 | ✅ 全部替换 | ✅ **可以安全上传** |
| 🟢 规则层 + LLM层(云端AI) | 规则层后，把半脱敏文本给ChatGPT等做LLM层脱敏 | ✅ 全部14类敏感信息 | ✅ 全部替换 | ✅ 可以上传，但LLM层脱敏那一步本身有数据暴露风险 |

**建议**：
- 如果文件涉密程度高 → 走完全是**规则层+本地LLM层**
- 如果文件涉密程度中等 → 规则层后自己用肉眼检查一遍，再上传给AI
- 如果只做案情摘要等不涉密分析 → 规则层处理后即可使用

> ⚠️ **记住：只跑规则层就把文件上传给AI，身份证号虽已替换，但人名、公司名、金额等仍在泄露。**
> 
> 完整脱敏 = 规则层 + LLM层（二选一：本地模型或云端AI）

## 推送工具（github.com 直连受限时）

`api-push.py` 通过 GitHub Git API 推送提交，适用于 github.com 无法直连、
但 api.github.com 可达的网络环境（如国内网络）。

```bash
# 推送指定文件
python3 api-push.py -m "fix: 修复xxx" desensitize.py

# 推送全部工作区改动，并同步本地历史（SHA 与远程一致）
python3 api-push.py -m "feat: xxx" --all --sync-local

# 先看将执行什么，不实际推送
python3 api-push.py -m "test" --all --dry-run
```

Token 按 `--token` → `GITHUB_PAT_TOKEN` → gh 配置文件（`~/.config/gh/hosts.yml`）
的顺序自动读取；网络恢复后仍可直接使用标准 `git push`。

## 授权

MIT License
