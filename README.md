# 法律文书脱敏工具 (Legal Document Desensitizer)

规则引擎 + EntityResolver 实体归一化 + LLM 混合脱敏工具，专为法律文书设计。

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

# JSON 格式输出
python desensitize.py mask --json -f 文档.docx
```

## 脱敏覆盖范围

### 规则层（18类）+ EntityResolver 实体归一化
身份证号、手机号、固定电话、邮箱、微信号、QQ号、银行卡号、统一社会信用代码、案号、律师执业证号、车牌号、日期

### LLM层（5类）
自然人姓名、公司/机构名称、地址信息、金额、敏感案情细节

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

## 授权

MIT License
