# 法律文书脱敏工具 (Legal Document Desensitizer)

规则引擎 + LLM 混合脱敏工具，专为法律文书设计。

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

# JSON 格式输出
python desensitize.py mask --json -f 文档.docx
```

## 脱敏覆盖范围

### 规则层（11类）
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

## 授权

MIT License
