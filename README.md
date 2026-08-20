# Boundary-Intelligence-Core

面向中文场景的反诈风险识别与干预平台。项目将规则引擎、语义路由、知识检索、风险解释和紧急劝阻流程组合在一起，为聊天、链接、截图、语音和举报材料提供统一的风险研判能力。

## 能力概览

- **多模态风险识别**：支持文本、URL、截图 OCR、语音转写和结构化举报。
- **分层风险决策**：规则引擎负责高置信风险，语义模型用于补充场景理解，并输出可解释的风险特征。
- **知识检索与问答**：基于反诈知识库、法律条款、典型案例和官方来源提供证据化回答。
- **紧急劝阻流程**：针对转账、验证码、远程控制、涉诈链接等场景提供分阶段的止损建议。
- **管理与评测工具**：包含风险规则管理、举报研判、训练营模块及离线评测脚本。

## 项目结构

```text
app/                 后端应用、API、规则引擎和业务模块
data/                脱敏后的知识库、规则和测试数据
evaluation/          合成评测集、评测脚本和报告
miniprogram/         微信小程序前端
mobile-app/          UniApp/H5 移动端
scripts/             启动、校验、导入和评测脚本
tests/ test/         自动化测试
.env.example         环境变量模板（不含真实密钥）
```

## 快速开始

### 1. 准备环境

- Python 3.11+（推荐 3.11 或 3.12）
- Docker Desktop
- Node.js 18+（仅在构建移动端/H5 时需要）
- DeepSeek 兼容 API key；如启用视觉 OCR，再配置 DashScope 视觉 API key

### 2. 创建配置

```bash
cp .env.example .env
```

在 `.env` 中填写自己的密钥和服务地址。`.env` 已被 Git 忽略，禁止提交到仓库。

如果暂时不下载 BGE-M3，可先使用本地哈希嵌入进行开发验证：

```env
ANTI_FRAUD_EMBEDDING_BACKEND=hash
```

### 3. 启动基础服务

```bash
docker compose up -d --build
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\\Scripts\\activate
python -m pip install -r requirements.txt
./scripts/launch_query_service.sh
```

默认查询服务端口为 `8001`。浏览器页面位于：

- `http://127.0.0.1:8001/chat.html`：反诈问答
- `http://127.0.0.1:8001/emergency.html`：紧急劝阻
- `http://127.0.0.1:8001/profile.html`：用户画像与风险记录

导入服务和完整 Docker 编排方式请参考 [DELIVERY_README.md](DELIVERY_README.md) 与 [ENVIRONMENT_REQUIREMENTS.md](ENVIRONMENT_REQUIREMENTS.md)。

## 模型与数据

BGE-M3 等模型文件不随仓库发布，请按 [MODEL_DOWNLOADS.md](MODEL_DOWNLOADS.md) 下载并配置路径。公开仓库只包含代码、模板、合成/脱敏数据和可复现脚本；本地数据库快照、模型缓存、视频素材、运行日志和交付压缩包不会进入 Git。

## 测试与校验

```bash
python -m pytest -q tests
python -m pytest -q tests/test_security_baseline.py
```

评测脚本位于 `evaluation/` 和 `scripts/`，运行前请确认本地服务及所需模型已经准备好。

## 安全说明

- 不要把 API key、数据库密码、管理员密码、Cookie、用户原始聊天记录或本机路径提交到仓库。
- 生产环境必须使用 HTTPS、明确的 CORS allowlist、密钥管理服务和最小权限数据库账号。
- `ANTI_FRAUD_ALLOW_INSECURE_CORS` 与 `ANTI_FRAUD_ALLOW_INSECURE_DEFAULTS` 不应在生产环境开启。
- 详细的安全基线和部署检查项见 [SECURITY.md](SECURITY.md)。

## 许可证与使用边界

本仓库当前用于项目演示、研究和受控部署。接入真实用户数据前，请完成数据授权、脱敏、保留期限、访问控制和合规审查；风险识别结果不能替代公安、银行或其他专业机构的正式判断。
