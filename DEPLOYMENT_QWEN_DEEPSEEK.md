# 反诈项目部署说明

本部署包不会携带本机 `.env` 和任何真实 API key。首次部署时需要补齐两个 key：

- `OPENAI_API_KEY`：DeepSeek 文本模型 key，用于主聊天、语义路由、RAG 总结等文本 LLM 能力。
- `VISION_API_KEY`：Qwen 视觉模型 key，用于聊天页截图 OCR 与视觉风险分析。

## 环境要求

- Python 3.11+
- Docker Desktop / Docker Engine
- macOS、Linux 或 WSL 环境

## 推荐部署方式

解压后进入项目根目录：

```bash
cd anti_fraud_project
bash scripts/deploy_with_keys.sh
```

脚本会自动：

1. 从 `.env.example` 生成 `.env`
2. 要求输入 DeepSeek key 和 Qwen key
3. 设置默认模型：
   - `OPENAI_BASE_URL=https://api.deepseek.com`
   - `LLM_DEFAULT_MODEL=deepseek-chat`
   - `VISION_BASE_URL=https://dashscope.aliyuncs.com/compatible-mode/v1`
   - `VISION_MODEL=qwen-vl-plus`
4. 安装 Python 依赖
5. 启动 Mongo、Milvus 和本地服务

也可以非交互部署：

```bash
DEEPSEEK_API_KEY="你的DeepSeekKey" \
QWEN_API_KEY="你的阿里云百炼Key" \
bash scripts/deploy_with_keys.sh
```

## 访问地址

启动成功后访问：

```text
http://127.0.0.1:8001/chat.html
```

后台健康检查：

```text
http://127.0.0.1:8001/health
```

## 截图 OCR

聊天页输入框左侧点击 `+`，选择“识别聊天截图”，会调用 Qwen-VL：

```env
VISION_BASE_URL=https://dashscope.aliyuncs.com/compatible-mode/v1
VISION_MODEL=qwen-vl-plus
```

如果需要更强的视觉识别，可以把 `.env` 中的模型改成：

```env
VISION_MODEL=qwen-vl-max
```

修改 `.env` 后需要重启：

```bash
bash scripts/start_local_services.sh
```

## 注意

- 不要把 `.env` 上传到公开仓库或发给别人。
- 如果截图识别提示缺少 `VISION_API_KEY`，说明 Qwen key 没填或服务没有重启。
- 如果主聊天提示 LLM 不可用，优先检查 `OPENAI_API_KEY` 是否为有效 DeepSeek key。
