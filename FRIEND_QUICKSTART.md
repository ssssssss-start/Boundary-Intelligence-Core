# 给朋友的启动说明

## 1. 准备配置

```bash
cp .env.example .env
```

编辑 `.env`，至少按需填写 DeepSeek 的 `OPENAI_API_KEY`；截图识别需要填写 `VISION_API_KEY`。不要使用交付者的私人密钥。

如果暂时不下载 BGE-M3，将以下配置改为：

```env
ANTI_FRAUD_EMBEDDING_BACKEND=hash
```

## 2. 一条命令启动全部服务

```bash
docker compose up -d --build
```

首次构建会下载 Python 依赖及 MongoDB、Milvus、FunASR 镜像，需要保持网络畅通。查看状态：

```bash
docker compose ps
docker compose logs -f query import
```

## 3. 访问

- 导入页面：http://127.0.0.1:8000/import.html
- 聊天页面：http://127.0.0.1:8001/chat.html
- 管理后台：http://127.0.0.1:8001/admin/review.html
- 健康检查：http://127.0.0.1:8001/health

## 4. 停止

```bash
docker compose down
```

数据库数据保存在 Docker volumes 中；如需同时删除数据卷，必须明确执行 `docker compose down -v`。
