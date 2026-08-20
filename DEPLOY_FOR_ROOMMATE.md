# 反诈项目本地部署说明

这份包用于本地运行反诈 Web 后端和微信小程序调试版。

## 需要先安装

- macOS 推荐 Python 3.11
- Docker Desktop
- 微信开发者工具

如果还没有 Python 3.11，可以用 Homebrew：

```bash
brew install python@3.11
```

## 一键启动

解压后进入项目目录：

```bash
cd anti_fraud_project
chmod +x scripts/start_local_services.sh scripts/stop_local_services.sh
./scripts/start_local_services.sh
```

启动成功后会看到：

```text
{"ok":true}
```

访问地址：

- Web 反诈咨询：http://127.0.0.1:8001/chat.html
- 导入/管理页：http://127.0.0.1:8000/import.html
- 查询服务健康检查：http://127.0.0.1:8001/health

## 微信小程序调试

1. 打开微信开发者工具。
2. 导入目录：

```text
anti_fraud_project/miniprogram
```

3. 在开发者工具的“详情 / 本地设置”里开启：

```text
不校验合法域名、web-view、TLS 版本以及 HTTPS 证书
```

4. 默认后端地址是：

```text
http://127.0.0.1:8001
```

真机预览时，`127.0.0.1` 指的是手机自己，不是电脑。需要在小程序“我的”页把后端地址改成电脑局域网 IP，例如：

```text
http://192.168.1.8:8001
```

## 大模型配置

`.env` 会由启动脚本从 `.env.example` 自动生成。

如果要使用 DeepSeek 等大模型，把 `.env` 里的这一项填上：

```bash
OPENAI_API_KEY=你的 key
```

不填也能跑，项目会使用本地规则兜底，但回答质量会比接入大模型弱。

## 语音能力

- Kokoro TTS 模型已经随包带上，路径是 `tts/kokoro/kokoro-int8-multi-lang-v1_1`。
- 小程序语音识别需要额外启动 FunASR WebSocket 服务，并监听 `127.0.0.1:10096`。
- 不启动 FunASR 不影响文字咨询、训练营、风险检测等功能。

## 停止服务

只停 Python 后端：

```bash
./scripts/stop_local_services.sh
```

连 Mongo/Milvus Docker 一起停：

```bash
./scripts/stop_local_services.sh --docker
```

## 常见问题

### 小程序显示 request:fail

说明没连上后端。先检查：

```bash
curl http://127.0.0.1:8001/health
```

如果连不上，重新执行：

```bash
./scripts/start_local_services.sh
```

### pip 安装 networkx 或 fastapi 失败

通常是 Python 版本不对。这个项目需要 Python 3.11+。

### 端口被占用

启动脚本会通过同一份 Docker Compose 自动启动 MongoDB、Milvus 和 FunASR，并清理 `8000` 和 `8001` 的旧 Python 进程。如果仍然异常，可以手动执行：

```bash
lsof -iTCP:8000 -sTCP:LISTEN
lsof -iTCP:8001 -sTCP:LISTEN
```
