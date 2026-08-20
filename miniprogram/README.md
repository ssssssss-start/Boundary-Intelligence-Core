# 反诈助手微信小程序

这是当前项目的原生微信小程序前端，复用已有 FastAPI 后端接口，不改后端业务逻辑。

## 当前包含

- 首页：后端健康检查与功能入口
- 反诈咨询：调用 `/knowledge/chat`
- 风险检测：调用 `/risk/check`、`/url/check`
- 防骗训练营：调用 `/game/next`、`/game/submit`、`/game/report`，包含大关地图、Boss 血量、题内进度与答题反馈
- 骗局模拟：调用 `/game/simulation/start`、`/game/simulation/turn`、`/game/simulation/finish`
- 小程序语音：录制 16k WAV，调用 `/game/simulation/asr`
- Kokoro TTS：调用 `/game/simulation/tts` 并播放返回的 WAV 音频
- 举报研判：调用 `/report-intel/analyze`、`/report-intel/confirm`
- 紧急劝阻：调用 `/emergency/chat`
- 我的设置：配置后端地址和用户 ID

## 本地调试

1. 启动后端：

```bash
cd /Users/sss/main/anti_fraud_project
docker compose up -d
nohup ./.venv/bin/python -m app.query_process.api.query_service > runtime_8001.out.log 2> runtime_8001.err.log &
```

2. 打开微信开发者工具，导入本目录：

```text
/Users/sss/main/anti_fraud_project/miniprogram
```

3. 开发者工具中关闭“校验合法域名、web-view、TLS 版本以及 HTTPS 证书”。

4. 默认后端地址是：

```text
http://127.0.0.1:8001
```

真机调试时，在“我的”页改成电脑局域网 IP，例如：

```text
http://192.168.1.8:8001
```

## 后续待接

- 管理后台小程序化或保留 Web 管理端
- 小程序端更细的登录、鉴权、历史会话与消息持久化
- 小程序正式上线所需 HTTPS 域名、隐私协议、麦克风权限说明
