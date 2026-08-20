# 反诈助手移动端 App

这是反诈助手第一版 App 端工程，使用 uni-app + Vue3，体验对齐当前微信小程序聊天页。

## 当前范围

- 启动页即聊天页，无底部 tabBar。
- 聊天页包含顶部 `... / 反诈助手 / +`、顶部固定状态条、历史会话、底部固定输入栏。
- 主聊天接口仍为 `POST /knowledge/chat`。
- 底部 `+` 内置「可疑链接/内容一键举报」，调用 `/report-intel/analyze` 和 `/report-intel/confirm`。
- 左侧菜单可进入「防骗训练营」和「骗局模拟」。

## 运行方式

### H5 移动端预览

当前机器可以先用 Codex 内置 Node/pnpm 跑 H5 预览，页面可直接在浏览器操作：

```bash
cd /Users/sss/main/anti_fraud_project/mobile-app
PATH="/Users/sss/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin:/Users/sss/.cache/codex-runtimes/codex-primary-runtime/dependencies/bin:$PATH" CI=true /Users/sss/.cache/codex-runtimes/codex-primary-runtime/dependencies/bin/pnpm install
PATH="/Users/sss/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin:/Users/sss/.cache/codex-runtimes/codex-primary-runtime/dependencies/bin:$PATH" CI=true /Users/sss/.cache/codex-runtimes/codex-primary-runtime/dependencies/bin/pnpm run dev:h5
```

启动后打开：

```text
http://127.0.0.1:5173/
```

### 原生 App

推荐使用 HBuilderX 打开 `mobile-app` 目录，选择运行到 Android 真机或模拟器。

也可以在安装好系统 Node/npm 和 uni CLI 后使用：

```bash
npm install
npm run dev:app
```

构建 Android/iOS App：

```bash
npm run build:app
```

## 后端地址

默认后端地址为：

```text
http://127.0.0.1:8001
```

真机运行时，`127.0.0.1` 指手机本机，需要改成电脑局域网 IP，例如：

```js
uni.setStorageSync("antiFraudMobileBaseUrl", "http://192.168.1.23:8001")
```

后续可以在 App 内增加设置页；当前第一版先保留 API 层配置能力，不在聊天界面展示开发配置。
