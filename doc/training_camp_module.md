# 防骗训练营模块说明

## 模块目标

防骗训练营面向反诈教育场景，提供游戏化、情景化的训练体验。当前实现覆盖：

- 闯关答题：按关卡推进典型骗局识别题。
- 题库规模：当前种子题库为 200 题，覆盖 20 类典型骗局，每类 10 题。
- 答案分布：正确答案在 4 个选项位置均衡分布，避免用户靠固定位置猜题。
- 积分奖励：题库闯关答对每题 2 分；实时骗局模拟通关每次 10 分。
- 段位勋章：总分 0-19 为白银，20-59 为黄金，60-139 为钻石，140 分及以上为王者。
- 题库情景：每一关返回受训者角色、可疑联系人角色、任务目标和风险信号。
- 实时骗局模拟：不使用题库题号或闯关进度，前端拆成两个视图：先只显示简单、中等、困难 3 个难度入口；用户点击难度后跳转到独立对话窗口，AI 自动生成第一句话并开始完整诈骗场景。
- 语音交互：题库闯关只保留选项作答；实时骗局模拟中，“语音”按钮录制单句话音频，后端转发到本地 FunASR WebSocket 服务识别成文字并自动发送一轮；“打电话”按钮做连续听写，识别到用户一句话后自动进入现有文字模拟流程，助手回复优先由本地 Kokoro TTS 合成音频播放，失败时才回退到浏览器 SpeechSynthesis。

## 接口契约

### 获取下一关

`GET /game/next?user_id={user_id}&level_id={level_id}`

返回核心字段：

- `level`: 当前关卡，不包含答案。
- `level.scenario_simulation`: 情景模拟结构，包含 `player_role`、`opponent_role`、`mission`、`risk_signals`。
- `level.voice_interaction`: 语音作答提示和选项提示。
- `level.reward_preview`: 本关可获得积分和勋章。
- `gamification`: 当前积分、勋章、完成率和评估等级。
- `multimodal`: 当前多模态能力声明。

### 提交答案

`POST /game/submit`

请求示例：

```json
{
  "user_id": "demo_user",
  "level_id": 1,
  "answer": "",
  "interaction_mode": "voice",
  "voice_text": "我选择第一项",
  "audio_meta": {
    "source": "browser_speech_recognition"
  }
}
```

返回核心字段：

- `correct`: 是否答对。
- `selected_answer`: 用户最终匹配到的答案。
- `interaction`: 交互来源、语音文本、置信度和语音元信息。
- `simulation_feedback`: 情景模拟复盘、NPC 反馈和风险信号。
- `reward`: 本次积分、勋章和累计奖励。
- `next_level_id`: 下一关建议。

### 训练报告

`GET /game/report?user_id={user_id}`

返回积分、答题数、正确率、完成率、勋章、训练模式和多模态能力。

总分规则：

- 题库闯关答对 1 题：`+2` 分。
- 实时骗局模拟未被骗且达到通关标准：`+10` 分。
- 段位勋章：`0-19 白银`、`20-59 黄金`、`60-139 钻石`、`140+ 王者`。

### 开始实时骗局模拟

`POST /game/simulation/start`

请求示例：

```json
{
  "user_id": "demo_user",
  "fraud_type": "刷单",
  "difficulty": "hard",
  "use_llm": true
}
```

`difficulty` 支持 `easy`、`medium`、`hard`，分别对应：

- 简单模式：风险点明显，骗子话术较直接。
- 中等模式：先建立信任，再逐步诱导。
- 困难模式：更真实克制，会回应质疑，诱导链条更隐蔽。

返回一个模拟会话，包含 `session_id`、随机或指定骗局类型、骗子角色、难度标签、风险信号和骗子第一句话。

### 推进一轮模拟

`POST /game/simulation/turn`

请求示例：

```json
{
  "session_id": "sim-xxxx",
  "user_message": "我不会转账，我要先联系官方客服核实。",
  "voice_text": "",
  "use_llm": true
}
```

后端将用户回复加入对话，由 LLM 继续扮演骗子生成下一句话。若用户已经出现转账、泄露验证码、点链接、下载 App、共享屏幕等高危行为，模拟会自动结束并评分。

### 结束并评分

`POST /game/simulation/finish`

返回 `score`、`outcome`、`loss_signals`、`safe_signals`、`points_delta`、`rank_badge` 和复盘建议。`score` 是本次模拟表现分，`points_delta` 是计入训练营总分的积分。评分核心不是选择题对错，而是判断用户在自由对话中是否被诱导做出高危动作。

### 实时模拟语音交互

当前前端可见交互集中在实时骗局模拟会话输入区：

- `语音`：单次浏览器听写，识别到一句话后自动作为本轮回复提交。
- `打电话`：网页内连续听写，不拨打真实电话；识别到一句话后暂停聆听、提交给现有模拟流程、播放助手回复，播放结束后继续聆听。
- `发送`：保留原有文字输入和发送方式。

这不是打真实电话，不需要手机号，也不接入外呼或呼叫中心。

实现链路：

1. 前端通过浏览器麦克风录制单句话音频，转换为 16k 单声道 PCM。
2. 前端调用 `/game/simulation/asr`，后端转发到本地 FunASR WebSocket 服务完成识别。
3. 单次语音识别一轮；打电话模式持续监听，遇到用户一句完整话后自动暂停。
4. 识别文本通过 `/game/simulation/turn` 的 `voice_text` 字段进入现有 `continue_scam_simulation` 流程。
5. 助手回复展示在模拟聊天窗口，并优先用本地 Kokoro TTS 自动播放。
6. 打电话模式在播放结束后继续监听下一句，直到用户点击“挂断”或模拟结束。

### 实时语音 WebSocket 预留

`WebSocket /game/simulation/realtime-voice/ws`

后端保留可插拔 WebSocket 语音链路，用于后续接入真实云 ASR/TTS provider。当前默认 `mock_realtime` 主要用于链路调试，不作为前端默认识别方式。

前端发送：

```json
{"type":"session.start","payload":{"mode":"realtime_voice","scenario_type":"刷单返利诈骗","difficulty":"medium"}}
```

```json
{"type":"audio.input.append","payload":{"audio_format":"webm_opus","audio_base64":"..."}}
```

```json
{"type":"audio.input.commit","payload":{}}
```

```json
{"type":"assistant.interrupt","payload":{}}
```

```json
{"type":"session.end","payload":{}}
```

后端返回：

```json
{"type":"session.started","payload":{"session_id":"voice-xxxx","simulation_session_id":"sim-xxxx","asr_provider":"mock_realtime","tts_provider":"browser_fallback"}}
```

```json
{"type":"transcript.partial","payload":{"text":"我先不转账","confidence":0.99}}
```

```json
{"type":"transcript.final","payload":{"text":"我先不转账，也不会给验证码，我要去官方渠道核实。","confidence":0.99}}
```

```json
{"type":"assistant.text.final","payload":{"text":"骗子下一句或结束复盘","tts":{"provider":"browser_fallback","speak_with_browser":true}}}
```

```json
{"type":"turn.completed","payload":{"risk_score":20,"safe_actions":[],"risk_events":[]}}
```

```json
{"type":"session.ended","payload":{"summary":"本轮复盘","final_score":85}}
```

```json
{"type":"error","payload":{"message":"错误说明"}}
```

当前默认 provider：

- `VOICE_ASR_PROVIDER=mock_realtime`：本地调试用，后端会接收真实音频 chunk，但 commit 时返回固定训练文本，保证项目无第三方语音 Key 也能跑通 WebSocket、转写事件和模拟流程。
- `VOICE_TTS_PROVIDER=browser_fallback`：后端返回浏览器播放指令，前端用 `SpeechSynthesis` 自动播放助手文字。

可配置项见 `.env.example`：

```env
VOICE_MODE=realtime_voice
VOICE_ASR_PROVIDER=mock_realtime
VOICE_TTS_PROVIDER=browser_fallback
VOICE_ENABLE_REALTIME_DIALOGUE=1
VOICE_ENABLE_INTERRUPTION=1
VOICE_MIN_CONFIDENCE=0.75
VOICE_SAVE_AUDIO=0
VOICE_SAVE_TRANSCRIPT=1
VOICE_DEFAULT_AUDIO_FORMAT=webm_opus
```

## 稳定性设计

- MongoDB 不可用时，服务降级使用 `app/modules/training_camp/data/seed_game_levels.json`。
- 关卡读取、答题读取、进度写入都有异常捕获和日志记录，保证训练流程能返回非持久化结果。
- 对外接口保持 `/game/next`、`/game/submit`、`/game/report` 不变，新增字段向后兼容。
- 实时骗局模拟优先使用 LLM；LLM 初始化或调用失败时自动降级到本地脚本话术，不影响训练流程。不同难度使用不同 prompt 约束和本地兜底话术长度。
- 旧路径 `app.game_process.services.game_service` 显式转发到新训练营服务，避免两套业务逻辑分叉。
- 模拟评分使用规则兜底，识别转账、验证码、密码、下载 App、点链接、共享屏幕等高危行为，也识别拒绝、核实、报警、保存证据等安全行为。
- 总分和段位由后端统一计算，避免前端自行推导导致展示不一致。
- 语音交互只替代“用户手动输入文字并发送”的过程；前端真实识别到的文本或 WebSocket provider 后续生成的 transcript 都应复用现有模拟 turn，不复制或重写骗局模拟核心逻辑。
- 语音 provider 架构集中在 `app/modules/voice`，默认 provider 不依赖第三方 API Key，后续可替换为真实云 ASR/TTS。

## 可扩展性约定

题库由 `scripts/generate_training_levels.py` 生成，并同步写入：

- `app/modules/training_camp/data/seed_game_levels.json`
- `app/game_process/data/seed_game_levels.json`

新增关卡或扩展骗局类型时，优先调整生成脚本中的 `SCAM_PACKAGES`，再重新生成题库。单题结构建议包含：

- `level_id`: 递增关卡 ID。
- `title`: 关卡标题。
- `scenario`: 情景文本。
- `question`: 训练问题。
- `options`: 选项数组。
- `answer`: 正确答案，必须与某个选项一致。
- `points`: 题库原始配置积分；当前总分规则固定按答对每题 2 分计入。
- `badge`: 可解锁勋章。
- `explanation`: 复盘解释。
- `scam_type_id` 和 `fraud_type`: 用于生成情景角色、章节和类型标签。

扩展实时模拟时，优先新增骗局包、风险信号、难度 profile、评分规则或 LLM prompt 约束，不改变 `/game/simulation/*` 的会话字段含义。

扩展新多模态能力时，优先在响应中新增 `multimodal`、`interaction` 或 `simulation` 子字段，不改变现有字段含义。

## 代码规范

- 新实现集中在 `app/modules/training_camp`。
- 实时语音 provider、WebSocket 会话编排集中在 `app/modules/voice`，路由入口在 `app/query_process/api/voice_api.py`。
- 旧 `app/game_process` 仅保留兼容 API 和显式服务转发。
- 前端训练营逻辑集中在 `app/query_process/page/chat.html` 的训练面板相关函数。
- 后端单测集中在 `test/test_game_service.py`，覆盖 200 题规模、20 类骗局、答案位置均衡、积分勋章、题库情景结构、语音作答、实时模拟安全高分和被骗低分。

## 验证命令

```powershell
.\.venv\Scripts\python.exe -c "import unittest, sys; suite=unittest.defaultTestLoader.discover('test', pattern='test_game_service.py'); result=unittest.TextTestRunner(verbosity=2).run(suite); sys.exit(0 if result.wasSuccessful() else 1)"
.\.venv\Scripts\python.exe -m compileall app\modules\training_camp app\game_process app\query_process\page test\test_game_service.py
```

重新生成题库：

```powershell
.\.venv\Scripts\python.exe scripts\generate_training_levels.py
```

运行服务：

```powershell
.\.venv\Scripts\uvicorn.exe app.query_process.api.app:app --host 127.0.0.1 --port 8000
```

训练营页面：

`http://127.0.0.1:8000/chat.html?module=training`
