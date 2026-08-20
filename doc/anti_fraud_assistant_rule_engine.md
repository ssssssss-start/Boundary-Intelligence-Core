# 智能反诈助手规则引擎说明

## 模块定位

智能反诈助手统一承载反诈科普、风险场景研判和实时劝阻。入口仍为 `/knowledge/chat`，由意图识别决定进入知识问答还是风险劝阻流程：

1. `route_user_input` 依据关键词、句式、上下文和安全信号识别用户意图。
2. `unified_anti_fraud_chat` 将科普问题送入知识问答，将疑似受骗场景送入 `risk_case_flow`。
3. `evaluate_rule_state` 从当前轮与用户历史中抽取诈骗类型、风险特征、阶段和命中规则。
4. `build_realtime_dissuasion` 根据命中规则和当前危险动作输出结构化劝阻话术、处置动作、案例、法规和证据指引。
5. 风险命中达到实时劝阻阈值后，最终回答优先使用确定性结构化输出，不再依赖大模型自由生成长篇科普，避免“已经进入风险场景但回答仍像课堂讲解”的问题。

## 意图识别设计

入口路由不是简单的“科普/求助”二分类，而是风险优先的 `RouteDecision`。路由输出会同时包含：

- `primary_intent`：`anti_fraud_qa`、`risk_help`、`emergency_help`、`risk_fact_clarification` 等。
- `workflow_mode`：`knowledge_answer`、`risk_case_flow`、`clarification`、`fallback`。
- `safety_signals`：已转账、已给验证码、已屏幕共享、已下载陌生 App、已点链接、已填身份证/银行卡等确定性安全信号。
- `risk_prefill`：候选骗局类型、当前对方要求的危险动作、可预填槽位。
- `routing_decision.prefill_slots`：供风险状态机直接使用的结构化事实。

判定优先级如下：

1. **已发生暴露或损失**：用户明确说“已经转账、给了验证码、正在屏幕共享、下载了 App、填了银行卡/身份证、交付游戏装备账号”，直接进入 `emergency_help` 和 `risk_case_flow`。
2. **对方正在要求危险动作**：用户说“对方让我交保证金/补单/给验证码/开屏幕共享/下载会议软件/点链接填信息”，进入 `risk_help`，但不会误写成用户已经完成操作。
3. **具体场景风险咨询**：用户问“我在兼职群看到点赞返佣靠谱吗”“这个贷款平台安全吗”“就业班承诺推荐实习可信吗”，虽然是问句，但属于真实场景预警，进入风险研判而不是普通科普。
4. **泛化科普问题**：用户问“什么是刷单返利诈骗”“校园贷怎么防范”“冒充公检法有哪些套路”，进入 `knowledge_answer`。
5. **事实不足的求助**：用户只说“我被骗了”“我可能遭遇诈骗”，进入 `risk_fact_clarification`，优先追问对方身份、危险动作、是否已转账或泄露信息。

## 事件链抽取与槽位补全

安全信号抽取层不再只依赖“我提供了身份证”这类固定句式，而是按事件链理解用户本轮输入：

1. **风险诱饵事件**：识别中奖、退款、贷款、兼职、投资、租房、就业班、游戏交易等接触场景。
2. **对方要求事件**：识别“对方让我/要我/问我要/需要我”后面的危险动作，例如转账、交保证金、填身份证、给验证码、下载 App、开屏幕共享。
3. **用户执行事件**：识别“我已经/我给他/我填了/我提交了/我点进去了/我下载了”等完成动作。
4. **上下文合并**：当同一句里出现“他要我提供身份证信息，我给他提供了”时，把前半句的对象“身份证信息”和后半句的动作“已提供”合并为 `has_provided_identity_or_bank=true`。
5. **否定保护**：当用户说“我没有提供”“还没填”“没转账”时，只保留预警场景，不升级为紧急暴露。

抽取后的标准槽位包括：

- `has_clicked_link`：已点击链接、扫码或进入可疑页面。
- `has_provided_identity_or_bank`：已填写/提供身份证、银行卡、实名信息、人脸识别或密码。
- `has_shared_code`：已提供验证码、短信码、动态码或支付码。
- `has_screen_share`：正在或已经开启屏幕共享、远程控制。
- `has_downloaded_app`：已下载或安装对方指定的陌生 App/软件。
- `current_requested_action`：对方当前要求用户做的高危动作。
- `requested_sensitive_info`：对方索要的敏感信息类型。

因此，下面这类表达会直接进入紧急劝阻，而不是普通科普：

```text
最近我手机有一个消息说我中奖了，我点进去那个链接，他要我提供身份证信息，我给他提供了
```

标准化结果：

```json
{
  "primary_intent": "emergency_help",
  "workflow_mode": "risk_case_flow",
  "has_clicked_link": true,
  "has_provided_identity_or_bank": true,
  "requested_sensitive_info": "身份证信息",
  "fraud_candidates": ["虚假中奖/免费礼品诈骗", "钓鱼链接诈骗"]
}
```

典型判定矩阵：

| 用户输入 | 路由结果 | 处理方式 |
| --- | --- | --- |
| 什么是电信诈骗？ | `anti_fraud_qa` / `knowledge_answer` | 科普定义、套路、防范建议 |
| 我在兼职群看到点赞关注就能返佣，这个靠谱吗？ | `risk_help` / `risk_case_flow` | 识别刷单返利风险，询问是否已转账/下载 App |
| 贷款 App 说银行卡填错，要先交解冻费才能放款 | `risk_help` / `risk_case_flow` | 识别网络贷款贷前收费风险，直接阻断付款 |
| 他们说先交 16800 培训费，不就业全额退款 | `risk_help` / `risk_case_flow` | 阻断培训费/培训贷，判断求职实习招聘诈骗 |
| 我已经把验证码给客服了 | `emergency_help` / `risk_case_flow` | 验证码泄露止损，改密、解绑银行卡、联系平台 |
| 中奖链接里要身份证，我已经填了 | `emergency_help` / `risk_case_flow` | 按钓鱼链接和身份信息泄露处理，阻断二次索要验证码/转账/人脸识别 |
| 他要我提供身份证信息，我没有提供 | `risk_help` / `risk_case_flow` | 识别为敏感信息索要预警，但不误判为已泄露 |
| 我被骗了 | `risk_fact_clarification` / `risk_case_flow` | 先补槽确认损失、危险动作、对方身份 |
| 我要举报这个 QQ 号 | `anti_fraud_qa` / `knowledge_answer` | 不进入独立举报流程，给出证据保留和风险处置建议 |
| 帮我看看这个链接安全吗 | `anti_fraud_qa` / `knowledge_answer` | 不进入独立链接检测流程，给出反诈安全建议 |
| 风险案件中又问“校园贷怎么防范？” | `anti_fraud_qa` / `knowledge_answer` | 允许切回科普，避免一直围绕旧话题 |

## 规则包扩展方式

新增骗局优先通过 `app/query_process/rules/scam_packages/*.json` 接入，配置项包括：

- `aliases`：骗局别名、业务场景词、常见口语说法。
- `features`：特征名、关键词、权重和解释。
- `rules`：`all/any/min_any` 条件、风险分、干预目标和话术模板。

规则包无需修改主流程即可被 `ScamRuleEngine` 加载，适合快速接入学生群体常见的新型骗局，例如就业班培训费、游戏交易验号、退费理赔验证码等。

## 实时劝阻目标

实时劝阻不只看诈骗类型，还会按当前危险动作纠偏：

- 已转账或已交付资产：进入止损报警。
- 正在屏幕共享或远程控制：优先关闭会议和远程控制。
- 对方索要验证码、短信码、动态码、登录码：优先阻断验证码泄露。
- 对方要求垫付、充值、补单、押金、培训费、服务费：优先阻断转账付款。

这样可以避免“只说验证码却提示关闭屏幕共享”或“就业培训费被退款关键词误判成客服验证码”的问题。

最终用户可见回答会按以下顺序组织：

1. 风险研判：说明疑似骗局类型、风险等级、当前阶段。
2. 命中的风险特征：列出规则命中的关键依据。
3. 立即劝阻：给出当前最该停止的动作，例如不要转账、不要补单、不要给验证码。
4. 不要继续做：列出本场景下最容易被继续诱导的危险动作。
5. 防范建议：只给与当前场景相关的简短建议。
6. 关键确认：只追问一个最关键槽位，例如是否已经垫付、充值、补单或提现受阻。

例如用户说“好友让我刷单，一单赚50，我已经刷了十几单”，系统会识别为刷单返利诈骗，并追问是否已垫付、充值、补单或转账，而不是继续输出泛化刷单科普。

## 风险状态机

`risk_case_flow` 会把用户多轮对话压缩成案件状态，并围绕风险处置推进：

1. **场景接入**：读取 `RouteDecision`、安全信号和历史案件状态。
2. **补充关键槽位**：确认对方身份、接触渠道、当前要求、是否已转账、是否给验证码、是否屏幕共享、是否下载 App、是否提供身份银行卡信息。
3. **规则研判**：抽取风险特征，匹配诈骗规则包，输出诈骗类型、风险阶段、风险分和命中依据。
4. **实时劝阻**：按当前最高危动作选择 `stop_transfer`、`stop_code_leak`、`stop_screen_share`、`stop_app_install`、`stop_click_link`、`call_police` 等目标。
5. **止损动作**：已损失场景要求联系银行/支付平台止付、拨打 110 或到派出所报案、保存证据。
6. **解除核验**：确认用户是否已经停止操作、保存证据、联系官方渠道、报警或完成账户保护。
7. **复盘科普**：风险解除后进入针对性防范建议和二次受骗提醒，避免继续追问旧风险动作。

## 本次覆盖的多轮场景

- 刷单返利：前期小额返利后要求充值联单，输出 `stop_transfer` 和刷单高危模板。
- 网络贷款/校园贷：贷款 App 以银行卡填错、账户冻结为由要求先交解冻费，输出 `stop_transfer` 和贷款高危模板。
- 游戏交易：私下交易中要求先交装备/账号验货，输出 `stop_transfer`，阻断虚拟资产交付。
- 冒充公检法：自称公安/警察并要求转入安全账户，输出 `stop_transfer`，强调不存在安全账户。
- 虚假投资：投资老师、高收益、陌生 App、提现失败后要求缴税费，输出 `stop_transfer`。
- 冒充客服验证码：上一轮说客服退款，下一轮只说验证码，输出 `stop_code_leak`。
- 冒充客服屏幕共享：上一轮说客服退款，下一轮说下载会议软件并共享屏幕，输出 `stop_screen_share`。
- 求职就业班收费：上一轮说新媒体运营就业班推荐实习月薪 8000，下一轮说先交培训费、不就业退款，输出 `stop_transfer` 和求职招聘诈骗模板。
- 具体场景预警咨询：用户用问句描述真实场景，如“兼职群点赞返佣靠谱吗”，也稳定进入 `risk_case_flow`。
- 旧风险案件切换科普：风险流程内用户改问“什么是电信诈骗/校园贷怎么防范”时，进入 `knowledge_answer`，避免持续围绕最早话题。

## 落地可行性

- 规则与知识完全本地化，核心判定不依赖在线大模型即可工作，适合金融机构、校园场景和客服坐席前置拦截。
- 运行链路支持 MongoDB 在线配置和本地 JSON 回退，适合灰度发布、离线演示和生产容灾。
- 输入输出为结构化字段，便于接入风控工单、坐席系统、App 弹窗和短信/Push 提示。

## 工程化实现

- 统一入口采用 `/knowledge/chat`，前端不需要感知科普与风险劝阻的底层差异。
- 风险判定由 `intent_router`、`ScamRuleEngine`、`realtime_dissuasion_engine` 分层完成，职责清晰。
- 规则包、模板、案例、法条均为 JSON，可直接扩展，无需改动主流程。
- 已补充单测覆盖多轮意图、规则命中、干预目标和法条引用。

## 业务适配度

- 面向学生群体覆盖刷单返利、游戏交易、校园贷、求职培训费、虚假投资等高频场景。
- 面向泛个人用户覆盖冒充客服、公检法、验证码泄露、屏幕共享、钓鱼链接等高危场景。
- 输出不仅给出判断，还给出“先做什么、不要做什么、保留什么证据、去哪核实”的可执行建议，适合真实客服/风控场景。

## 稳定性与可扩展性

- 规则引擎是确定性路径，结果可解释，便于审计和排查。
- 新骗局只需新增诈骗包 JSON、特征和模板即可接入，避免大范围代码改动。
- 实时劝阻层会按“当前危险动作”自动纠偏，减少跨场景模板误用。
- 本地知识库与 Mongo 配置双轨并行，可支持生产扩展和应急降级。

## 代码与文档规范

- 所有知识结构、规则条件和劝阻模板采用统一 JSON 格式，字段命名一致。
- 测试按场景命名，覆盖单轮和多轮，便于回归和定位。
- 文档明确说明模块职责、扩展方式、落地方式和回归命令，方便后续维护与交接。

## 回归命令

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s test -p "test_intent_router.py"
.\.venv\Scripts\python.exe -m unittest discover -s test -p "test_risk_engine.py"
.\.venv\Scripts\python.exe -m unittest discover -s test -p "test_realtime_dissuasion_engine.py"
.\.venv\Scripts\python.exe -m unittest discover -s test -p "test_emergency_dissuasion_workflow.py"
.\.venv\Scripts\python.exe -m unittest discover -s test -p "test_unified_anti_fraud_assistant.py"
.\.venv\Scripts\python.exe -m unittest discover -s test -p "test_knowledge_assistant_chat.py"
.\.venv\Scripts\python.exe -m unittest discover -s test -p "test_student_personal_scenarios.py"
.\.venv\Scripts\python.exe -m unittest discover -s test -p "test_emergency_multiturn_regression.py"
```
