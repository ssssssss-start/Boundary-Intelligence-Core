# 方向三评测集标注指南（v1.0）

## 1. 标注原则

1. 只依据用户明确陈述和对话上下文，不补充未出现的事实。
2. 标注者不得查看系统预测、规则命中或另一位标注者的结果。
3. 情绪、语气急迫不等于高风险；风险等级由行为、暴露和损失决定。
4. 出现“转账、验证码、诈骗”等词不等于个人风险，必须区分科普、新闻、作业和真实处境。
5. 无法可靠判断时使用`clarification`或`unknown`，不要强行归类。

## 2. workflow 场景路由

| 标签 | 定义 | 例子 |
|---|---|---|
| `knowledge_answer` | 用户在了解反诈知识，没有描述本人当前险情 | “刷单诈骗是什么？” |
| `risk_case_flow` | 用户本人、亲友正在接触可疑对象，或已操作、暴露、损失 | “对方让我补单，我已经付了500。” |
| `fallback` | 闲聊、感谢、身份询问、语音纠正 | “谢谢你”“你是谁” |
| `clarification` | 文本含义不足以判断想学习还是正在遇险 | “这个怎么办？”且无上下文 |

## 3. fraud_type 诈骗类型

优先使用`data/knowledge/scam_types.json`中的标准名称。比赛五类必须使用：

- `刷单返利诈骗`
- `游戏交易诈骗`
- `冒充公检法诈骗`
- `虚假投资理财诈骗`
- `网络贷款诈骗`（包含校园贷包装）

无法区分时标记`unknown`，并在`candidate_fraud_types`列出最多三个候选。

## 4. risk_stage 风险阶段

| 标签 | 判断标准 |
|---|---|
| `knowledge_only` | 纯知识学习 |
| `contacted` | 已收到或接触可疑信息，尚无高危要求 |
| `requested_action` | 对方提出转账、验证码、下载App、远控等要求 |
| `active_operation` | 用户正在执行高危操作 |
| `exposed` | 已泄露验证码、账户、身份信息或设备权限 |
| `paid` | 已付款，但是否形成最终损失尚不明确 |
| `post_loss` | 已确认资金、资产或账户控制损失 |
| `resolved` | 已停止危险操作并完成关键处置 |
| `unknown` | 信息不足 |

多阶段同时存在时，选择已经发生的最高阶段。

## 5. risk_level 风险等级

| 标签 | 判断标准 |
|---|---|
| `none` | 非个人险情或没有风险事实 |
| `medium_low` | 声称可疑但关键事实不足 |
| `medium` | 命中诈骗特征，尚无明确高危要求或暴露 |
| `high` | 对方提出高危要求，或已发生信息/账户/资金暴露 |
| `critical` | 正在转账、正在远控/共享屏幕、持续被催促操作等需立即制止的情况 |

## 6. required_actions 多标签

可选值：

```text
stop_operation
stop_transfer
disconnect_remote_control
do_not_share_code
contact_bank
change_password
check_account_bindings
preserve_evidence
contact_official_platform
call_96110_or_110
education_only
ask_clarification
```

只标注当前阶段必要的动作。例如尚未付款的科普问题通常只标`education_only`；正在屏幕共享至少应标`stop_operation`和`disconnect_remote_control`。

## 7. knowledge_intent

仅知识咨询填写，其他场景填`null`：

```text
definition
technique
case
prevention
law
compare
summary
general
```

## 8. 多轮对话

- 短回答必须结合前文，例如“已经给了”不能单独解释。
- 用户明确否认的事实不能沿用为真。
- 上一案件已关闭后出现新对象、新平台或新金额，应标为新案件。
- `turn_under_test`表示本样本主要评测哪一轮，默认最后一轮。

## 9. 分歧处理

标注员A、B分别完成后运行一致性脚本。任何以下字段不一致都进入仲裁：

- `workflow`
- `fraud_type`
- `risk_stage`
- `risk_level`
- `required_actions`

仲裁者必须记录`decision_reason`，不得只覆盖标签。

## 10. 试标门槛

先对同一批100条候选进行双人试标。路由、诈骗类型和风险等级的Cohen’s Kappa达到`0.80`后，再开始正式500–1000条数据生产。

