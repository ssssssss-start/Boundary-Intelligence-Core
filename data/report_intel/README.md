# 举报研判数据库

这个目录是“可疑链接 / 内容一键举报”的独立研判数据域，只服务一键举报初判，不参与反诈科普知识检索，也不参与多轮实时劝阻的风险规则。

数据边界：
- `scam_types.json`：举报侧诈骗类型、别名、默认建议和证据提醒。
- `risk_phrases.json`：可疑文本、短信、聊天内容中的高危话术特征。
- `url_rules.json`：URL 结构特征规则。
- `rule_combos.json`：多特征组合研判规则。
- `domain_allowlist.json`：常见官方或正常业务域名白名单，用于降低误报。
- `domain_watchlist.json`：域名、路径、品牌仿冒相关观察项。
- `negative_samples.json`：负样本，用于回归测试普通链接或普通话术不被误判。
- `evidence_requirements.json`：不同骗局建议保留的举报证据。
- `display_policy.json`：前端展示文案和空状态策略。
- `source_registry.json`：数据来源登记。

维护原则：
- 官方来源优先，运营补充必须脱敏、去重、人工复核。
- 大模型只能用于扩展候选词和测试样例，不能作为事实来源。
- 白名单和负样本必须和风险规则一起维护，避免普通链接被说成可疑。
