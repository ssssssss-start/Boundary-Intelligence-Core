# 方向三评测基准

运行离线、确定性基线：

```bash
python scripts/run_direction3_evaluation.py
```

输入数据位于`evaluation/direction3_benchmark.json`，生成：

- `reports/evaluation/direction3_evaluation.md`
- `reports/evaluation/direction3_evaluation.json`

基准覆盖场景路由、风险召回与误报、赛题指定五类骗局、知识问答意图、知识资产规模和本地处理延迟。运行器不调用外部LLM，适合作为持续集成回归门槛。

当前数据集是工程基线，样本数量较小且由项目团队维护。比赛正式指标必须另建由独立人员盲标、评测前冻结、不得针对失败样本即时调规则的测试集，避免数据泄漏和过拟合。

## 用户补充标注集

当前任务中由用户提供的 105 条种子描述和每条 1 条语义保持一致的改写位于：

- `evaluation/annotations/user_labeled_105.jsonl`
- `evaluation/annotations/user_augmented_210.jsonl`
- `evaluation/annotations/user_annotation_manifest.json`

两条样本属于同一个 `case_family_id`，只能在同一个开发或验证切分中使用；这批数据不是独立盲测集。结构化标签中的诈骗类别来自用户分组，风险阶段、风险等级和必要动作是规则初标，正式盲测前仍需人工复核或双人仲裁。
