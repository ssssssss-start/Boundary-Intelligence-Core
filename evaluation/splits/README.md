# 数据集切分目录

正式切分建议：开发集25%、验证集25%、盲测集50%。必须按`case_family_id`分组切分，禁止同一公开案件的不同改写跨集合。

试标数据不得直接进入`blind_test.jsonl`。盲测标签应由非开发成员保管；开发者只接触去掉`labels`的`blind_test_inputs.jsonl`。

当前 `development.jsonl` 已登记用户补充的 210 条增强样本。原始样本与改写样本共享 `case_family_id`，因此必须整体留在开发集；`validation.jsonl` 和 `blind_test.jsonl` 仍为空，不能把这批数据当作独立盲测结果。
