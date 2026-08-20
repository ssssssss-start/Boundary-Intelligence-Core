# 风险劝阻视频审核报告

审核日期：2026-07-31

## 审核范围

本次审核针对 `doc/risk_intervention_video_download_links.md` 中的 12 条优先候选和 3 条备选，共 15 条 B 站官方页面。

逐条核对了：

- 官方页面是否仍可打开并播放。
- 视频标题、页面播放画面或字幕是否与项目诈骗类型匹配。
- B 站账号官方认证主体。
- 视频页面是否存在明显的项目素材广告、二维码、私人联系方式或未处理的敏感隐私信息。
- 页面标注“未经作者授权，禁止转载”时，只保留原始页面链接，不复制视频文件、不镜像视频流、不嵌入播放器。

本报告是“页面链接卡片”审核，不代表取得视频下载、改编、再发布或商业使用授权。

## 审核结果

以下 15 条已写入 MongoDB `risk_video_cards`，状态为 `published`，但权限模式为 `link_only`：

| 诈骗类型 | 视频 ID | 官方账号 | B 站认证主体 | 审核结论 |
|---|---|---|---|---|
| 刷单返利诈骗 | `rv_scam_brush_rebate_BV1G341167UC` | 中国警察网 | 公安部新闻传媒中心中国警察网官方账号 | 通过：标题和播放画面对应刷单话术/返利骗局 |
| 冒充客服诈骗 | `rv_scam_fake_customer_service_BV1gDSWBgEg9` | 衢州网警 | 中共衢州市公安局网络安全保卫支队支部委员 | 通过：标题和播放画面对应冒充客服、诱导添加社交账号 |
| 冒充公检法诈骗 | `rv_scam_fake_police_BV1mtwReFEWv` | 东营网警 | 东营市公安局网络安全保卫支队官方账号 | 通过：标题和播放画面对应警察不会网上办案 |
| 虚假投资理财诈骗 | `rv_scam_fake_investment_BV1wW97YfEFZ` | 阳泉网警 | 阳泉市公安局网络安全保卫支队官方账号 | 通过：标题和播放画面对应数字人民币投资骗局 |
| 网络贷款诈骗 | `rv_scam_fake_loan_BV1Dz4y1i7Qk` | 公安部新闻宣传局 | 公安部新闻宣传局官方账号 | 通过：标题和播放画面对应虚假网络贷款骗局 |
| 屏幕共享/远程控制诈骗 | `rv_scam_screen_remote_control_BV1t42VBNEtJ` | 武汉网警 | 武汉市公安局网络安全保卫支队官方账号 | 通过：标题和播放画面对应屏幕共享风险 |
| 校园二手/票务交易诈骗 | `rv_scam_secondhand_ticket_trade_BV1dW3K6gEzL` | 广东公安 | 广东省公安厅 | 通过：标题和播放画面对应演唱会内部渠道购票骗局 |
| 两卡出租出借与跑分诈骗 | `rv_scam_two_cards_rent_BV1RL3F6HEDT` | 广东公安 | 广东省公安厅 | 通过：标题和播放画面对应跑分洗钱案件 |
| 机票火车票退改签诈骗 | `rv_scam_travel_ticket_refund_BV1E2421K7Wu` | 晋城网警 | 晋城市公安局网络安全保卫支队官方账号 | 通过：标题和播放画面对应机票退改签诈骗 |
| 情感交友诱导投资诈骗 | `rv_scam_romance_investment_BV1urd1BEEHB` | 阳泉网警 | 阳泉市公安局网络安全保卫支队官方账号 | 通过：标题和播放画面对应军恋杀猪盘/网图冒充 |
| 养老保健品诈骗 | `rv_scam_elderly_health_product_BV1RL7N6EEiN` | 广东公安 | 广东省公安厅 | 通过：标题和播放画面对应养老保健品诈骗 |
| 医保骗保/医保卡倒卖诈骗 | `rv_scam_medical_insurance_fund_BV1SUZ8B5Eir` | 阳泉网警 | 阳泉市公安局网络安全保卫支队官方账号 | 通过：标题和播放画面对应医保短信链接骗局 |
| 冒充领导或熟人借钱诈骗 | `rv_scam_acquaintance_borrow_BV1DA411H7hT` | 青海普法 | 青海省司法厅普法与依法治理处官方账号 | 通过：标题和播放画面对应冒充领导熟人诈骗 |
| 屏幕共享/远程控制诈骗 | `rv_scam_screen_remote_control_BV1aNm1BYEDz` | 803 反诈 | 上海市公安局刑事侦查总队 | 通过：标题和播放画面对应手机远程控制/屏幕共享 |
| 养老保健品诈骗 | `rv_scam_elderly_health_product_BV1z3411k7NV` | 中国警察网 | 公安部新闻传媒中心中国警察网官方账号 | 通过：标题和播放画面对应保健品讲座推销风险 |

## 数据权限

所有通过记录统一写入：

```json
{
  "status": "published",
  "source_check_status": "passed",
  "rights_status": "link_only",
  "usage_policy": {
    "direct_link_allowed": true,
    "embed_allowed": false,
    "download_allowed": false
  }
}
```

因此前端会展示官方封面和标题，点击后跳转 B 站原始页面；不会把视频文件下载到项目服务器，也不会把 B 站视频流嵌入项目页面。

## 未纳入

清单中的 16 个待补充类型和 4 条“只作发现线索”的媒体转载链接没有写入正式视频库。后续新增视频仍需重新核对页面有效性、官方主体、主题匹配和页面内容。
