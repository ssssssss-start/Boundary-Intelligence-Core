# 安全基线与部署检查表

## 已实施的基线

- CORS 默认仅允许本机开发来源，通配符必须显式开启不安全开关。
- 管理员密码使用 PBKDF2-HMAC-SHA256 加盐存储。
- 新数据库拒绝自动创建弱默认管理员密码。
- 管理登录连续失败达到阈值后临时锁定，并记录审计日志。
- 管理会话令牌仅保存哈希；Cookie 使用 HttpOnly、SameSite，并可自动/显式启用 Secure。
- 用户端旧版明文凭据键会在页面加载时清理；浏览器仅保存带随机盐的 PBKDF2 凭据摘要，不保存明文密码。
- `/db/init` 仅允许已登录管理员调用。
- `/sessions/{module}/{session_id}` 和 `/history/{session_id}` 删除接口仅允许已登录管理员调用。
- 高成本公共接口按客户端和路径限流，并限制请求体大小。
- API响应添加 nosniff、拒绝嵌入、无缓存等安全响应头。
- 发送给外部LLM前，统一遮蔽手机号、身份证号、银行卡号和验证码；金额保留用于风险研判。
- 会话记忆优先存储脱敏文本和原文哈希。
- 文字、语音转写和截图文字统一生成 allowlist 情绪提示；情绪只调整表达方式，不参与风险事实裁决。

## 生产环境必须配置

```env
ANTI_FRAUD_CORS_ORIGINS=https://your-web.example.com
ANTI_FRAUD_ALLOW_INSECURE_CORS=0
ANTI_FRAUD_ALLOW_INSECURE_DEFAULTS=0
ANTI_FRAUD_ADMIN_USERNAME=your-admin
ANTI_FRAUD_ADMIN_PASSWORD=use-a-unique-secret-from-a-secret-manager
ANTI_FRAUD_REVIEW_ADMIN_USERNAME=your-reviewer
ANTI_FRAUD_REVIEW_ADMIN_PASSWORD=use-another-unique-secret
ANTI_FRAUD_ADMIN_MAX_FAILED_LOGINS=5
ANTI_FRAUD_ADMIN_LOCKOUT_MINUTES=15
ANTI_FRAUD_COOKIE_SECURE=1
ANTI_FRAUD_RATE_LIMIT_WINDOW_SECONDS=60
ANTI_FRAUD_MAX_REQUEST_BODY_BYTES=12582912
```

不要把真实密码或API密钥提交到源码、镜像或演示材料。生产部署应由密钥管理服务或受控环境变量注入。

## 部署边界

1. 使用HTTPS反向代理，并只开放统一入口端口。
2. MongoDB、Milvus和FunASR仅通过Compose内部网络访问，不应直接暴露到公网。
3. 为MongoDB启用身份认证、最小权限用户和备份加密。
4. 将管理员Cookie设置为Secure，并在反向代理正确传递`X-Forwarded-Proto: https`。
5. 定期清理过期会话、原始聊天兼容数据和审计日志；按比赛演示数据制定保存期限。
6. 对日志采集平台再次执行敏感字段过滤，禁止记录请求正文、Cookie和API密钥。

## 当前仍需后续处理的风险

- 旧版兼容聊天记录路径仍可能保存原文，需要完成数据迁移后关闭。
- 当前限流为单进程内存实现，多实例部署应改为Redis集中限流。
- 尚未完成MongoDB静态数据加密、集中密钥管理和完整数据保留策略。
- 尚需增加提示词注入、越权访问、依赖漏洞和恶意文件专项测试。
- 本地开发仍使用HTTP；这只适合受控演示环境。

## 验证命令

```bash
python -m pytest -q tests/test_security_baseline.py
python scripts/run_direction3_evaluation.py
```
