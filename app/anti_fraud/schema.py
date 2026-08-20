from typing import Dict, List


FRAUD_TYPES: List[str] = [
    "刷单返利诈骗",
    "游戏交易诈骗",
    "虚假投资理财诈骗",
    "网络贷款诈骗",
    "冒充客服诈骗",
    "冒充公检法诈骗",
    "杀猪盘诈骗",
    "钓鱼链接诈骗",
    "验证码/账户盗刷诈骗",
    "屏幕共享/远程控制诈骗",
    "冒充熟人诈骗",
    "虚假购物服务诈骗",
    "冒充老师辅导员收费诈骗",
    "求职实习招聘诈骗",
    "奖助学金/学费退费诈骗",
    "考试考证论文服务诈骗",
    "校园二手/票务交易诈骗",
    "租房合租押金诈骗",
    "裸聊敲诈勒索诈骗",
    "两卡出租出借与跑分诈骗",
    "机票火车票退改签诈骗",
    "虚假中奖/免费礼品诈骗",
    "征信修复/注销账户诈骗",
    "情感交友诱导投资诈骗",
    "AI换脸冒充熟人诈骗",
    "冒充领导或熟人借钱诈骗",
    "未知",
]

FRAUD_STAGES: List[str] = [
    "初步接触阶段",
    "引流诱导阶段",
    "建立信任阶段",
    "小额试探阶段",
    "资金转账前阶段",
    "资金转账阶段",
    "信息索取阶段",
    "信息泄露阶段",
    "提现受阻阶段",
    "损失发生阶段",
    "止损报警阶段",
    "科普学习",
    "未知",
]

RISK_FEATURES: List[str] = [
    "陌生人引导",
    "任务返佣",
    "要求垫付资金",
    "承诺返利",
    "小额返利",
    "大额垫付",
    "无法提现",
    "诱导下载陌生APP",
    "高收益诱导",
    "保本稳赚承诺",
    "陌生投资平台",
    "索要验证码",
    "索要银行卡或身份信息",
    "点击陌生链接",
    "私下交易",
    "低价代充",
    "账号密码索取",
    "贷款前收费",
    "校园贷包装",
    "要求继续补单",
    "已发生转账",
    "要求缴纳解冻费",
    "要求删除证据",
    "冒充客服",
    "冒充公检法",
    "屏幕共享",
    "远程控制",
    "已泄露验证码",
    "熟人新账号联系",
    "非本人账户收款",
    "拒绝二次核验",
    "仿冒异常域名",
    "AI换脸冒充",
]

# Older Mongo rule snapshots contain a few labels that describe the same
# behaviour with a different wording.  Rules are normalised through this map
# before matching so an alias never causes the whole rule to be discarded.
RISK_FEATURE_ALIASES: Dict[str, str] = {
    "不方便电话核实": "拒绝二次核验",
    "拒绝电话核验": "拒绝二次核验",
    "拒绝回拨核实": "拒绝二次核验",
    "AI换脸": "AI换脸冒充",
    "冒充客服退款理赔": "冒充客服",
    "客服退款理赔": "冒充客服",
    "继续做单": "要求继续补单",
    "继续补单要求": "要求继续补单",
    "保本承诺": "保本稳赚承诺",
    "稳赚承诺": "保本稳赚承诺",
}

RISK_FEATURE_SYNONYMS: Dict[str, List[str]] = {
    "陌生人引导": ["陌生人", "网友", "有人加我", "群里", "老师", "导师", "陌生客服", "陌生账号", "新加我", "新账号", "领导新加", "卖家", "私聊", "网恋", "网恋对象", "交友", "对象"],
    "任务返佣": ["做任务", "刷单", "点赞", "关注", "抢单", "返佣", "兼职", "任务赚钱"],
    "要求垫付资金": ["垫付", "先交钱", "先转钱", "先交", "先把钱转", "转走", "资金清查", "预付款", "充值", "保证金", "押金", "定金", "订金", "运费", "补差价", "激活费", "认证金", "解冻费", "手续费", "补单", "联单", "资料费", "刷流水", "税费", "借钱", "借款", "周转", "代付", "帮他付", "帮忙转"],
    "承诺返利": ["返利", "返现", "返佣", "返钱", "马上返", "本金返", "收益", "回报", "返400", "高佣金"],
    "小额返利": ["小额返利", "先返", "返了几块", "返了几十", "试单返现"],
    "大额垫付": ["大额垫付", "大额订单", "加大投入", "大单", "连单"],
    "无法提现": ["提现失败", "不能提现", "无法提现", "提现前", "账户冻结", "冻结", "风控", "解冻"],
    "诱导下载陌生APP": ["下载APP", "下载app", "下载一个", "陌生App", "陌生APP", "安装软件", "陌生软件", "投资软件", "投资App", "投资APP", "贷款APP", "会议软件"],
    "高收益诱导": ["高收益", "高回报", "高额收益", "短期收益", "收益", "稳赚", "翻倍", "日赚", "暴利", "内部收益", "盈利很多"],
    "保本稳赚承诺": ["保本", "稳赚", "无风险", "包赚", "稳赚不赔"],
    "陌生投资平台": ["投资平台", "投资App", "投资APP", "投资app", "投资软件", "理财平台", "交易平台", "数字货币平台", "陌生平台", "非官方平台", "虚拟币投资", "虚拟币", "平台一直盈利"],
    "索要验证码": ["验证码", "短信码", "动态码", "验证码发我"],
    "索要银行卡或身份信息": ["银行卡", "身份证", "账号密码", "微信密码", "登录密码", "支付密码", "人脸识别", "身份证照片"],
    "点击陌生链接": ["链接", "网址", "二维码", "点开", "打开链接", "短信链接", "http://", "https://", "login", "security", "verify"],
    "私下交易": ["私下交易", "平台外", "脱离平台", "个人账户", "先把账号", "先发账号", "账号交易", "加私聊", "私聊", "不能走平台", "不走平台"],
    "低价代充": ["低价代充", "半价充值", "代充", "低价充值", "点券", "皮肤"],
    "账号密码索取": ["账号密码", "微信密码", "登录密码", "支付密码", "把账号密码发", "把密码告诉", "要我的密码", "验号"],
    "贷款前收费": ["贷款", "借款", "放款", "刷流水", "包装费", "会员费", "贷前收费"],
    "校园贷包装": ["校园贷", "学生贷款", "包装资料", "资料费", "学生资料"],
    "要求继续补单": ["补单", "联单", "连单", "继续做单", "任务没完成", "补任务"],
    "已发生转账": ["已经转了", "已转", "转了钱", "转了", "付了", "付过钱", "打款", "付款了", "汇款"],
    "要求缴纳解冻费": ["解冻费", "保证金解冻", "缴税", "税费", "认证费", "解封费"],
    "要求删除证据": ["删除聊天", "删记录", "不要报警", "别告诉别人", "清空聊天"],
    "冒充客服": ["自称客服", "客服称", "客服让", "平台客服", "快递客服", "物流客服", "电商客服", "网店客服", "航司客服", "领奖客服", "补贴办理员", "客服来电", "退款", "理赔", "售后", "取消会员", "百万保障"],
    "冒充公检法": ["公安", "民警", "办案民警", "办案人员", "警察", "检察院", "法院", "公检法", "通缉令", "法律文书", "涉密", "调查", "视频做笔录", "资金审查", "安全账户", "涉案", "涉嫌洗钱"],
    "屏幕共享": ["共享屏幕", "屏幕共享", "远程会议", "视频会议"],
    "远程控制": ["远程控制", "远程协助", "控制手机", "控制电脑"],
    "已泄露验证码": ["已经给了验证码", "验证码发给了", "泄露验证码", "填了验证码"],
    "熟人新账号联系": ["熟人新账号", "换了新号", "新微信联系", "陌生账号冒充熟人"],
    "非本人账户收款": ["转到别人账户", "非本人账户", "第三方账户", "陌生账号收款", "只能通过陌生账号收款"],
    "拒绝二次核验": ["拒绝接电话", "不方便电话", "拒绝回拨", "不让核实", "只说几句话就挂断"],
    "仿冒异常域名": ["仿冒网站", "异常域名", "假官网", "高仿网站"],
    "AI换脸冒充": ["AI换脸", "AI 换脸", "拟声", "视频里像", "声音很像", "仿冒亲友", "仿冒亲属"],
}

KNOWLEDGE_TYPES: List[str] = [
    "fraud_definition",
    "fraud_process",
    "fraud_case",
    "risk_signal",
    "prevention_advice",
    "intervention_action",
    "police_report_guide",
    "evidence_guide",
    "bank_stop_guide",
    "persuasion_script",
    "education_summary",
]

KNOWLEDGE_TYPE_LABELS: Dict[str, str] = {
    "fraud_definition": "诈骗定义",
    "fraud_process": "诈骗流程",
    "fraud_case": "典型案例",
    "risk_signal": "风险信号",
    "prevention_advice": "防范建议",
    "intervention_action": "干预动作",
    "police_report_guide": "报警指引",
    "evidence_guide": "证据保存指引",
    "bank_stop_guide": "银行或支付止付指引",
    "persuasion_script": "劝阻话术",
    "education_summary": "科普总结",
}

ROUTES: List[str] = [
    "prevention_consult",
    "loss_response",
    "education",
]

INTERVENTION_GOALS: List[str] = [
    "ask_clarification",
    "stop_transfer",
    "stop_app_install",
    "stop_code_leak",
    "stop_screen_share",
    "preserve_evidence",
    "call_bank",
    "call_police",
    "report_platform",
    "educate",
]

RISK_LEVELS: List[str] = [
    "高风险",
    "中风险",
    "低风险",
    "风险未知",
    "不适用",
]

REQUIRED_KNOWLEDGE_FIELDS: List[str] = [
    "knowledge_id",
    "knowledge_type",
    "fraud_type",
    "fraud_stage",
    "title",
    "summary",
    "content",
    "risk_tags",
    "applicable_routes",
    "applicable_case_types",
    "intervention_goals",
    "user_stage",
    "use_when",
    "do_not_use_when",
    "answer_role",
    "priority",
    "risk_level",
    "source",
]


def build_embedding_text(item: dict) -> str:
    risk_tags = item.get("risk_tags") or []
    risk_tags_text = "、".join(risk_tags) if isinstance(risk_tags, list) else str(risk_tags)
    routes = item.get("applicable_routes") or []
    routes_text = "、".join(routes) if isinstance(routes, list) else str(routes)
    goals = item.get("intervention_goals") or []
    goals_text = "、".join(goals) if isinstance(goals, list) else str(goals)
    case_types = item.get("applicable_case_types") or []
    case_types_text = "、".join(str(value) for value in case_types) if isinstance(case_types, list) else str(case_types)
    knowledge_type = item.get("knowledge_type", "")
    knowledge_type_label = KNOWLEDGE_TYPE_LABELS.get(knowledge_type, knowledge_type)
    return "\n".join([
        f"诈骗类型：{item.get('fraud_type', '')}",
        f"诈骗阶段：{item.get('fraud_stage', '')}",
        f"知识类型：{knowledge_type_label}",
        f"适用路径：{routes_text}",
        f"适用案件类型：{case_types_text}",
        f"干预目标：{goals_text}",
        f"标题：{item.get('title', '')}",
        f"摘要：{item.get('summary', '')}",
        f"风险标签：{risk_tags_text}",
        f"风险等级：{item.get('risk_level', '')}",
        f"用户阶段：{item.get('user_stage', '')}",
        f"适用条件：{item.get('use_when', '')}",
        f"不适用条件：{item.get('do_not_use_when', '')}",
        f"回答作用：{item.get('answer_role', '')}",
        f"内容：{item.get('content', '')}",
    ]).strip()


def normalize_risk_features(values: List[str] | None, text: str = "") -> List[str]:
    normalized = set()
    raw_values = values or []

    for value in raw_values:
        value = str(value or "").strip()
        canonical = RISK_FEATURE_ALIASES.get(value, value)
        if canonical in RISK_FEATURES:
            normalized.add(canonical)

    search_text = " ".join(raw_values) + " " + (text or "")
    for canonical, synonyms in RISK_FEATURE_SYNONYMS.items():
        if canonical in search_text or any(word in search_text for word in synonyms):
            normalized.add(canonical)

    return [feature for feature in RISK_FEATURES if feature in normalized]
