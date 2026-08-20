from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ANNOTATION_DIR = ROOT / "evaluation" / "annotations"
FILES = [ANNOTATION_DIR / "annotator_a.jsonl", ANNOTATION_DIR / "annotator_b.jsonl"]
PRELABEL_DATE = "2026-08-02T20:00:00+08:00"


KNOWLEDGE_TYPES = {
    1: "刷单返利诈骗",
    2: "游戏交易诈骗",
    3: "冒充公检法诈骗",
    4: "虚假投资理财诈骗",
    5: "网络贷款诈骗",
}
KNOWLEDGE_INTENTS = {1: "definition", 2: "technique", 3: "case", 4: "prevention", 5: "law"}


def label(
    workflow: str,
    personal: bool,
    fraud_type: str | None,
    stage: str,
    level: str,
    *,
    candidates: list[str] | None = None,
    features: list[str] | None = None,
    actions: list[str] | None = None,
    intent: str | None = None,
) -> dict:
    return {
        "workflow": workflow,
        "is_personal_risk": personal,
        "fraud_type": fraud_type,
        "candidate_fraud_types": candidates or [],
        "risk_stage": stage,
        "risk_level": level,
        "risk_features": features or [],
        "required_actions": actions or [],
        "knowledge_intent": intent,
    }


def knowledge(fraud_type: str | None, intent: str = "general") -> dict:
    return label(
        "knowledge_answer", False, fraud_type, "knowledge_only", "none",
        actions=["education_only"], intent=intent,
    )


def fallback() -> dict:
    return label("fallback", False, None, "unknown", "none")


def clarification() -> dict:
    return label(
        "clarification", False, None, "unknown", "medium_low",
        actions=["ask_clarification"],
    )


RISK = {
    26: ("刷单返利诈骗", "requested_action", "high", ["小额返利诱导", "垫付联单"], ["stop_operation", "stop_transfer", "preserve_evidence"], []),
    27: ("刷单返利诈骗", "paid", "high", ["连续刷单", "补款提现"], ["stop_operation", "stop_transfer", "contact_bank", "preserve_evidence", "call_96110_or_110"], []),
    28: ("刷单返利诈骗", "active_operation", "critical", ["连续充值任务", "正在支付"], ["stop_operation", "stop_transfer", "contact_bank", "preserve_evidence"], []),
    29: ("刷单返利诈骗", "paid", "high", ["已付款", "最后一单返还承诺"], ["stop_operation", "stop_transfer", "contact_bank", "preserve_evidence", "call_96110_or_110"], []),
    30: ("刷单返利诈骗", "requested_action", "high", ["点赞兼职", "保证金"], ["stop_operation", "stop_transfer", "preserve_evidence"], []),
    31: ("游戏交易诈骗", "requested_action", "high", ["游戏装备", "先交货后付款", "中间人验货"], ["stop_operation", "preserve_evidence", "contact_official_platform"], []),
    32: ("游戏交易诈骗", "requested_action", "high", ["游戏账号交易", "陌生担保平台", "解冻费"], ["stop_operation", "stop_transfer", "preserve_evidence", "contact_official_platform"], []),
    33: ("游戏交易诈骗", "requested_action", "high", ["低价游戏皮肤", "平台外付款", "二维码支付"], ["stop_operation", "stop_transfer", "preserve_evidence", "contact_official_platform"], []),
    34: ("游戏交易诈骗", "requested_action", "high", ["冒充游戏客服", "索要密码", "索要验证码"], ["stop_operation", "do_not_share_code", "change_password", "check_account_bindings", "preserve_evidence", "contact_official_platform"], ["验证码/账户盗刷诈骗", "冒充客服诈骗"]),
    35: ("游戏交易诈骗", "requested_action", "high", ["游戏仓库展示", "要求屏幕共享", "打开支付软件"], ["stop_operation", "disconnect_remote_control", "preserve_evidence", "contact_official_platform"], ["屏幕共享/远程控制诈骗"]),
    36: ("冒充公检法诈骗", "requested_action", "high", ["冒充公安", "安全账户", "资金清查"], ["stop_operation", "stop_transfer", "preserve_evidence", "call_96110_or_110"], []),
    37: ("冒充公检法诈骗", "requested_action", "high", ["虚假通缉令", "要求保密"], ["stop_operation", "preserve_evidence", "call_96110_or_110"], []),
    38: ("冒充公检法诈骗", "active_operation", "critical", ["冒充民警", "会议App", "正在屏幕共享"], ["stop_operation", "disconnect_remote_control", "stop_transfer", "change_password", "check_account_bindings", "preserve_evidence", "call_96110_or_110"], ["屏幕共享/远程控制诈骗"]),
    39: ("冒充公检法诈骗", "requested_action", "high", ["假警察", "电话催促", "资金清查"], ["stop_operation", "stop_transfer", "preserve_evidence", "call_96110_or_110"], []),
    40: ("冒充公检法诈骗", "requested_action", "high", ["威胁抓捕", "索要身份证", "索要银行卡"], ["stop_operation", "do_not_share_code", "preserve_evidence", "call_96110_or_110"], []),
    41: ("虚假投资理财诈骗", "requested_action", "high", ["稳赚承诺", "陌生投资App", "虚拟币投资"], ["stop_operation", "stop_transfer", "preserve_evidence"], []),
    42: ("虚假投资理财诈骗", "post_loss", "high", ["先小额提现", "大额提现受阻", "要求税费"], ["stop_operation", "stop_transfer", "contact_bank", "preserve_evidence", "call_96110_or_110"], []),
    43: ("虚假投资理财诈骗", "post_loss", "high", ["网友带投", "已入金", "账户无法登录"], ["stop_operation", "stop_transfer", "contact_bank", "preserve_evidence", "call_96110_or_110"], []),
    44: ("虚假投资理财诈骗", "requested_action", "high", ["直播间荐股", "内部群", "个人账户转账"], ["stop_operation", "stop_transfer", "preserve_evidence"], []),
    45: ("虚假投资理财诈骗", "post_loss", "high", ["虚假盈利", "提现受阻", "认证费"], ["stop_operation", "stop_transfer", "contact_bank", "preserve_evidence", "call_96110_or_110"], []),
    46: ("网络贷款诈骗", "requested_action", "high", ["无抵押秒到账", "放款前手续费"], ["stop_operation", "stop_transfer", "preserve_evidence"], []),
    47: ("网络贷款诈骗", "requested_action", "high", ["银行卡填错", "刷流水解冻"], ["stop_operation", "stop_transfer", "preserve_evidence"], ["征信修复/注销账户诈骗"]),
    48: ("网络贷款诈骗", "post_loss", "high", ["到账金额少于合同", "砍头息", "服务费"], ["stop_operation", "contact_bank", "preserve_evidence", "contact_official_platform"], []),
    49: ("征信修复/注销账户诈骗", "requested_action", "high", ["征信修复承诺", "先付款", "索要身份和银行卡"], ["stop_operation", "stop_transfer", "do_not_share_code", "preserve_evidence"], ["网络贷款诈骗"]),
    50: ("网络贷款诈骗", "requested_action", "high", ["保证金", "威胁通知学校家长"], ["stop_operation", "stop_transfer", "preserve_evidence"], []),
    51: ("屏幕共享/远程控制诈骗", "exposed", "high", ["冒充退款客服", "远程控制软件", "已授权设备权限"], ["stop_operation", "disconnect_remote_control", "change_password", "check_account_bindings", "contact_bank", "preserve_evidence"], ["冒充客服诈骗"]),
    52: ("钓鱼链接诈骗", "exposed", "high", ["短信链接", "已填写银行卡", "索要验证码"], ["stop_operation", "do_not_share_code", "contact_bank", "change_password", "check_account_bindings", "preserve_evidence"], ["验证码/账户盗刷诈骗"]),
    53: ("冒充老师辅导员收费诈骗", "requested_action", "high", ["冒充辅导员", "班费", "限时扫码转账"], ["stop_operation", "stop_transfer", "preserve_evidence", "contact_official_platform"], []),
    54: ("校园二手/票务交易诈骗", "requested_action", "high", ["演唱会票", "先付定金", "线下取票"], ["stop_operation", "stop_transfer", "preserve_evidence", "contact_official_platform"], []),
    55: ("租房合租押金诈骗", "requested_action", "high", ["未看房", "留房费", "制造紧迫感"], ["stop_operation", "stop_transfer", "preserve_evidence", "contact_official_platform"], []),
    56: ("情感交友诱导投资诈骗", "requested_action", "high", ["长期情感培养", "推荐数字货币投资"], ["stop_operation", "stop_transfer", "preserve_evidence"], ["虚假投资理财诈骗"]),
    57: ("求职实习招聘诈骗", "requested_action", "high", ["境外高薪招聘", "先交签证费", "要求上交护照"], ["stop_operation", "stop_transfer", "preserve_evidence", "contact_official_platform"], []),
    58: ("AI换脸冒充熟人诈骗", "requested_action", "high", ["亲友视频借钱", "行为异常", "紧急转账"], ["stop_operation", "stop_transfer", "preserve_evidence"], ["冒充领导或熟人借钱诈骗"]),
    59: ("屏幕共享/远程控制诈骗", "requested_action", "high", ["冒充快递理赔客服", "掌握订单信息", "要求屏幕共享"], ["stop_operation", "disconnect_remote_control", "preserve_evidence", "contact_official_platform"], ["冒充客服诈骗"]),
    60: ("验证码/账户盗刷诈骗", "resolved", "medium_low", ["曾被索要验证码", "未泄露", "已挂断"], ["check_account_bindings", "preserve_evidence", "contact_official_platform"], []),
    61: (None, "resolved", "medium_low", ["已联系银行", "已报警", "已保存证据"], ["preserve_evidence", "contact_official_platform"], []),
    62: ("钓鱼链接诈骗", "contacted", "medium", ["点击陌生链接", "未填写信息"], ["stop_operation", "change_password", "check_account_bindings", "preserve_evidence"], []),
    63: ("游戏交易诈骗", "exposed", "high", ["游戏密码已泄露", "账户仍可登录"], ["stop_operation", "change_password", "check_account_bindings", "preserve_evidence", "contact_official_platform"], ["验证码/账户盗刷诈骗"]),
    64: (None, "post_loss", "high", ["资金已转出", "要求删除记录"], ["stop_operation", "stop_transfer", "contact_bank", "preserve_evidence", "call_96110_or_110"], []),
    65: ("屏幕共享/远程控制诈骗", "active_operation", "critical", ["冒充客服", "正在屏幕共享", "亲友代求助"], ["stop_operation", "disconnect_remote_control", "stop_transfer", "contact_bank", "change_password", "check_account_bindings", "preserve_evidence"], ["冒充客服诈骗"]),
    96: ("刷单返利诈骗", "requested_action", "high", ["点赞任务", "先免费后付费", "要求垫付"], ["stop_operation", "stop_transfer", "preserve_evidence"], []),
    97: ("冒充公检法诈骗", "active_operation", "critical", ["冒充公安", "正在屏幕共享", "要求保密"], ["stop_operation", "disconnect_remote_control", "stop_transfer", "contact_bank", "change_password", "check_account_bindings", "preserve_evidence", "call_96110_or_110"], ["屏幕共享/远程控制诈骗"]),
    98: ("虚假投资理财诈骗", "post_loss", "high", ["投资平台", "无法提现"], ["stop_operation", "stop_transfer", "contact_bank", "preserve_evidence", "call_96110_or_110"], []),
    99: ("游戏交易诈骗", "resolved", "medium_low", ["曾泄露游戏密码", "已改密", "已退出陌生设备"], ["preserve_evidence", "contact_official_platform"], ["验证码/账户盗刷诈骗"]),
    100: ("网络贷款诈骗", "requested_action", "high", ["曾向贷款客服转账", "新对象要求解冻费"], ["stop_operation", "stop_transfer", "contact_bank", "preserve_evidence", "call_96110_or_110"], []),
}


NEGATIVE = {
    66: knowledge("刷单返利诈骗", "summary"),
    67: knowledge("验证码/账户盗刷诈骗", "technique"),
    68: knowledge(None, "general"),
    69: knowledge(None, "general"),
    70: knowledge("游戏交易诈骗", "prevention"),
    71: knowledge("屏幕共享/远程控制诈骗", "general"),
    72: knowledge("冒充公检法诈骗", "summary"),
    73: knowledge(None, "prevention"),
    74: knowledge("网络贷款诈骗", "compare"),
    75: knowledge(None, "general"),
    76: label("risk_case_flow", True, None, "contacted", "medium_low", features=["仅收到促销短信", "未转账", "未下载软件"], actions=["ask_clarification"]),
    77: label("risk_case_flow", True, "虚假投资理财诈骗", "contacted", "medium_low", features=["收到投资课程", "未要求付款"], actions=["stop_transfer", "education_only"]),
    78: knowledge("虚假投资理财诈骗", "technique"),
    79: knowledge("游戏交易诈骗", "case"),
    80: knowledge("网络贷款诈骗", "compare"),
    81: knowledge("虚假投资理财诈骗", "case"),
    82: knowledge("验证码/账户盗刷诈骗", "prevention"),
    83: knowledge(None, "summary"),
    84: knowledge("冒充公检法诈骗", "technique"),
    85: knowledge("屏幕共享/远程控制诈骗", "prevention"),
}


def labels_for(index: int) -> dict:
    if 1 <= index <= 25:
        group = (index - 1) // 5 + 1
        offset = (index - 1) % 5 + 1
        return knowledge(KNOWLEDGE_TYPES[group], KNOWLEDGE_INTENTS[offset])
    if index in RISK:
        fraud_type, stage, level, features, actions, candidates = RISK[index]
        return label(
            "risk_case_flow", True, fraud_type, stage, level,
            candidates=candidates, features=features, actions=actions,
        )
    if index in NEGATIVE:
        return deepcopy(NEGATIVE[index])
    if 86 <= index <= 90:
        return fallback()
    if 91 <= index <= 95:
        return clarification()
    raise ValueError(f"No labels defined for sample {index}")


def difficulty_for(index: int) -> str:
    if 91 <= index <= 100 or index in {34, 35, 38, 48, 51, 52, 56, 58, 59, 60, 61, 62, 63, 64, 65, 76, 77}:
        return "hard"
    if 26 <= index <= 65:
        return "medium"
    return "easy"


def prelabel_file(path: Path) -> None:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    metadata = rows[0]
    if metadata.get("record_type") != "metadata":
        raise ValueError(f"Missing metadata row in {path}")
    review_slot = metadata.get("annotator_id", path.stem)
    metadata["status"] = "prelabeled_needs_independent_human_review"
    metadata["prelabel_provenance"] = "codex_content_based_v1"
    metadata["prelabel_warning"] = "A/B currently share the same prelabels; do not compute Kappa until each human reviewer independently confirms or edits every row."

    seen = set()
    for row in rows[1:]:
        index = int(row["sample_id"].split("-")[-1])
        if index in seen:
            raise ValueError(f"Duplicate sample index {index} in {path}")
        seen.add(index)
        row["labels"] = labels_for(index)
        row["annotation"] = {
            "annotator_id": f"codex_prelabel_for_{review_slot}",
            "annotated_at": PRELABEL_DATE,
            "difficulty": difficulty_for(index),
            "notes": f"机器辅助预标注；待标注员 {review_slot} 依据原文独立复核，不能直接计入双人一致性。",
        }

    if seen != set(range(1, 101)):
        raise ValueError(f"Expected 100 samples in {path}, got {len(seen)}")
    path.write_text("\n".join(json.dumps(row, ensure_ascii=False) for row in rows) + "\n", encoding="utf-8")


def main() -> None:
    for path in FILES:
        prelabel_file(path)
        print(path)


if __name__ == "__main__":
    main()
