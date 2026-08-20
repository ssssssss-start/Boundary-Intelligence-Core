"""Four-dimensional anti-fraud engine result normalizer.

The runtime already has separate routing, rule scoring, dissuasion, URL, and
report services.  This module converts those scattered internal results into a
single frontend-friendly contract:

service function, scam scene, risk stage, and risk level.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List

from app.anti_fraud.taxonomy import canonicalize_fraud_types, fraud_type_metadata


FUNCTION_KNOWLEDGE = "knowledge_education"
FUNCTION_INTERVENTION = "real_time_intervention"
FUNCTION_REPORT = "suspicious_report"
FUNCTION_ASSESSMENT = "risk_assessment"
FUNCTION_CLARIFICATION = "clarification"
FUNCTION_SMALLTALK = "smalltalk"

HANDLED_CASE_STATUSES = {"prevented", "stop_loss_done", "education_ready", "closed", "non_risk_task"}

SCENE_ALIASES = [
    ("brushing_rebate", "刷单返利诈骗", ["刷单", "返利", "返佣", "做任务", "点赞", "关注", "补单"]),
    ("game_trade", "游戏交易诈骗", ["游戏交易", "游戏装备", "游戏账号", "装备", "皮肤", "点券", "代充", "代练"]),
    ("fake_police", "冒充公检法诈骗", ["冒充公检法", "公检法", "公安", "警察", "法院", "检察院", "安全账户", "涉案"]),
    ("fake_investment", "虚假投资理财诈骗", ["投资", "理财", "虚拟币", "高收益", "稳赚", "老师带单", "提现失败"]),
    ("campus_loan", "校园贷/网络贷款诈骗", ["校园贷", "网络贷款", "贷款", "借款", "解冻费", "刷流水"]),
    ("fake_customer_service", "冒充客服退款诈骗", ["冒充客服", "客服", "退款", "理赔", "快递", "售后", "会议软件"]),
    ("phishing_link", "钓鱼链接/虚假网站", ["钓鱼链接", "虚假网站", "链接", "网址", "login", "verify", "二维码"]),
    ("account_theft", "账号盗取/验证码诈骗", ["验证码", "短信码", "动态码", "账号盗", "账号密码", "支付密码"]),
    ("screen_share", "屏幕共享/远程控制诈骗", ["屏幕共享", "共享屏幕", "远程控制", "远程协助"]),
    ("romance_investment", "杀猪盘/情感投资诈骗", ["杀猪盘", "网恋", "恋爱", "交友", "情感", "婚恋"]),
    ("acquaintance_impersonation", "冒充熟人诈骗", ["冒充熟人", "领导", "亲友", "同学", "同事", "室友", "舍友", "换号", "新微信号"]),
    ("job_recruitment", "求职实习招聘诈骗", ["求职", "实习", "招聘", "就业班", "培训费", "保offer", "推荐实习"]),
    ("prize_gift", "虚假中奖/免费礼品诈骗", ["中奖", "领奖", "兑奖", "免费领", "抽中", "福利礼品"]),
    ("shopping_service", "虚假购物服务诈骗", ["虚假购物", "演唱会票", "门票", "二手", "定金", "订金", "不走平台"]),
    ("rental_deposit", "租房合租押金诈骗", ["租房", "合租", "房东", "押金", "看房"]),
]

INTENT_DISPLAY_NAMES = {
    FUNCTION_KNOWLEDGE: "反诈知识普及",
    FUNCTION_INTERVENTION: "风险行为实时劝阻",
    FUNCTION_REPORT: "可疑链接/内容一键举报",
    FUNCTION_ASSESSMENT: "风险场景智能研判",
    FUNCTION_CLARIFICATION: "关键信息补充",
    FUNCTION_SMALLTALK: "普通引导",
}

STAGE_DESCRIPTIONS = {
    "before_learning": "用户主要在学习、防范或了解骗局，还没有进入个人风险处境。",
    "contact_lure": "用户已经接触可疑人员、链接、广告或话术，但损失事实尚未确认。",
    "action_boundary": "对方正在推动转账、验证码、共享屏幕、下载陌生 App 或填写敏感信息等高危动作。",
    "loss_or_exposure": "用户已经发生转账、虚拟资产交付、验证码/身份银行卡信息泄露或设备控制暴露。",
    "mitigation": "用户已进入止损、报警、冻结、保存证据或复盘科普阶段。",
    "content_discovered": "用户提交了可疑链接、短信、聊天内容或账号线索，系统正在做初步研判。",
    "unknown": "当前事实不足，等待用户补充关键信息。",
}

HIGH_DANGER_FEATURES = {
    "已发生转账",
    "虚拟资产已交付",
    "索要验证码",
    "索要银行卡或身份信息",
    "账号密码索取",
    "屏幕共享",
    "远程控制",
    "诱导下载陌生APP",
    "点击陌生链接",
    "要求垫付资金",
    "贷款前收费",
    "要求继续补单",
    "要求缴纳解冻费",
    "无法提现",
}


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _dedupe(items: Iterable[Any], limit: int = 12) -> List[str]:
    result: List[str] = []
    for item in items:
        text = str(item or "").strip()
        if text and text not in result:
            result.append(text)
        if len(result) >= limit:
            break
    return result


def _dedupe_dicts(items: Iterable[Dict[str, Any]], key_fields: Iterable[str], limit: int = 8) -> List[Dict[str, Any]]:
    result: List[Dict[str, Any]] = []
    seen = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        key = "|".join(str(item.get(field) or "") for field in key_fields).strip("|")
        if not key:
            key = str(item)
        if key in seen:
            continue
        result.append(item)
        seen.add(key)
        if len(result) >= limit:
            break
    return result


def _is_truthy(value: Any) -> bool:
    return value is True or str(value).lower() in {"true", "1", "yes", "y"}


def _risk_level_rank(level: str) -> int:
    text = str(level or "")
    if any(word in text for word in ["紧急", "极高", "urgent"]):
        return 4
    if "高" in text or text == "high":
        return 3
    if "中" in text or text == "medium":
        return 2
    if "低" in text or text == "low":
        return 1
    return 0


def _level_tone(level: str, score: int) -> str:
    text = str(level or "")
    if score >= 76 or any(word in text for word in ["紧急", "极高", "urgent", "critical"]):
        return "critical"
    if score >= 51 or "高" in text or text == "high":
        return "high"
    if score >= 21 or "中" in text or text == "medium":
        return "medium"
    if score > 0 or "低" in text or text == "low":
        return "low"
    return "unknown"


def normalize_risk_level(score: int | float | str | None, raw_level: str = "") -> Dict[str, Any]:
    try:
        numeric = int(float(score or 0))
    except (TypeError, ValueError):
        numeric = 0
    raw_level = str(raw_level or "")
    if numeric >= 76 or "极高" in raw_level or "紧急" in raw_level:
        return {"risk_level": "urgent", "risk_level_name": "紧急风险", "risk_score": numeric}
    if numeric >= 51 or "高风险" in raw_level:
        return {"risk_level": "high", "risk_level_name": "高风险", "risk_score": numeric}
    if numeric >= 21 or "中" in raw_level:
        return {"risk_level": "medium", "risk_level_name": "中风险", "risk_score": numeric}
    if numeric > 0 or "低" in raw_level:
        return {"risk_level": "low", "risk_level_name": "低风险", "risk_score": numeric}
    return {"risk_level": "unknown", "risk_level_name": "风险未知", "risk_score": numeric}


def scene_from_text(*values: Any) -> Dict[str, str]:
    text = " ".join(str(value or "") for value in values)
    for tag, name, aliases in SCENE_ALIASES:
        if any(alias and alias in text for alias in aliases):
            return {"risk_scene": tag, "risk_scene_name": name}
    return {"risk_scene": "unknown_risk", "risk_scene_name": "未知风险场景"}


def _canonical_scene(scene: Dict[str, str], authoritative_scene: str) -> Dict[str, str]:
    text = str(authoritative_scene or "").strip()
    if text and text not in {"未知", "未知风险", "暂未识别诈骗风险"}:
        inferred = scene_from_text(text)
        if inferred.get("risk_scene") != "unknown_risk":
            return inferred
        return {
            "risk_scene": re.sub(r"\W+", "_", text.lower()).strip("_")[:40] or "custom_risk",
            "risk_scene_name": text,
        }
    return scene


def _truthy_text(value: Any) -> bool:
    return str(value or "").strip().lower() in {"true", "1", "yes", "y", "paid", "loss_confirmed"}


def _judgement_stage(
    *,
    function_route: str,
    route_decision: Dict[str, Any],
    risk_result: Dict[str, Any],
    report_result: Dict[str, Any],
    url_result: Dict[str, Any],
    hit_features: List[str],
    scene: Dict[str, str],
) -> Dict[str, str]:
    case_status = str(risk_result.get("case_status") or "").strip()
    if case_status in HANDLED_CASE_STATUSES or risk_result.get("risk_resolved"):
        code, name = "mitigation", "止损处理中"
    elif function_route == FUNCTION_KNOWLEDGE:
        code, name = "before_learning", "事前了解"
    elif function_route == FUNCTION_REPORT or report_result or url_result:
        code, name = "content_discovered", "可疑内容发现"
    elif (
        risk_result.get("has_loss_or_exposure")
        or _truthy_text(risk_result.get("has_paid"))
        or str(risk_result.get("loss_status") or "") == "loss_confirmed"
        or any(feature in {"已发生转账", "虚拟资产已交付"} for feature in hit_features)
    ):
        code, name = "loss_or_exposure", "已暴露/已损失"
    elif (
        any(feature in HIGH_DANGER_FEATURES for feature in hit_features)
        or (route_decision.get("risk_signals") or {}).get("has_current_transfer_request")
        or (route_decision.get("safety_signals") or {}).get("requested_action_signal")
    ):
        code, name = "action_boundary", "行为临界"
    elif scene.get("risk_scene") and scene.get("risk_scene") != "unknown_risk":
        code, name = "contact_lure", "接触诱导"
    else:
        code, name = "unknown", "事实不足"
    return {
        "code": code,
        "name": name,
        "description": STAGE_DESCRIPTIONS.get(code, ""),
    }


def _evidence_items(hit_features: List[str], matched_rules: List[str], explanation: str) -> Dict[str, Any]:
    features = _dedupe(hit_features, limit=5)
    rules = _dedupe(matched_rules, limit=4)
    summary_parts = []
    if features:
        summary_parts.append("命中特征：" + "、".join(features[:3]))
    if rules:
        summary_parts.append("命中规则：" + "、".join(rules[:2]))
    if not summary_parts and explanation:
        summary_parts.append(str(explanation)[:120])
    return {
        "summary": "；".join(summary_parts) if summary_parts else "暂无明确命中依据，需继续补充事实。",
        "features": features,
        "rules": rules,
    }


def _authoritative_scene_source(
    *,
    risk_result: Dict[str, Any],
    report_result: Dict[str, Any],
    url_result: Dict[str, Any],
    route_decision: Dict[str, Any],
    memory_context: Dict[str, Any],
) -> str:
    """Return the single fraud-type source used for frontend scene display."""
    case_state = (memory_context or {}).get("case_state") or {}
    scam_memory = case_state.get("scam_memory") or case_state.get("scam_understanding") or {}
    route_frame = (route_decision or {}).get("semantic_frame") or {}
    candidates = [
        report_result.get("fraud_type"),
        report_result.get("suspected_type"),
        report_result.get("primary_type"),
        risk_result.get("fraud_type"),
        risk_result.get("primary_type"),
        risk_result.get("scam_type"),
        (risk_result.get("rule_engine") or {}).get("fraud_type") if isinstance(risk_result.get("rule_engine"), dict) else "",
        case_state.get("fraud_type"),
        scam_memory.get("primary_scam_type"),
        scam_memory.get("primary_scam_type_name"),
        route_decision.get("normalized_topic"),
        route_decision.get("fraud_type_id"),
        *(route_frame.get("fraud_candidates") or []),
        url_result.get("suspected_type"),
    ]
    for candidate in candidates:
        text = str(candidate or "").strip()
        if text and text not in {"未知", "未知风险", "暂未识别诈骗风险"}:
            return text
    return ""


def _stage_from_raw(
    *,
    function_route: str,
    route_decision: Dict[str, Any],
    risk_result: Dict[str, Any],
    report_result: Dict[str, Any],
    url_result: Dict[str, Any],
) -> Dict[str, str]:
    risk_signals = route_decision.get("risk_signals") or {}
    safety_signals = route_decision.get("safety_signals") or {}
    raw_stage = str(
        risk_result.get("risk_stage")
        or risk_result.get("fraud_stage")
        or (route_decision.get("semantic_frame") or {}).get("risk_stage")
        or ""
    )
    if function_route == FUNCTION_REPORT:
        return {"risk_stage": "discovered", "risk_stage_name": "发现时处理"}
    if risk_signals.get("confirmed_exposure_signal") or safety_signals.get("confirmed_exposure_signal"):
        return {"risk_stage": "after", "risk_stage_name": "事后处理"}
    if (
        function_route == FUNCTION_INTERVENTION
        or safety_signals.get("requested_action_signal")
        or risk_signals.get("has_current_transfer_request")
        or any(word in raw_stage for word in ["转账前", "信息索取", "验证码", "屏幕共享", "下载陌生"])
    ):
        return {"risk_stage": "during", "risk_stage_name": "事中干预"}
    if function_route == FUNCTION_KNOWLEDGE or "科普" in raw_stage or "学习" in raw_stage:
        return {"risk_stage": "before", "risk_stage_name": "事前预防"}
    if function_route == FUNCTION_ASSESSMENT:
        return {"risk_stage": "full_process", "risk_stage_name": "全流程研判"}
    if url_result:
        return {"risk_stage": "discovered", "risk_stage_name": "发现时处理"}
    return {"risk_stage": "unknown", "risk_stage_name": "阶段未知"}


def _function_from_route(route_decision: Dict[str, Any]) -> str:
    primary = str(route_decision.get("primary_intent") or "")
    workflow = str(route_decision.get("workflow_mode") or "")
    urgency = str(route_decision.get("urgency") or "")
    if primary == "report_submit" or workflow == "report_flow":
        return FUNCTION_REPORT
    if primary == "url_check" or workflow == "url_check":
        return FUNCTION_REPORT
    if workflow == "risk_case_flow":
        if primary == "risk_fact_clarification":
            return FUNCTION_ASSESSMENT
        if primary == "risk_help":
            return FUNCTION_INTERVENTION
        if primary == "emergency_help" or urgency == "emergency" or route_decision.get("safety_override"):
            return FUNCTION_INTERVENTION
        safety = route_decision.get("safety_signals") or {}
        risk = route_decision.get("risk_signals") or {}
        if safety.get("requested_action_signal") or risk.get("has_current_transfer_request"):
            return FUNCTION_INTERVENTION
        return FUNCTION_ASSESSMENT
    if workflow == "knowledge_answer" or primary == "anti_fraud_qa":
        return FUNCTION_KNOWLEDGE
    if workflow == "clarification" or primary == "clarify":
        return FUNCTION_CLARIFICATION
    return FUNCTION_SMALLTALK


def _secondary_functions(function_route: str, score: int, route_decision: Dict[str, Any], text: str) -> List[str]:
    values: List[str] = []
    if function_route != FUNCTION_ASSESSMENT and (score > 0 or route_decision.get("workflow_mode") == "risk_case_flow"):
        values.append(FUNCTION_ASSESSMENT)
    if function_route not in {FUNCTION_KNOWLEDGE, FUNCTION_SMALLTALK}:
        values.append(FUNCTION_KNOWLEDGE)
    return _dedupe(values, limit=4)


def _strategy(function_route: str, level: str, has_report_target: bool) -> Dict[str, Any]:
    if function_route == FUNCTION_INTERVENTION:
        secondary = ["解释命中风险依据", "提示官方渠道核验", "提醒保留证据"]
        return {"main_action": "立即劝阻", "secondary_actions": secondary}
    if function_route == FUNCTION_REPORT:
        return {
            "main_action": "链接/内容初步研判并生成举报记录",
            "secondary_actions": ["自动带入风险类型和命中特征", "提醒保存截图和聊天记录", "提示不要继续点击或转账"],
        }
    if function_route == FUNCTION_ASSESSMENT:
        return {"main_action": "风险场景智能研判", "secondary_actions": ["输出诈骗类型和风险等级", "追问关键信息", "给出处置建议"]}
    if function_route == FUNCTION_KNOWLEDGE:
        return {"main_action": "知识讲解", "secondary_actions": ["补充典型案例", "给出防范建议", "提示遇到真实风险可切换研判"]}
    if function_route == FUNCTION_CLARIFICATION:
        return {"main_action": "补充关键信息", "secondary_actions": ["确认用户是学习、举报还是正在遭遇风险"]}
    return {"main_action": "引导说明", "secondary_actions": ["提示用户描述对方身份、要求和是否已操作"]}


def _case_state_risk_event(case_state: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(case_state, dict) or not case_state:
        return {}
    risk_memory = case_state.get("risk_memory") or case_state.get("risk") or {}
    scam_memory = case_state.get("scam_memory") or case_state.get("scam_understanding") or {}
    resolution = case_state.get("resolution_memory") or case_state.get("resolution") or {}
    exposure_memory = case_state.get("exposure_memory") or {}
    scene_name = (
        scam_memory.get("primary_scam_type")
        or scam_memory.get("primary_scam_type_name")
        or case_state.get("fraud_type")
        or risk_memory.get("fraud_type")
        or ""
    )
    internal_class = str(risk_memory.get("internal_risk_class") or risk_memory.get("risk_class") or case_state.get("risk_class") or "")
    score = risk_memory.get("risk_score") or case_state.get("risk_score") or 0
    if not score:
        if internal_class == "high_loss":
            score = 90
        elif internal_class == "medium_low_pre_loss":
            score = 55
    raw_level = (
        risk_memory.get("display_risk_label")
        or risk_memory.get("risk_level")
        or case_state.get("risk_level")
        or ("高风险" if internal_class == "high_loss" else "中风险" if internal_class == "medium_low_pre_loss" else "")
        or ""
    )
    level = normalize_risk_level(score, str(raw_level))
    if (not scene_name or scene_name == "未知") and level["risk_level"] == "unknown" and not risk_memory:
        return {}
    scene = scene_from_text(scene_name, " ".join(_as_list(scam_memory.get("matched_features"))))
    handled = (
        _is_truthy(resolution.get("risk_resolved"))
        or str(case_state.get("case_status") or "") in HANDLED_CASE_STATUSES
    )
    if _is_truthy(exposure_memory.get("has_ever_paid")) and not handled:
        stage = {"risk_stage": "after", "risk_stage_name": "事后处理"}
    elif case_state.get("fraud_stage"):
        stage = {"risk_stage": str(case_state.get("fraud_stage")), "risk_stage_name": str(case_state.get("fraud_stage"))}
    else:
        stage = {"risk_stage": "full_process", "risk_stage_name": "全流程研判"}
    return {
        **scene,
        **stage,
        **level,
        "handled": handled,
        "case_status": case_state.get("case_status", ""),
        "timestamp": case_state.get("last_updated_at") or case_state.get("updated_at") or case_state.get("created_at") or "",
        "source": "case_state",
    }


def _global_context(
    memory_context: Dict[str, Any],
    *,
    function_route: str,
    input_text: str,
    scene: Dict[str, str],
    level: Dict[str, Any],
    report_result: Dict[str, Any],
) -> Dict[str, Any]:
    memory_context = memory_context or {}
    case_state = memory_context.get("case_state") or {}
    provided = memory_context.get("global_context") or {}
    past_events = [item for item in _as_list(provided.get("past_risk_events")) if isinstance(item, dict)]
    case_event = _case_state_risk_event(case_state)
    if case_event:
        past_events.insert(0, case_event)
    reported_items = [item for item in _as_list(provided.get("reported_items")) if isinstance(item, dict)]
    if report_result:
        reported_items.insert(
            0,
            {
                "report_id": report_result.get("report_id", ""),
                "risk_scene": scene.get("risk_scene", ""),
                "risk_scene_name": scene.get("risk_scene_name", ""),
                "risk_level": level.get("risk_level", ""),
                "risk_level_name": level.get("risk_level_name", ""),
                "content": report_result.get("content") or report_result.get("raw_content") or "",
                "created_at": report_result.get("created_at", ""),
            },
        )
    knowledge_queries = [item for item in _as_list(provided.get("knowledge_queries")) if isinstance(item, dict)]
    if function_route == FUNCTION_KNOWLEDGE:
        knowledge_queries.insert(
            0,
            {
                "topic": scene.get("risk_scene_name") if scene.get("risk_scene") != "unknown_risk" else input_text[:40],
                "risk_scene": scene.get("risk_scene", ""),
                "risk_scene_name": scene.get("risk_scene_name", ""),
            },
        )
    deduped_events = _dedupe_dicts(past_events, ["risk_scene", "timestamp", "case_status"])
    return {
        "session_id": memory_context.get("session_id", ""),
        "case_id": memory_context.get("case_id") or case_state.get("case_id", ""),
        "active_workflow": (memory_context.get("route_context") or {}).get("active_workflow", ""),
        "case_status": case_state.get("case_status", ""),
        "past_risk_events": deduped_events,
        "reported_items": _dedupe_dicts(reported_items, ["report_id", "content", "created_at"]),
        "knowledge_queries": _dedupe_dicts(knowledge_queries, ["topic", "risk_scene"]),
        "has_unresolved_high_risk": any(
            not item.get("handled") and _risk_level_rank(item.get("risk_level_name") or item.get("risk_level")) >= 3
            for item in deduped_events
        ),
    }


def _context_note(function_route: str, scene: Dict[str, str], global_context: Dict[str, Any]) -> str:
    events = global_context.get("past_risk_events") or []
    if not events:
        return ""
    same_scene = [
        item
        for item in events
        if item.get("risk_scene") == scene.get("risk_scene")
        or (scene.get("risk_scene_name") and item.get("risk_scene_name") == scene.get("risk_scene_name"))
    ]
    event = same_scene[0] if same_scene else events[0]
    scene_name = event.get("risk_scene_name") or scene.get("risk_scene_name") or "相关风险"
    if function_route == FUNCTION_KNOWLEDGE:
        return f"你之前遇到过{scene_name}，这里是相关科普内容。"
    if function_route == FUNCTION_REPORT:
        return f"已结合会话中记录的{scene_name}风险线索生成举报研判。"
    if global_context.get("has_unresolved_high_risk") and function_route in {FUNCTION_ASSESSMENT, FUNCTION_INTERVENTION}:
        return f"会话中仍有未完成的{scene_name}风险处置，本轮会继续优先保障止损。"
    return ""


def build_anti_fraud_engine_result(
    *,
    input_text: str,
    route_decision: Dict[str, Any] | None = None,
    risk_result: Dict[str, Any] | None = None,
    report_result: Dict[str, Any] | None = None,
    url_result: Dict[str, Any] | None = None,
    memory_context: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    route_decision = route_decision or {}
    risk_result = risk_result or {}
    report_result = report_result or {}
    url_result = url_result or {}
    function_route = _function_from_route(route_decision)
    score = (
        report_result.get("risk_score")
        if report_result
        else url_result.get("risk_score")
        if url_result
        else risk_result.get("risk_score")
        if risk_result
        else 0
    )
    raw_level = (
        report_result.get("risk_level")
        or url_result.get("risk_level")
        or risk_result.get("risk_level")
        or route_decision.get("risk_level")
        or ""
    )
    level = normalize_risk_level(score, str(raw_level))
    authoritative_scene = _authoritative_scene_source(
        risk_result=risk_result,
        report_result=report_result,
        url_result=url_result,
        route_decision=route_decision,
        memory_context=memory_context or {},
    )
    scene = scene_from_text(
        authoritative_scene,
        " ".join(_as_list(risk_result.get("risk_features"))),
    )
    scene = _canonical_scene(scene, authoritative_scene)
    explicit_clear_result = bool(risk_result) and int(level.get("risk_score", 0) or 0) < 30 and not (
        _as_list(risk_result.get("risk_features"))
        or _as_list(risk_result.get("normalized_risk_features"))
        or _as_list(risk_result.get("matched_rules"))
    )
    if scene.get("risk_scene") == "unknown_risk" and not explicit_clear_result:
        scene = scene_from_text(input_text)
    hit_features = _dedupe(
        _as_list(risk_result.get("risk_features"))
        + _as_list(risk_result.get("normalized_risk_features"))
        + _as_list(report_result.get("matched_rules"))
        + _as_list(url_result.get("risk_rules"))
    )
    matched_rules = _dedupe(
        [
            item.get("rule_name") or item.get("rule_id") or item.get("label")
            for item in _as_list(risk_result.get("matched_rules"))
            if isinstance(item, dict)
        ]
        + _as_list(report_result.get("matched_rules"))
        + _as_list(url_result.get("risk_rules"))
    )
    stage = _stage_from_raw(
        function_route=function_route,
        route_decision=route_decision,
        risk_result=risk_result,
        report_result=report_result,
        url_result=url_result,
    )
    judgement_stage = _judgement_stage(
        function_route=function_route,
        route_decision=route_decision,
        risk_result=risk_result,
        report_result=report_result,
        url_result=url_result,
        hit_features=hit_features,
        scene=scene,
    )
    explanation = (
        risk_result.get("advice")
        or report_result.get("answer")
        or url_result.get("advice")
        or route_decision.get("reason")
        or ""
    )
    global_context = _global_context(
        memory_context or {},
        function_route=function_route,
        input_text=input_text,
        scene=scene,
        level=level,
        report_result=report_result,
    )
    current_turn = {
        "text": input_text,
        "intent": function_route,
        "primary_intent": route_decision.get("primary_intent", ""),
        "workflow_mode": route_decision.get("workflow_mode", ""),
        "function_route": function_route,
        "function_name": {
            FUNCTION_KNOWLEDGE: "反诈知识普及",
            FUNCTION_INTERVENTION: "风险行为实时劝阻",
            FUNCTION_REPORT: "可疑链接/内容一键举报",
            FUNCTION_ASSESSMENT: "风险场景智能研判",
            FUNCTION_CLARIFICATION: "关键信息补充",
            FUNCTION_SMALLTALK: "普通引导",
        }.get(function_route, "普通引导"),
        **scene,
        **stage,
        **level,
    }
    primary_intent = str(route_decision.get("primary_intent") or "")
    user_intent_name = (
        "风险求助"
        if primary_intent in {"risk_help", "emergency_help"}
        else INTENT_DISPLAY_NAMES.get(function_route, "普通引导")
    )
    if explicit_clear_result and scene.get("risk_scene") == "unknown_risk":
        card_status = "not_applicable"
    elif function_route == FUNCTION_KNOWLEDGE:
        card_status = "knowledge"
    elif function_route in {FUNCTION_ASSESSMENT, FUNCTION_INTERVENTION}:
        card_status = "active"
    elif function_route == FUNCTION_REPORT:
        card_status = "content_check"
    else:
        card_status = "pending"
    risk_judgement_card = {
        "title": "风险场景智能研判",
        "status": card_status,
        "user_intent": {
            "code": route_decision.get("primary_intent") or function_route,
            "name": user_intent_name,
            "workflow_mode": str(route_decision.get("workflow_mode") or ""),
            "reason": str(route_decision.get("reason") or "")[:180],
        },
        "risk_scene": {
            "code": scene.get("risk_scene", "unknown_risk"),
            "name": scene.get("risk_scene_name", "未知风险场景"),
        },
        "risk_stage": judgement_stage,
        "risk_level": {
            "code": level.get("risk_level", "unknown"),
            "name": level.get("risk_level_name", "风险未知"),
            "score": level.get("risk_score", 0),
            "tone": _level_tone(str(level.get("risk_level") or ""), int(level.get("risk_score", 0) or 0)),
        },
        "evidence": _evidence_items(hit_features, matched_rules, str(explanation or "")),
    }
    raw_types = [
        risk_result.get("primary_type"),
        risk_result.get("fraud_type"),
        *(risk_result.get("candidate_types") or []),
        *(risk_result.get("possible_fraud_types") or []),
    ]
    type_candidates = canonicalize_fraud_types([item for item in raw_types if item], limit=8)
    primary_metadata = fraud_type_metadata(risk_result.get("primary_type") or authoritative_scene)
    return {
        "input": input_text,
        "function_route": function_route,
        "function_name": current_turn["function_name"],
        "primary_function": function_route,
        "secondary_functions": _secondary_functions(function_route, level["risk_score"], route_decision, input_text),
        **scene,
        **stage,
        **level,
        "current_turn": current_turn,
        "global_context": global_context,
        "context_note": _context_note(function_route, scene, global_context),
        "intent_confidence": route_decision.get("confidence", 0),
        "fraud_type_id": primary_metadata.get("fraud_type_id", risk_result.get("fraud_type_id", "")),
        "primary_type": primary_metadata.get("primary_type", risk_result.get("primary_type") or authoritative_scene),
        "candidate_types": [item.get("primary_type", "") for item in type_candidates if item.get("primary_type")],
        "candidate_type_ids": [item.get("fraud_type_id", "") for item in type_candidates if item.get("fraud_type_id")],
        "type_candidates": type_candidates,
        "type_confidence": risk_result.get("type_confidence", risk_result.get("confidence", 0.0)),
        "hit_features": hit_features,
        "matched_rules": matched_rules,
        "explanation": str(explanation or "")[:500],
        "risk_judgement_card": risk_judgement_card,
        "response_strategy": _strategy(function_route, level["risk_level"], bool(report_result or url_result.get("urls"))),
    }
