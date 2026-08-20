"""Risk score decay helpers for multi-turn anti-fraud cases.

The decay layer keeps a past high-risk case from staying permanently "active"
after the user has stopped the dangerous action, resolved the case, or has had
no further risk input for a while. It is deliberately rule-based so routing and
memory can share the same deterministic behavior.
"""

from __future__ import annotations

import re
from copy import deepcopy
from datetime import datetime
from typing import Any, Dict, Optional

from app.query_process.services.scam_rule_engine import risk_level_from_score


TRUE = "true"
FALSE = "false"
UNKNOWN = "unknown"

RISK_DECAY_CONFIG = {
    "after_user_stopped_action": -30,
    "after_case_resolved": "close_active_case",
    "after_timeout_minutes": 15,
}

NON_BLOCKING_DECAY_STATUSES = {"mitigated", "resolved", "observation"}
OBSERVATION_CASE_STATUSES = {"observation"}


def _compact(text: str) -> str:
    return re.sub(r"\s+", "", text or "")


def _as_bool(value: Any) -> Optional[bool]:
    if value is True or str(value).strip().lower() == TRUE:
        return True
    if value is False or str(value).strip().lower() == FALSE:
        return False
    return None


def _score(value: Any, default: int = 0) -> int:
    try:
        return max(0, min(100, int(float(value))))
    except (TypeError, ValueError):
        return default


def _case_risk_score(case_state: Dict[str, Any]) -> int:
    risk_memory = case_state.get("risk_memory") or case_state.get("risk") or {}
    decay = case_state.get("risk_decay") or {}
    candidates = [
        case_state.get("risk_score"),
        risk_memory.get("risk_score"),
        decay.get("current_risk_score"),
        decay.get("base_risk_score"),
    ]
    for candidate in candidates:
        value = _score(candidate, -1)
        if value >= 0:
            return value
    return 0


def _case_base_score(case_state: Dict[str, Any], current_score: Any = None) -> int:
    decay = case_state.get("risk_decay") or {}
    risk_memory = case_state.get("risk_memory") or case_state.get("risk") or {}
    candidates = [
        current_score,
        decay.get("base_risk_score"),
        case_state.get("risk_score"),
        risk_memory.get("risk_score"),
        decay.get("current_risk_score"),
    ]
    score = 0
    for candidate in candidates:
        value = _score(candidate, -1)
        if value >= 0:
            score = max(score, value)
    return score


def parse_case_datetime(value: Any) -> Optional[datetime]:
    if isinstance(value, datetime):
        return value
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _case_updated_at(case_state: Dict[str, Any]) -> Optional[datetime]:
    decay = case_state.get("risk_decay") or {}
    for key in [
        "last_risk_input_at",
        "last_decay_at",
    ]:
        parsed = parse_case_datetime(decay.get(key))
        if parsed:
            return parsed
    for key in ["last_updated_at", "updated_at", "created_at"]:
        parsed = parse_case_datetime(case_state.get(key))
        if parsed:
            return parsed
    risk_memory = case_state.get("risk_memory") or {}
    return parse_case_datetime(risk_memory.get("updated_at"))


def _minutes_since(value: Optional[datetime], now: datetime) -> Optional[float]:
    if value is None:
        return None
    if value.tzinfo is not None and now.tzinfo is None:
        now = now.astimezone(value.tzinfo)
    elif value.tzinfo is None and now.tzinfo is not None:
        value = value.replace(tzinfo=now.tzinfo)
    return (now - value).total_seconds() / 60


def text_has_current_risk_input(text: str) -> bool:
    """Return True when this turn mentions a new risky action or exposure."""
    compact = _compact(text)
    if not compact:
        return False
    danger_pattern = (
        r"(转账|付款|充值|打款|汇款|补单|垫付|交钱|保证金|解冻费|手续费|认证金|"
        r"验证码|共享屏幕|屏幕共享|远程控制|远程协助|下载|安装|点击|打开|填写|输入|"
        r"链接|网址|二维码|银行卡|身份证|密码)"
    )
    report_intent = bool(re.search(r"(举报|投诉|上报|提交线索|反馈线索|我要举报|帮我举报|举报这个|报这个)", compact))
    report_only = report_intent and not re.search(danger_pattern, compact)
    if report_only:
        return False
    learning_intent = bool(re.search(r"(什么是|是什么意思|科普|学习|了解|案例|怎么骗|怎么防|如何防范|防范建议)", compact))
    if learning_intent and not re.search(danger_pattern, compact):
        return False
    if re.search(
        r"(正在|还在|继续|准备|马上|现在|刚要|又|再次|还要).{0,16}"
        r"(转账|付款|充值|打款|汇款|补单|垫付|交钱|保证金|解冻费|验证码|共享屏幕|屏幕共享|远程控制|下载|安装|链接|网址|二维码|银行卡|身份证|密码)",
        compact,
        re.IGNORECASE,
    ):
        return True
    if re.search(
        r"(对方|客服|他|她|他们|骗子|平台|老师|警察|公安|网友|有人)"
        r".{0,12}(让我|叫我|要求我|要我|发来|发了|给了|说要|说让我)"
        r".{0,24}(转账|付款|充值|打款|汇款|补单|垫付|交钱|保证金|解冻费|验证码|共享屏幕|屏幕共享|远程控制|下载|安装|链接|网址|二维码|银行卡|身份证|密码)",
        compact,
        re.IGNORECASE,
    ):
        return True
    if re.search(
        r"(已经|已|刚刚|刚才).{0,12}"
        r"(转账|付款|充值|打款|汇款|补单|垫付|交钱|给了验证码|填了验证码|共享屏幕|下载|安装|点了链接|填了银行卡|填了身份证|告诉密码)",
        compact,
        re.IGNORECASE,
    ):
        return True
    return bool(
        re.search(
            r"https?://[^\s，。；]+|www\.[^\s，。；]+|[A-Za-z0-9.-]+\.(?:com|cn|net|top|xyz|vip|click|shop|icu|cc|site|online|app)",
            text or "",
            re.IGNORECASE,
        )
    )


def user_confirms_stopped_action(text: str, slots: Dict[str, Any] | None = None) -> bool:
    slots = slots or {}
    if _as_bool(slots.get("has_stopped_operation")) is True:
        return True
    compact = _compact(text)
    return bool(
        re.search(
            r"(已停止|已经停止|停止了|停下了|不转了|不付了|没有继续|没继续|已关闭|关闭了|退出会议|挂断了|断开了|卸载了|拉黑|删除了对方|不信了|不相信了|不会再信|停止联系|不再联系|不联系对方)",
            compact,
        )
    )


def user_confirms_no_transfer_and_stopped_contact(text: str, slots: Dict[str, Any] | None = None) -> bool:
    slots = slots or {}
    compact = _compact(text)
    no_transfer_text = bool(
        re.search(
            r"(没有|没|未|还没|尚未).{0,10}(转账|转钱|付款|付钱|充值|打款|汇款|补单|垫付|垫钱|交钱|交费|缴费|付过|转过)",
            compact,
        )
    )
    stopped_contact_text = bool(
        re.search(
            r"(拉黑(了)?对方|把对方拉黑|删除了对方|删了对方|停止联系|不再联系|不联系对方|挂断|退出群|退出会议|不信了|不相信了|不会再信|知道是诈骗|明白是骗局)",
            compact,
        )
    )
    no_payment_slot = _as_bool(slots.get("has_paid")) is not True and _as_bool(slots.get("has_transferred_virtual_asset")) is not True
    no_sensitive_exposure = all(
        _as_bool(slots.get(key)) is not True
        for key in [
            "has_shared_code",
            "has_screen_share",
            "has_downloaded_app",
            "has_clicked_link",
            "has_provided_identity_or_bank",
            "has_password_exposed",
            "has_remote_control_enabled",
            "has_bank_card_exposed",
            "has_id_card_exposed",
        ]
    )
    no_transfer_confirmed = no_transfer_text or _as_bool(slots.get("has_paid")) is False
    stopped_contact_confirmed = stopped_contact_text or _as_bool(slots.get("user_no_longer_believes_scammer")) is True
    return no_payment_slot and no_sensitive_exposure and no_transfer_confirmed and stopped_contact_confirmed


def risk_decay_nonblocking(case_state: Dict[str, Any]) -> bool:
    decay = case_state.get("risk_decay") or {}
    status = str(decay.get("status") or case_state.get("case_status") or "")
    return status in NON_BLOCKING_DECAY_STATUSES or str(case_state.get("case_status") or "") in OBSERVATION_CASE_STATUSES


def case_is_high_risk_unresolved(case_state: Dict[str, Any]) -> bool:
    if not case_state:
        return False
    decay = case_state.get("risk_decay") or {}
    if str(decay.get("status") or "") in NON_BLOCKING_DECAY_STATUSES or str(case_state.get("case_status") or "") in OBSERVATION_CASE_STATUSES:
        return False
    resolution = case_state.get("resolution_memory") or case_state.get("resolution") or {}
    if _as_bool(resolution.get("risk_resolved")) is True or _as_bool(case_state.get("risk_resolved")) is True:
        return False
    if str(case_state.get("case_status") or "") in {"prevented", "stop_loss_done", "education_ready", "closed", "non_risk_task"}:
        return False
    risk_memory = case_state.get("risk_memory") or case_state.get("risk") or {}
    level = str(risk_memory.get("display_risk_label") or risk_memory.get("risk_level") or case_state.get("risk_level") or "")
    internal_class = str(risk_memory.get("internal_risk_class") or risk_memory.get("risk_class") or case_state.get("risk_class") or "")
    score = _case_risk_score(case_state)
    return "高" in level or "紧急" in level or "极高" in level or internal_class == "high_loss" or score >= 51


def build_risk_decay_update(
    *,
    previous_case: Dict[str, Any] | None = None,
    current_case: Dict[str, Any] | None = None,
    current_text: str = "",
    slots: Dict[str, Any] | None = None,
    risk_score: Any = None,
    risk_level: str = "",
    risk_class: str = "",
    resolution: Dict[str, Any] | None = None,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Build a risk decay decision for the current turn."""
    previous_case = previous_case or {}
    current_case = current_case or {}
    merged_case = {**previous_case, **current_case}
    slots = slots or current_case.get("slots") or previous_case.get("slots") or {}
    resolution = resolution or current_case.get("resolution") or current_case.get("resolution_memory") or {}
    now = now or datetime.now()
    now_text = now.isoformat(timespec="seconds")

    base_score = _case_base_score(merged_case, risk_score)
    current_score = _score(risk_score, base_score)
    previous_decay = previous_case.get("risk_decay") or {}
    previous_status = str(previous_decay.get("status") or previous_case.get("case_status") or "")
    current_case_status = str(current_case.get("case_status") or "")
    current_signal = text_has_current_risk_input(current_text)
    stopped = user_confirms_stopped_action(current_text, slots)
    fully_resolved = stopped and user_confirms_no_transfer_and_stopped_contact(current_text, slots)

    previous_time = _case_updated_at(previous_case)
    stale_minutes = _minutes_since(previous_time, now)
    previous_case_status = str(previous_case.get("case_status") or "")
    stale = (
        stale_minutes is not None
        and stale_minutes >= int(RISK_DECAY_CONFIG["after_timeout_minutes"])
        and not current_signal
        and not stopped
        and previous_case_status not in {"resolved", "observation", "closed", "stop_loss_done", "prevented"}
    )

    reactivated = current_signal and (
        previous_status in NON_BLOCKING_DECAY_STATUSES
        or str(previous_case.get("case_status") or "") in {"mitigated", "observation", "prevented", "stop_loss_done", "closed"}
    )

    status = "active"
    case_status = current_case_status or "active"
    reason = "当前仍按最新风险研判保持活跃状态。"
    decayed_score = current_score
    score_delta = 0
    resolved = bool(resolution.get("risk_resolved", False))
    ready_for_education = bool(resolution.get("ready_for_education", False))
    closure_can_close = bool((resolution.get("closure_standard") or {}).get("can_close"))

    if reactivated:
        status = "reactivated"
        case_status = "active"
        reason = "用户再次提到转账、验证码、链接、下载或屏幕共享等风险输入，重新激活风险事件。"
        decayed_score = max(current_score, base_score)
        score_delta = 0
        resolved = False
        ready_for_education = False
    elif bool(resolution.get("risk_resolved", False)):
        status = "resolved"
        case_status = str(resolution.get("case_status") or current_case_status or "closed")
        reason = "风险解除核验已经通过，当前活跃风险事件关闭。"
        decayed_score = min(20, max(0, base_score + int(RISK_DECAY_CONFIG["after_user_stopped_action"])))
        score_delta = decayed_score - base_score
        resolved = True
        ready_for_education = True
    elif fully_resolved and closure_can_close:
        status = "resolved"
        case_status = "prevented" if risk_class != "high_loss" else "stop_loss_done"
        reason = "用户确认未转账且已停止联系/拉黑对方，并已满足当前场景事件结束标准，当前活跃风险事件关闭。"
        decayed_score = min(20, max(0, base_score + int(RISK_DECAY_CONFIG["after_user_stopped_action"])))
        score_delta = decayed_score - base_score
        resolved = True
        ready_for_education = True
    elif fully_resolved:
        status = "mitigated"
        case_status = "mitigated"
        reason = "用户确认未转账且已停止联系/拉黑对方，风险降为已缓解；仍需完成证据提醒、举报选择等场景闭环后再关闭事件。"
        decayed_score = max(0, base_score + int(RISK_DECAY_CONFIG["after_user_stopped_action"]))
        score_delta = decayed_score - base_score
        resolved = False
        ready_for_education = False
    elif stopped:
        status = "mitigated"
        case_status = "mitigated"
        reason = "用户确认已经停止危险动作，当前活跃风险降为已缓解。"
        decayed_score = max(0, base_score + int(RISK_DECAY_CONFIG["after_user_stopped_action"]))
        score_delta = decayed_score - base_score
        resolved = bool(resolution.get("risk_resolved", False))
        ready_for_education = bool(resolution.get("ready_for_education", False))
    elif stale:
        status = "observation"
        case_status = "observation"
        reason = f"{int(RISK_DECAY_CONFIG['after_timeout_minutes'])}分钟内没有新的风险输入，事件转入观察状态。"
        decayed_score = min(45, max(0, base_score + int(RISK_DECAY_CONFIG["after_user_stopped_action"])))
        score_delta = decayed_score - base_score
        resolved = False
        ready_for_education = False
    elif previous_status in NON_BLOCKING_DECAY_STATUSES and not current_signal:
        status = previous_status
        case_status = "prevented" if previous_status == "resolved" else previous_status
        reason = previous_decay.get("reason") or "沿用上一轮风险衰减状态。"
        decayed_score = _score(previous_decay.get("current_risk_score"), max(0, base_score + int(RISK_DECAY_CONFIG["after_user_stopped_action"])))
        score_delta = decayed_score - base_score
        resolved = previous_status == "resolved"
        ready_for_education = previous_status == "resolved" or bool(previous_decay.get("ready_for_education", False))

    level = risk_level_from_score(decayed_score) if decayed_score else "风险未知"
    if risk_level and status == "active":
        level = risk_level

    return {
        "enabled": True,
        "config": deepcopy(RISK_DECAY_CONFIG),
        "status": status,
        "case_status": case_status,
        "base_risk_score": base_score,
        "current_risk_score": decayed_score,
        "risk_level": level,
        "score_delta": score_delta,
        "risk_resolved": resolved,
        "ready_for_education": ready_for_education,
        "reactivated": reactivated,
        "stale_minutes": round(stale_minutes, 2) if stale_minutes is not None else None,
        "timeout_minutes": int(RISK_DECAY_CONFIG["after_timeout_minutes"]),
        "last_risk_input_at": now_text if current_signal or reactivated else previous_decay.get("last_risk_input_at") or now_text,
        "last_decay_at": now_text if status in {"mitigated", "resolved", "observation"} else previous_decay.get("last_decay_at", ""),
        "reason": reason,
    }


def apply_decay_to_case_snapshot(case_state: Dict[str, Any], current_text: str = "", now: Optional[datetime] = None) -> Dict[str, Any]:
    """Return a case snapshot with routing-time timeout/reactivation decay applied."""
    if not case_state:
        return {}
    case_copy = deepcopy(case_state)
    update = build_risk_decay_update(
        previous_case=case_state,
        current_case=case_state,
        current_text=current_text,
        slots=case_state.get("slots") or {},
        risk_score=_case_risk_score(case_state),
        risk_level=str((case_state.get("risk_memory") or {}).get("display_risk_label") or case_state.get("risk_level") or ""),
        risk_class=str((case_state.get("risk_memory") or {}).get("internal_risk_class") or case_state.get("risk_class") or ""),
        resolution=case_state.get("resolution_memory") or case_state.get("resolution") or {},
        now=now,
    )
    if update.get("status") in {"mitigated", "resolved", "observation", "reactivated"}:
        case_copy["risk_decay"] = update
        case_copy["risk_score"] = update["current_risk_score"]
        case_copy["risk_level"] = update["risk_level"]
        case_copy["case_status"] = update["case_status"]
        case_copy["risk_resolved"] = bool(update.get("risk_resolved"))
        case_copy["ready_for_education"] = bool(update.get("ready_for_education"))
        risk_memory = dict(case_copy.get("risk_memory") or {})
        if risk_memory:
            risk_memory.update({
                "risk_score": update["current_risk_score"],
                "display_risk_label": update["risk_level"],
                "risk_decay_status": update["status"],
            })
            case_copy["risk_memory"] = risk_memory
        resolution_memory = dict(case_copy.get("resolution_memory") or {})
        if resolution_memory:
            resolution_memory.update({
                "risk_resolved": bool(update.get("risk_resolved")),
                "ready_for_education": bool(update.get("ready_for_education")),
                "risk_decay_status": update["status"],
            })
            case_copy["resolution_memory"] = resolution_memory
        route_context = dict(case_copy.get("route_context") or {})
        if update.get("status") in {"resolved", "observation"}:
            route_context["pending_question"] = {}
            route_context["active_workflow"] = "idle"
        elif update.get("status") == "reactivated":
            route_context["active_workflow"] = "risk_case_flow"
        case_copy["route_context"] = route_context
    return case_copy
