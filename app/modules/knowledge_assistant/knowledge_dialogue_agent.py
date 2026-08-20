"""Multi-turn anti-fraud knowledge dialogue agent.

This agent is intentionally separate from the legacy education RAG generator.
It teaches one section per turn, keeps a lightweight learning state, and remains
interruptible by the unified risk router before it is called.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from langchain_core.messages import HumanMessage, SystemMessage

from app.clients.mongo_business_utils import get_business_mongo_tool
from app.core.logger import logger
from app.lm.lm_utils import get_llm_client, get_llm_config_error
from app.query_process.agent.nodes.common import extract_json_object, get_message_content


WORKFLOW_MODE = "knowledge_dialogue_flow"
STAGE_ORDER = ["overview", "features", "tactics", "case", "prevention", "law", "summary"]
STAGE_LABELS = {
    "overview": "核心识别点",
    "features": "骗局特征",
    "tactics": "作案手法",
    "case": "典型案例",
    "prevention": "防范建议",
    "law": "法律与处置常识",
    "summary": "学习总结",
}
STAGE_TO_INTENT = {
    "overview": "definition",
    "features": "technique",
    "tactics": "technique",
    "case": "case",
    "prevention": "prevention",
    "law": "law",
    "summary": "summary",
}

CONTINUATION_WORDS = ["继续", "接着", "往下", "然后", "下一步", "还有", "再讲", "说下去", "想听", "想看"]
AFFIRM_CONTINUE_WORDS = ["可以", "行", "想", "讲", "听"]
BRIEF_ACK_WORDS = ["好", "好的", "嗯", "嗯嗯", "明白", "明白了", "知道了", "了解", "收到"]
STAGE_KEYWORDS = {
    "features": ["特征", "识别", "信号", "怎么看", "怎么判断", "高危点"],
    "tactics": ["套路", "手法", "流程", "怎么骗", "怎么上钩", "步骤"],
    "case": ["案例", "例子", "真实案例", "举例", "复盘一个"],
    "prevention": ["防范", "怎么防", "避免", "核验", "预防", "注意什么"],
    "law": ["法律", "法规", "违法", "报警", "立案", "追回", "处置"],
    "summary": ["总结", "概括", "口诀", "重点", "记住"],
}
LEARNING_TURN_ACTS = {
    "new_topic",
    "continue_learning",
    "stage_jump",
    "close_learning",
    "post_completion_ack",
    "risk_interrupt",
    "smalltalk",
    "unclear",
}
RISK_INTERRUPT_RE = re.compile(
    r"(我|我现在|已经|刚刚|对方|客服|老师|平台).{0,18}"
    r"(转账|付款|充值|入金|提现不了|不能提现|保证金|解冻费|税费|验证码|屏幕共享|下载.{0,4}app|安全账户|账号密码|银行卡)",
    re.IGNORECASE,
)


def _project_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _knowledge_dir() -> Path:
    return _project_root() / "data" / "knowledge"


@lru_cache(maxsize=16)
def _load_json_collection(name: str) -> List[Dict[str, Any]]:
    path = _knowledge_dir() / f"{name}.json"
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    return data if isinstance(data, list) else []


def _safe_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _text(value: Any) -> str:
    return str(value or "").strip()


def _compact(text: str) -> str:
    return re.sub(r"[\s/／、·._-]+", "", text or "")


def _normalized_short_text(text: str) -> str:
    return re.sub(r"[\s，。,.!！?？、~～]+", "", text or "").strip()


def _join(values: Any, limit: int = 6) -> str:
    items = [_text(item) for item in _safe_list(values) if _text(item)]
    return "、".join(items[:limit])


@lru_cache(maxsize=1)
def load_dialogue_policy() -> List[Dict[str, Any]]:
    try:
        tool = get_business_mongo_tool()
        rows = list(
            tool.db["knowledge_dialogue_policy"]
            .find({"enabled": True}, {"_id": 0})
            .sort([("priority", -1)])
        )
        if rows:
            return rows
    except Exception as exc:
        logger.warning(f"知识对话策略 Mongo 不可用，降级本地 JSON：{exc}")
    return _load_json_collection("knowledge_dialogue_policy")


def _global_policy() -> Dict[str, Any]:
    return next((item for item in load_dialogue_policy() if item.get("policy_type") == "global_teaching_contract"), {})


def _scam_policy_by_type() -> Dict[str, Dict[str, Any]]:
    policies: Dict[str, Dict[str, Any]] = {}
    for item in load_dialogue_policy():
        if item.get("policy_type") == "scam_teaching_path" and item.get("fraud_type"):
            policies[str(item["fraud_type"])] = item
    return policies


@lru_cache(maxsize=1)
def _scam_catalog() -> List[Dict[str, Any]]:
    policies = _scam_policy_by_type()
    scams = []
    for row in _load_json_collection("scam_types"):
        name = _text(row.get("name"))
        if not name:
            continue
        policy = policies.get(name, {})
        aliases = list(dict.fromkeys([*_safe_list(row.get("aliases")), *_safe_list(policy.get("aliases"))]))
        scams.append({**row, "aliases": aliases, "teaching_policy": policy})
    return scams


def _features_for(scam: Dict[str, Any], fraud_type: str) -> List[Dict[str, Any]]:
    scam_id = _text(scam.get("scam_id"))
    rows = [
        item
        for item in _load_json_collection("scam_features")
        if _text(item.get("scam_id")) == scam_id or _text(item.get("fraud_type")) == fraud_type
    ]
    rows.sort(key=lambda item: int(float(item.get("risk_weight") or 0)), reverse=True)
    return rows


def _advice_for(fraud_type: str) -> List[Dict[str, Any]]:
    return [item for item in _load_json_collection("prevention_advice") if _text(item.get("fraud_type")) == fraud_type]


def _cases_for(fraud_type: str) -> List[Dict[str, Any]]:
    return [item for item in _load_json_collection("typical_cases") if _text(item.get("fraud_type")) == fraud_type]


def _report_guides_for(fraud_type: str) -> List[Dict[str, Any]]:
    return [
        item
        for item in _load_json_collection("report_guides")
        if _text(item.get("fraud_type")) in {fraud_type, "通用"}
    ]


def _evidence_guides_for(fraud_type: str) -> List[Dict[str, Any]]:
    return [
        item
        for item in _load_json_collection("evidence_guides")
        if _text(item.get("fraud_type")) in {fraud_type, "通用"}
    ]


def _laws_for(fraud_type: str, stage: str) -> List[Dict[str, Any]]:
    stage_terms = {
        "law": ["报警", "止付冻结", "证据保存", "转账前劝阻"],
        "prevention": ["转账前劝阻", "证据保存", "官方核验"],
        "case": ["报警", "证据保存"],
    }
    terms = stage_terms.get(stage, ["转账前劝阻", "证据保存"])
    rows = []
    for law in _load_json_collection("law_clauses"):
        related_scam = fraud_type in [_text(item) for item in _safe_list(law.get("related_scam_types"))]
        related_behavior = any(term in [_text(item) for item in _safe_list(law.get("related_behaviors"))] for term in terms)
        if related_scam or related_behavior:
            rows.append(law)
    return rows[:3]


def _score_topic(message: str, scam: Dict[str, Any]) -> Tuple[int, List[str]]:
    compact = _compact(message)
    score = 0
    hits: List[str] = []
    name = _text(scam.get("name"))
    candidates = [name, name.replace("诈骗", "").strip(), *_safe_list(scam.get("aliases"))]
    for candidate in candidates:
        candidate_text = _compact(_text(candidate))
        if candidate_text and candidate_text in compact:
            score += 18 if candidate_text == _compact(_text(scam.get("name"))) else 10
            hits.append(_text(candidate))
    for feature in _features_for(scam, _text(scam.get("name")))[:12]:
        for keyword in _safe_list(feature.get("keywords")):
            keyword_text = _compact(_text(keyword))
            if keyword_text and keyword_text in compact:
                score += 4
                hits.append(_text(keyword))
    return score, list(dict.fromkeys(hits))[:8]


def match_dialogue_topic(message: str, state: Dict[str, Any] | None = None) -> Optional[Dict[str, Any]]:
    return match_dialogue_topic_with_semantics(message, state=state)


def match_dialogue_topic_with_semantics(
    message: str,
    state: Dict[str, Any] | None = None,
    turn_semantics: Dict[str, Any] | None = None,
) -> Optional[Dict[str, Any]]:
    state = state or {}
    scored: List[Tuple[int, Dict[str, Any], List[str]]] = []
    for scam in _scam_catalog():
        score, hits = _score_topic(message, scam)
        if score:
            scored.append((score, scam, hits))
    if scored:
        scored.sort(key=lambda item: item[0], reverse=True)
        score, scam, hits = scored[0]
        return {"scam": scam, "score": score, "matched_terms": hits}
    previous = _text(state.get("topic"))
    turn_act = str((turn_semantics or {}).get("turn_act") or "")
    if previous and turn_act in {"continue_learning", "stage_jump", "close_learning"}:
        scam = next((item for item in _scam_catalog() if _text(item.get("name")) == previous), None)
        if scam:
            return {"scam": scam, "score": 3, "matched_terms": ["上一轮主题", "LLM语义续接"]}
    return None


def is_knowledge_continuation(message: str, state: Dict[str, Any] | None = None) -> bool:
    state = state or {}
    if not state.get("topic"):
        return False
    if str(state.get("active_workflow") or "") != WORKFLOW_MODE:
        return False
    semantics = analyze_learning_turn_semantics(message=message, state=state, route_decision={}, use_llm=True)
    return bool(semantics.get("should_continue_knowledge") or semantics.get("should_close_learning"))


def looks_like_risk_interrupt(message: str) -> bool:
    compact = _compact(message)
    if not compact:
        return False
    knowledge_markers = ["什么是", "科普", "了解", "案例", "怎么防", "如何识别"]
    if any(marker in compact for marker in knowledge_markers) and not any(word in compact for word in ["我现在", "我已经", "对方让我", "不能提现"]):
        return False
    return bool(RISK_INTERRUPT_RE.search(compact))


def _next_stage(current: str, completed: List[str]) -> str:
    if current not in STAGE_ORDER:
        return "overview"
    index = STAGE_ORDER.index(current)
    for candidate in STAGE_ORDER[index + 1 :]:
        if candidate not in completed:
            return candidate
    return "summary"


def _normalize_learning_semantics(data: Dict[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
    turn_act = str(data.get("turn_act") or "unclear").strip()
    if turn_act not in LEARNING_TURN_ACTS:
        turn_act = "unclear"
    requested_stage = str(data.get("requested_stage") or "").strip()
    if requested_stage not in STAGE_ORDER:
        requested_stage = ""
    active = str(state.get("active_workflow") or "") == WORKFLOW_MODE
    completed = str(state.get("dialogue_status") or "") == "completed" and str(state.get("active_workflow") or "") == "idle"
    is_risk_interrupt = bool(data.get("is_risk_interrupt", False) or turn_act == "risk_interrupt")
    should_close = bool(data.get("should_close_learning", False) or turn_act == "close_learning")
    should_continue = bool(
        active
        and not is_risk_interrupt
        and turn_act in {"continue_learning", "stage_jump", "close_learning"}
    )
    is_post_completion_idle = bool(
        completed
        and not is_risk_interrupt
        and (data.get("is_post_completion_idle") or turn_act in {"post_completion_ack", "smalltalk", "unclear"})
    )
    return {
        "turn_act": turn_act,
        "requested_stage": requested_stage,
        "should_continue_knowledge": should_continue,
        "should_close_learning": bool(active and should_close and not is_risk_interrupt),
        "is_risk_interrupt": is_risk_interrupt,
        "is_post_completion_idle": is_post_completion_idle,
        "semantic_rewrite": str(data.get("semantic_rewrite") or data.get("rewritten_text") or ""),
        "confidence": data.get("confidence", 0),
        "reason": str(data.get("reason") or ""),
        "source": str(data.get("source") or "llm_learning_turn_semantics"),
    }


def _fallback_learning_semantics(message: str, state: Dict[str, Any]) -> Dict[str, Any]:
    compact = _compact(message)
    active = str((state or {}).get("active_workflow") or "") == WORKFLOW_MODE
    if looks_like_risk_interrupt(message):
        turn_act = "risk_interrupt"
        requested_stage = ""
    elif active and any(word in compact for word in ["不用继续", "先到这", "谢谢", "明白了", "懂了", "记住了"]):
        turn_act = "close_learning"
        requested_stage = "summary"
    elif active and any(word in compact for word in CONTINUATION_WORDS + AFFIRM_CONTINUE_WORDS + BRIEF_ACK_WORDS):
        turn_act = "continue_learning"
        requested_stage = ""
    else:
        turn_act = "new_topic"
        requested_stage = ""
        for stage, words in STAGE_KEYWORDS.items():
            if any(_compact(word) in compact for word in words):
                requested_stage = stage
                break
    return _normalize_learning_semantics(
        {
            "turn_act": turn_act,
            "requested_stage": requested_stage,
            "should_continue_knowledge": active and turn_act in {"continue_learning", "stage_jump", "close_learning"},
            "should_close_learning": turn_act == "close_learning",
            "is_risk_interrupt": turn_act == "risk_interrupt",
            "semantic_rewrite": message,
            "confidence": 0.45,
            "reason": "local fallback semantics",
            "source": "local_learning_turn_semantics",
        },
        state,
    )


def analyze_learning_turn_semantics(
    *,
    message: str,
    state: Dict[str, Any],
    route_decision: Optional[Dict[str, Any]] = None,
    use_llm: bool = True,
) -> Dict[str, Any]:
    """Use the LLM to classify the user's learning-turn intent.

    This is the semantic source of truth for continuing, closing, or idling a
    knowledge dialogue.  Local rules only clamp unsafe boundaries.
    """
    state = dict(state or {})
    route_decision = dict(route_decision or {})
    if not use_llm:
        return _fallback_learning_semantics(message, state)
    config_error = get_llm_config_error()
    if config_error:
        logger.warning(f"Use local learning semantics: {config_error}")
        return _fallback_learning_semantics(message, state)

    global_policy = _global_policy().get("teaching_contract", {})
    system_prompt = """
你是反诈知识教学流程的语义判定器，只输出 JSON，不回答用户。

任务：
1. 判断用户本轮是在继续学习、跳到某个学习板块、结束学习、完成后随口确认、日常闲聊，还是出现真实风险打断。
2. 不要靠固定关键词做判断，要把用户原话结合当前学习状态改写成明确语义。
3. “我记住了/差不多懂了/先到这/不用继续了/谢谢”等同类表达，语义上是 close_learning。
4. 如果学习已经 completed 且 active_workflow=idle，用户只是短确认或含糊词，应判为 post_completion_ack 或 smalltalk，不要判成风险。
5. 只有用户描述自己正在转账、提现失败、被要求交钱、验证码/屏幕共享/陌生App/账号密码等真实处境，才判 risk_interrupt。
6. 用户明确问“案例/怎么防/法律/流程/特征/总结”等，输出对应 requested_stage。
7. 新主题也要判断用户真正想问的板块：问报案、证据保存、取证、止付、追回、举报、立案、处置，requested_stage 应为 law；问怎么防或核验，requested_stage 应为 prevention；问套路/流程/手法，requested_stage 应为 tactics；问识别特征，requested_stage 应为 features；只泛泛说“科普/什么是/讲讲”，才用 overview。
"""
    human_prompt = f"""
【用户本轮输入】
{message}

【当前学习状态】
{json.dumps(state, ensure_ascii=False)}

【入口路由结果】
{json.dumps({
    "workflow_mode": route_decision.get("workflow_mode", ""),
    "primary_intent": route_decision.get("primary_intent", ""),
    "reason": route_decision.get("reason", ""),
    "turn_rewrite": route_decision.get("turn_rewrite", {}),
    "risk_signals": route_decision.get("risk_signals", {}),
}, ensure_ascii=False)}

【教学策略】
{json.dumps(global_policy, ensure_ascii=False)}

请返回严格 JSON：
{{
  "turn_act": "new_topic|continue_learning|stage_jump|close_learning|post_completion_ack|risk_interrupt|smalltalk|unclear",
  "requested_stage": "overview|features|tactics|case|prevention|law|summary|",
  "should_continue_knowledge": true,
  "should_close_learning": false,
  "is_risk_interrupt": false,
  "is_post_completion_idle": false,
  "semantic_rewrite": "把用户本轮话语改写成明确学习意图",
  "confidence": 0.0,
  "reason": "简短说明为什么这样判定"
}}
"""
    try:
        llm = get_llm_client(json_mode=True)
        response = llm.invoke([SystemMessage(content=system_prompt.strip()), HumanMessage(content=human_prompt.strip())])
        data = extract_json_object(get_message_content(response))
        if not data:
            raise ValueError("知识学习意图 LLM 返回空 JSON")
        return _normalize_learning_semantics(data, state)
    except Exception as exc:
        logger.warning(f"Learning semantics LLM failed, use local fallback: {exc}", exc_info=True)
        return _fallback_learning_semantics(message, state)


def choose_teaching_stage(
    message: str,
    state: Dict[str, Any],
    topic_changed: bool,
    turn_semantics: Dict[str, Any] | None = None,
) -> str:
    turn_semantics = turn_semantics or {}
    requested_stage = str(turn_semantics.get("requested_stage") or "")
    if not topic_changed and bool(turn_semantics.get("should_close_learning")):
        return "summary"
    if requested_stage in STAGE_ORDER:
        return requested_stage
    if topic_changed or not state.get("topic"):
        return "overview"
    if str(turn_semantics.get("turn_act") or "") == "continue_learning":
        return _next_stage(_text(state.get("learning_stage")), list(state.get("completed_sections") or []))
    return _text(state.get("learning_stage")) or "overview"


def _stage_materials(scam: Dict[str, Any], stage: str) -> Dict[str, Any]:
    fraud_type = _text(scam.get("name"))
    features = _features_for(scam, fraud_type)
    advice = _advice_for(fraud_type)
    cases = _cases_for(fraud_type)
    laws = _laws_for(fraud_type, stage)
    reports = _report_guides_for(fraud_type)
    evidence = _evidence_guides_for(fraud_type)
    if stage == "overview":
        return {
            "profile": scam,
            "features": features[:5],
            "advice": advice[:1],
            "cases": cases[:1],
            "laws": laws[:1],
            "reports": [],
            "evidence": [],
        }
    if stage in {"features", "tactics"}:
        return {"profile": scam, "features": features[:8], "advice": advice[:1], "cases": cases[:1], "laws": [], "reports": [], "evidence": []}
    if stage == "case":
        return {"profile": scam, "features": features[:5], "advice": advice[:1], "cases": cases[:2], "laws": laws[:1], "reports": [], "evidence": evidence[:1]}
    if stage == "prevention":
        return {"profile": scam, "features": features[:4], "advice": advice[:3], "cases": cases[:1], "laws": laws[:2], "reports": reports[:1], "evidence": evidence[:1]}
    if stage == "law":
        return {"profile": scam, "features": features[:3], "advice": advice[:2], "cases": cases[:1], "laws": laws[:3], "reports": reports[:2], "evidence": evidence[:2]}
    return {"profile": scam, "features": features[:5], "advice": advice[:2], "cases": cases[:1], "laws": laws[:1], "reports": reports[:1], "evidence": evidence[:1]}


def _material_references(materials: Dict[str, Any], stage: str) -> List[Dict[str, Any]]:
    refs: List[Dict[str, Any]] = []
    for feature in materials.get("features") or []:
        refs.append(
            {
                "id": feature.get("feature_id", ""),
                "knowledge_type": "scam_features",
                "fraud_type": materials.get("profile", {}).get("name", ""),
                "title": feature.get("feature_name", ""),
                "summary": feature.get("explanation", ""),
                "stage": feature.get("stage", ""),
            }
        )
    for advice in materials.get("advice") or []:
        refs.append(
            {
                "id": advice.get("advice_id", ""),
                "knowledge_type": "prevention_advice",
                "fraud_type": advice.get("fraud_type", ""),
                "title": advice.get("advice", ""),
                "summary": _join(advice.get("do"), limit=4),
                "stage": advice.get("risk_stage", ""),
            }
        )
    for case in materials.get("cases") or []:
        refs.append(
            {
                "id": case.get("case_id", ""),
                "knowledge_type": "typical_case",
                "fraud_type": case.get("fraud_type", ""),
                "title": case.get("key_pattern", ""),
                "summary": case.get("summary", ""),
                "stage": case.get("risk_stage", ""),
            }
        )
    for law in materials.get("laws") or []:
        refs.append(
            {
                "id": law.get("law_id", ""),
                "knowledge_type": "law_clause",
                "fraud_type": materials.get("profile", {}).get("name", ""),
                "title": law.get("topic", ""),
                "summary": law.get("plain_summary", ""),
                "stage": stage,
            }
        )
    for report in materials.get("reports") or []:
        refs.append(
            {
                "id": report.get("guide_id", ""),
                "knowledge_type": "report_guide",
                "fraud_type": report.get("fraud_type", ""),
                "title": "报案和线索整理指南",
                "summary": _join(report.get("required_fields"), limit=5),
                "stage": stage,
            }
        )
    for evidence in materials.get("evidence") or []:
        refs.append(
            {
                "id": evidence.get("guide_id", ""),
                "knowledge_type": "evidence_guide",
                "fraud_type": evidence.get("fraud_type", ""),
                "title": evidence.get("scenario", "证据保存指南"),
                "summary": _join(evidence.get("evidence_items"), limit=5),
                "stage": stage,
            }
        )
    deduped: List[Tuple[int, Dict[str, Any]]] = []
    seen = set()
    for index, ref in enumerate(refs):
        key = (ref.get("knowledge_type"), ref.get("id"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append((index, ref))

    stage_priority = {
        "law": {
            "law_clause": 0,
            "report_guide": 1,
            "evidence_guide": 2,
            "prevention_advice": 3,
            "scam_features": 4,
            "typical_case": 5,
        },
        "prevention": {
            "prevention_advice": 0,
            "evidence_guide": 1,
            "report_guide": 2,
            "law_clause": 3,
            "scam_features": 4,
            "typical_case": 5,
        },
        "case": {
            "typical_case": 0,
            "scam_features": 1,
            "prevention_advice": 2,
            "evidence_guide": 3,
            "law_clause": 4,
        },
        "summary": {
            "scam_features": 0,
            "prevention_advice": 1,
            "typical_case": 2,
            "law_clause": 3,
            "report_guide": 4,
            "evidence_guide": 5,
        },
    }.get(stage, {})
    deduped.sort(key=lambda item: (stage_priority.get(item[1].get("knowledge_type"), 20), item[0]))
    return [ref for _, ref in deduped[:10]]


def _compact_materials_for_prompt(materials: Dict[str, Any], stage: str) -> Dict[str, Any]:
    profile = materials.get("profile") or {}
    return {
        "profile": {
            "name": profile.get("name", ""),
            "description": profile.get("description", ""),
            "aliases": profile.get("aliases", [])[:8],
            "common_channels": profile.get("common_channels", [])[:6],
            "target_users": profile.get("target_users", [])[:6],
            "typical_stages": profile.get("typical_stages", [])[:8],
            "critical_facts": profile.get("critical_facts", [])[:8],
            "loss_signals": profile.get("loss_signals", [])[:8],
            "one_sentence_rule": profile.get("one_sentence_rule", ""),
            "risk_formula": profile.get("risk_formula", ""),
        },
        "features": [
            {
                "name": item.get("feature_name", ""),
                "stage": item.get("stage", ""),
                "keywords": item.get("keywords", [])[:6],
                "explanation": item.get("explanation", ""),
            }
            for item in materials.get("features", [])[:8]
        ],
        "advice": [
            {
                "advice": item.get("advice", ""),
                "do": item.get("do", [])[:5],
                "dont": item.get("dont", [])[:5],
                "verification": item.get("official_verification_methods", [])[:4],
                "misconceptions": item.get("common_misconceptions", [])[:4],
            }
            for item in materials.get("advice", [])[:3]
        ],
        "cases": [
            {
                "summary": item.get("summary", ""),
                "key_pattern": item.get("key_pattern", ""),
                "lesson": item.get("lesson", ""),
            }
            for item in materials.get("cases", [])[:2]
        ],
        "laws": [
            {
                "topic": item.get("topic", ""),
                "plain_summary": item.get("plain_summary", ""),
                "actions": item.get("actions", [])[:4],
                "evidence_to_preserve": item.get("evidence_to_preserve", [])[:5],
                "disclaimer": item.get("disclaimer", ""),
            }
            for item in materials.get("laws", [])[:3]
        ],
        "report_guides": [
            {
                "input_type": item.get("input_type", ""),
                "required_fields": item.get("required_fields", [])[:6],
                "evidence_checklist": item.get("evidence_checklist", [])[:6],
                "next_actions": item.get("next_actions", [])[:4],
            }
            for item in materials.get("reports", [])[:2]
        ],
        "evidence_guides": [
            {
                "scenario": item.get("scenario", ""),
                "evidence_items": item.get("evidence_items", [])[:6],
                "collection_tips": item.get("collection_tips", [])[:4],
                "warning": item.get("warning", ""),
            }
            for item in materials.get("evidence", [])[:2]
        ],
        "stage": stage,
    }


def _stage_followup_sentence(stage: str, fraud_type: str = "") -> str:
    topic = _text(fraud_type) or "这类骗局"
    return {
        "overview": f"我还可以告诉您{topic}具体的特征和常见套路。",
        "features": f"我还可以告诉您{topic}通常是怎样一步步把人套进去的。",
        "tactics": f"我还可以用一个典型案例，帮您把{topic}的套路对上现实场景。",
        "case": f"我还可以告诉您遇到{topic}时应该怎么防。",
        "prevention": "我还可以告诉您相关的报案、证据保存和处置常识。",
        "law": f"我还可以帮您把{topic}的重点收成几句话。",
    }.get(stage, "")


def _ensure_stage_followup(answer: str, stage: str, fraud_type: str = "") -> str:
    sentence = _stage_followup_sentence(stage, fraud_type)
    if not sentence:
        return answer
    if sentence in answer:
        return answer
    return f"{answer.rstrip()}\n\n{sentence}"


def _build_teaching_prompt(
    *,
    message: str,
    state: Dict[str, Any],
    scam: Dict[str, Any],
    stage: str,
    materials: Dict[str, Any],
) -> Tuple[str, str]:
    policy = scam.get("teaching_policy") or {}
    global_policy = _global_policy()
    stage_goal = (policy.get("stage_goals") or {}).get(stage, "")
    stage_label = STAGE_LABELS.get(stage, stage)
    close_instruction = (
        "本轮是最终收口。只做简短复盘和记忆点确认，不要再引出案例、流程、下一节，不要用疑问句结尾。"
        if stage == "summary"
        else f"本轮末尾必须用一句自然过渡提示下一步：{_stage_followup_sentence(stage, _text(scam.get('name')))} 不要要求用户回复固定口令，不要问“想听吗/要不要/需不需要/可以吗”，不要像课程目录一样催用户继续。"
    )
    system_prompt = """
你是反诈知识对话导师。你的目标不是一次性百科输出，而是分轮帮助用户理解骗局。
必须遵守：
1. 本轮只完成一个教学重点，不要把定义、套路、案例、防范、法律全部塞进一轮。
2. 中文回答，220-420字为宜，最多5个要点。
3. 只使用材料中支持的事实，不编造法律条文号。
4. 语气要像真实对话，直接、轻一点，不要反复说“好的，我们接着”“这次先把这个记住”。
5. 如果用户是在问知识，就保持科普语气；不要追问他是否已经转账。
6. 避免重复上一轮已经讲过的识别规则；如果必须重复，只压缩成一句。
7. 不要用“好的/好，那咱们/我们接着/下面我们/接下来可以”作为开头。
8. 不要用“想听吗/想继续听吗/要不要/需不需要/可以吗”作为结尾。
9. 自建知识库材料分为结构化诈骗画像/特征、半结构化案例/防范/报案/证据/法律材料。本轮需要什么就取什么，不要把所有材料一次性堆给用户。
"""
    human_prompt = f"""
【用户本轮输入】
{message}

【当前学习状态】
{json.dumps(state, ensure_ascii=False)}

【本轮教学主题】
诈骗类型：{scam.get("name")}
教学阶段：{stage} / {stage_label}
本轮目标：{stage_goal}
一句话识别规则：{policy.get("one_sentence_rule", "")}
收口要求：{close_instruction}

【全局教学策略】
{json.dumps(global_policy.get("teaching_contract", {}), ensure_ascii=False)}

【自建知识库材料】
{json.dumps(_compact_materials_for_prompt(materials, stage), ensure_ascii=False)}

请生成本轮回答。"""
    return system_prompt.strip(), human_prompt.strip()


def _polish_teaching_answer(answer: str, stage: str, fraud_type: str = "") -> str:
    text = (answer or "").strip()
    for pattern in [
        r"^(好的?|好|嗯|收到)[，,。！!\s]*",
        r"^(那)?(我们|咱们)(来|就)?(继续|接着)(讲|聊|看|拆)?[，,。！!\s]*",
        r"^(那)?(我们|咱们)(来|就)?(讲|聊|看|拆)(一下|一看)?[，,。！!\s]*",
    ]:
        text = re.sub(pattern, "", text, count=1).strip()
    text = re.sub(
        r"(接下来|下面|然后)[^。！？\n]*(想听吗|想继续听吗|要不要|需不需要|可以吗)[。！？?？]?\s*$",
        "",
        text,
    ).strip()
    if stage == "summary":
        text = re.sub(
            r"(如果|接下来|后面)[^。！？\n]*(案例|流程|继续|下一节|想听|要不要)[。！？?？]?\s*$",
            "",
            text,
        ).strip()
    text = text or answer.strip()
    return _ensure_stage_followup(text, stage, fraud_type)


def _first_text(items: List[Dict[str, Any]], *keys: str) -> str:
    for item in items:
        for key in keys:
            raw_value = item.get(key)
            value = _join(raw_value, limit=5) if isinstance(raw_value, list) else _text(raw_value)
            if value:
                return value
    return ""


def _build_local_teaching_answer(
    scam: Dict[str, Any],
    stage: str,
    materials: Dict[str, Any],
) -> str:
    fraud_type = _text(scam.get("name")) or "这类骗局"
    profile = materials.get("profile") or {}
    lines: List[str] = []

    if stage == "overview":
        description = _text(profile.get("description")) or _text(profile.get("one_sentence_rule"))
        lines.append(f"{fraud_type}的核心是：{description or '用看似合理的理由诱导你交钱、泄露信息或继续操作。'}")
        channels = _join(profile.get("common_channels"), limit=4)
        if channels:
            lines.append(f"它常出现在：{channels}。")
    elif stage == "features":
        features = materials.get("features", [])[:3]
        lines.append(f"识别{fraud_type}，优先看这些信号：")
        lines.extend(
            f"{index}. {_text(item.get('feature_name')) or _text(item.get('explanation'))}"
            for index, item in enumerate(features, start=1)
            if _text(item.get("feature_name")) or _text(item.get("explanation"))
        )
    elif stage == "tactics":
        stages = _safe_list(profile.get("typical_stages"))[:5]
        lines.append(f"{fraud_type}通常会按这个节奏推进：")
        lines.extend(f"{index}. {_text(item)}" for index, item in enumerate(stages, start=1) if _text(item))
    elif stage == "case":
        case = (materials.get("cases") or [{}])[0]
        lines.append(_text(case.get("summary")) or f"典型的{fraud_type}会先建立信任，再用返利、解冻、保证金或安全验证等理由推动你继续操作。")
        lesson = _text(case.get("lesson") or case.get("key_pattern"))
        if lesson:
            lines.append(f"这个案例要记住：{lesson}")
    elif stage == "prevention":
        advice = (materials.get("advice") or [{}])[0]
        do_items = _join(advice.get("do"), limit=4)
        dont_items = _join(advice.get("dont"), limit=4)
        lines.append(f"防{fraud_type}，先做两件事：{do_items or '通过官方渠道核验身份和业务真实性'}。")
        if dont_items:
            lines.append(f"不要做：{dont_items}。")
    elif stage == "law":
        law = _first_text(materials.get("laws", []), "plain_summary", "topic")
        report = _first_text(materials.get("reports", []), "next_actions", "evidence_checklist")
        evidence = _first_text(materials.get("evidence", []), "warning", "collection_tips")
        lines.append(law or "涉及资金损失时，优先止付、冻结、报警，并保存完整证据链。")
        if report:
            lines.append(f"处置上重点是：{report}")
        if evidence:
            lines.append(f"证据上注意：{evidence}")
    else:
        rule = _text(profile.get("one_sentence_rule")) or "陌生链接不点，验证码不交，转账前先核验。"
        lines.append(f"把{fraud_type}记成一句话：{rule}")

    answer = "\n".join(line for line in lines if line).strip()
    return _ensure_stage_followup(answer or f"{fraud_type}要重点防范诱导转账、验证码泄露和屏幕共享。", stage, fraud_type)


def _generate_teaching_answer(
    *,
    message: str,
    state: Dict[str, Any],
    scam: Dict[str, Any],
    stage: str,
    materials: Dict[str, Any],
    use_llm: bool,
) -> Tuple[str, str]:
    config_error = get_llm_config_error() if use_llm else "LLM generation is disabled"
    if config_error:
        logger.warning(f"Use local teaching answer: {config_error}")
        return _build_local_teaching_answer(scam, stage, materials), "local_template"
    system_prompt, human_prompt = _build_teaching_prompt(
        message=message,
        state=state,
        scam=scam,
        stage=stage,
        materials=materials,
    )
    try:
        llm = get_llm_client(json_mode=False)
        response = llm.invoke([SystemMessage(content=system_prompt), HumanMessage(content=human_prompt)])
        answer = get_message_content(response).strip()
        if not answer:
            raise ValueError("知识对话 LLM 生成了空回答")
        return _polish_teaching_answer(answer, stage, _text(scam.get("name"))), "llm_knowledge_dialogue"
    except Exception as exc:
        logger.warning(f"Teaching answer LLM failed, use local fallback: {exc}", exc_info=True)
        return _build_local_teaching_answer(scam, stage, materials), "local_template_after_llm_error"


def _build_unknown_topic_response(session_id: str, message: str, memory: Dict[str, Any]) -> Dict[str, Any]:
    answer = (
        "可以，你可以直接说想了解哪类骗局，比如刷单返利、游戏交易、冒充公检法、虚假投资、校园贷/网络贷款。"
        "我会分轮讲：先讲核心识别点，再按你的追问展开套路、案例、防范建议和法律处置常识。"
    )
    memory.setdefault("history", []).extend(
        [{"role": "user", "content": message}, {"role": "assistant", "content": answer}]
    )
    memory["history"] = memory["history"][-8:]
    return {
        "message": "知识对话需要明确主题",
        "answer": answer,
        "session_id": session_id,
        "intent": "general",
        "intent_label": "综合科普",
        "topics": [],
        "references": [],
        "source": "knowledge_dialogue_policy",
        "generation": "template",
        "module": "knowledge_assistant",
        "scope": "anti_fraud_knowledge_dialogue",
        "assistant_mode": "knowledge_education",
        "workflow_mode": WORKFLOW_MODE,
        "knowledge_dialogue_state": memory.get("knowledge_dialogue_state", {}),
    }


def run_knowledge_dialogue_agent(
    *,
    message: str,
    session_id: str,
    memory: Dict[str, Any],
    history: Optional[List[Dict[str, Any]]] = None,
    route_decision: Optional[Dict[str, Any]] = None,
    use_llm: bool = True,
    limit: int = 8,
) -> Dict[str, Any]:
    message = (message or "").strip()
    state = dict(memory.get("knowledge_dialogue_state") or {})
    route_decision = route_decision or {}
    turn_semantics = route_decision.get("knowledge_turn_semantics")
    if not isinstance(turn_semantics, dict) or not turn_semantics:
        turn_semantics = analyze_learning_turn_semantics(
            message=message,
            state=state,
            route_decision=route_decision,
            use_llm=use_llm,
        )
    if turn_semantics.get("is_risk_interrupt"):
        raise RuntimeError("知识对话检测到风险打断，应由 risk_case_flow 处理")

    route_prefill = (route_decision.get("routing_decision") or {}).get("prefill_slots") or {}
    topic_hint = " ".join(
        str(value or "").strip()
        for value in [
            route_decision.get("normalized_topic"),
            route_decision.get("query_rewrite"),
            route_prefill.get("normalized_topic") if isinstance(route_prefill, dict) else "",
            route_prefill.get("education_topic") if isinstance(route_prefill, dict) else "",
        ]
        if str(value or "").strip()
    )
    match_message = f"{message} {topic_hint}".strip()
    topic_match = match_dialogue_topic_with_semantics(match_message, state, turn_semantics=turn_semantics)
    if not topic_match:
        return _build_unknown_topic_response(session_id, message, memory)

    scam = topic_match["scam"]
    topic = _text(scam.get("name"))
    topic_changed = bool(state.get("topic") and state.get("topic") != topic)
    stage = choose_teaching_stage(message, state, topic_changed=topic_changed, turn_semantics=turn_semantics)
    if stage not in STAGE_ORDER:
        stage = "overview"

    completed = [] if topic_changed else list(state.get("completed_sections") or [])
    if stage not in completed:
        completed.append(stage)
    completed = [item for item in STAGE_ORDER if item in completed]

    materials = _stage_materials(scam, stage)
    answer, generation = _generate_teaching_answer(
        message=message,
        state=state,
        scam=scam,
        stage=stage,
        materials=materials,
        use_llm=use_llm,
    )
    references = _material_references(materials, stage)[: max(1, min(limit, 10))]
    terminal_stage = stage == "summary"
    next_stage = "" if terminal_stage else _next_stage(stage, completed)
    now = datetime.now().isoformat(timespec="seconds")
    updated_state = {
        "active_workflow": WORKFLOW_MODE if not terminal_stage else "idle",
        "dialogue_status": "completed" if terminal_stage else "active",
        "topic": topic,
        "scam_id": scam.get("scam_id", ""),
        "learning_stage": stage,
        "learning_stage_label": STAGE_LABELS.get(stage, stage),
        "completed_sections": completed,
        "available_sections": STAGE_ORDER,
        "next_suggested_stage": next_stage,
        "last_teaching_goal": (scam.get("teaching_policy") or {}).get("stage_goals", {}).get(stage, ""),
        "turn_count": int(state.get("turn_count") or 0) + 1,
        "risk_interruptible": True,
        "matched_terms": topic_match.get("matched_terms", []),
        "turn_semantics": turn_semantics,
        "updated_at": now,
    }
    if terminal_stage:
        updated_state["closed_at"] = now
    memory["knowledge_dialogue_state"] = updated_state
    memory["last_topic"] = topic
    memory["last_intent"] = STAGE_TO_INTENT.get(stage, "general")
    memory.setdefault("history", []).extend(
        [{"role": "user", "content": message}, {"role": "assistant", "content": answer[:600]}]
    )
    memory["history"] = memory["history"][-8:]
    public_topic = {
        "fraud_type": topic,
        "score": topic_match.get("score", 0),
        "matched_terms": topic_match.get("matched_terms", []),
        "aliases": scam.get("aliases", [])[:8],
        "target_users": scam.get("target_users", [])[:6],
    }
    return {
        "message": "知识多轮教学完成",
        "answer": answer,
        "session_id": session_id,
        "intent": STAGE_TO_INTENT.get(stage, "general"),
        "intent_label": STAGE_LABELS.get(stage, stage),
        "topics": [public_topic],
        "references": references,
        "source": "structured_knowledge_dialogue",
        "generation": generation,
        "module": "knowledge_assistant",
        "scope": "anti_fraud_knowledge_dialogue",
        "assistant_mode": "knowledge_education",
        "workflow_mode": WORKFLOW_MODE if not terminal_stage else "knowledge_answer",
        "knowledge_dialogue_state": updated_state,
        "knowledge_turn_semantics": turn_semantics,
        "route_decision": route_decision,
    }


__all__ = [
    "WORKFLOW_MODE",
    "analyze_learning_turn_semantics",
    "is_knowledge_continuation",
    "looks_like_risk_interrupt",
    "load_dialogue_policy",
    "match_dialogue_topic",
    "run_knowledge_dialogue_agent",
]
