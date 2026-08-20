import hashlib
import json
import re
import secrets
from datetime import datetime
from typing import Any, Dict, List, Tuple

from fastapi import HTTPException
from langchain_core.messages import HumanMessage, SystemMessage

from app.anti_fraud.schema import (
    FRAUD_TYPES,
    INTERVENTION_GOALS,
    KNOWLEDGE_TYPES,
    REQUIRED_KNOWLEDGE_FIELDS,
    RISK_FEATURES,
    RISK_LEVELS,
    ROUTES,
    build_embedding_text,
    normalize_risk_features,
)
from app.lm.lm_utils import get_llm_client
from app.clients.milvus_utils import get_milvus_client
from app.clients.mongo_business_utils import (
    get_business_mongo_tool,
    search_anti_fraud_knowledge,
    upsert_anti_fraud_knowledge,
    upsert_risk_rules,
    write_audit_log,
)
from app.core.logger import logger
from app.import_process.agent.nodes.node_import_fraud_knowledge_milvus import _create_collection, _to_milvus_rows
from app.lm.embedding_utils import generate_embeddings


STATUS_DRAFT = "draft"
STATUS_PENDING_REVIEW = "pending_review"
STATUS_NEED_MORE_INFO = "need_more_info"
STATUS_REJECTED = "rejected"
STATUS_APPROVED = "approved"
STATUS_READY_TO_PUBLISH = "ready_to_publish"
STATUS_PUBLISHED = "published"
STATUS_ROLLED_BACK = "rolled_back"

PROVENANCE_USER = "from_user_material"
PROVENANCE_LLM = "llm_inferred"
PROVENANCE_RULE = "rule_generated"
PROVENANCE_DB = "db_matched"
PROVENANCE_REVIEW = "needs_review"


SENSITIVE_PATTERNS = [
    ("phone", re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")),
    ("id_card", re.compile(r"(?<!\d)\d{17}[\dXx](?!\d)")),
    ("bank_card", re.compile(r"(?<!\d)(?:\d[ -]?){16,19}(?!\d)")),
    ("url_token", re.compile(r"((?:token|password|pwd|code|auth)=)[^&\s]+", re.I)),
]


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _id(prefix: str) -> str:
    return f"{prefix}_{datetime.now().strftime('%Y%m%d%H%M%S')}_{secrets.token_hex(4)}"


def _as_text(value: Any) -> str:
    return str(value or "").strip()


def _as_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, tuple):
        return [str(item).strip() for item in value if str(item).strip()]
    text = str(value).strip()
    if not text:
        return []
    parts = re.split(r"[\n,，、;；]+", text)
    return [item.strip() for item in parts if item.strip()]


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _extract_json_object(text: str) -> Dict[str, Any]:
    cleaned = str(text or "").strip()
    cleaned = re.sub(r"^```(?:json)?", "", cleaned, flags=re.IGNORECASE).strip()
    cleaned = re.sub(r"```$", "", cleaned).strip()
    try:
        data = json.loads(cleaned)
        return data if isinstance(data, dict) else {}
    except Exception:
        pass
    match = re.search(r"\{.*\}", cleaned, flags=re.DOTALL)
    if not match:
        return {}
    try:
        data = json.loads(match.group(0))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _compact(value: str, limit: int = 180) -> str:
    text = re.sub(r"\s+", " ", _as_text(value))
    return text[:limit]


def redact_sensitive(text: str) -> Tuple[str, List[Dict[str, Any]]]:
    redacted = _as_text(text)
    findings: List[Dict[str, Any]] = []
    for kind, pattern in SENSITIVE_PATTERNS:
        matches = list(pattern.finditer(redacted))
        if not matches:
            continue
        findings.append({"type": kind, "count": len(matches)})
        redacted = pattern.sub(lambda match: match.group(1) + "***" if kind == "url_token" else f"[已脱敏:{kind}]", redacted)
    return redacted, findings


def sanitize_materials(materials: Dict[str, Any]) -> Tuple[Dict[str, Any], List[Dict[str, Any]], str]:
    raw_json = json.dumps(materials or {}, ensure_ascii=False, sort_keys=True, default=str)
    raw_hash = hashlib.sha256(raw_json.encode("utf-8")).hexdigest()
    redactions: List[Dict[str, Any]] = []

    def clean(value: Any, path: str) -> Any:
        if isinstance(value, str):
            redacted, findings = redact_sensitive(value)
            if findings:
                redactions.append({"field": path, "findings": findings})
            return redacted
        if isinstance(value, list):
            return [clean(item, f"{path}[{index}]") for index, item in enumerate(value)]
        if isinstance(value, dict):
            return {str(key): clean(item, f"{path}.{key}" if path else str(key)) for key, item in value.items()}
        return value

    sanitized = clean(materials or {}, "")
    return sanitized if isinstance(sanitized, dict) else {}, redactions, raw_hash


def _source_text(materials: Dict[str, Any]) -> str:
    fields = [
        "fraud_name",
        "aliases",
        "scam_scene",
        "target_users",
        "raw_dialogue",
        "keywords",
        "incident_process",
        "requested_actions",
        "case_description",
        "source_description",
        "evidence_description",
        "links_apps_accounts",
    ]
    return "\n".join(_as_text(materials.get(field)) for field in fields if _as_text(materials.get(field)))


def _infer_fraud_type(materials: Dict[str, Any]) -> str:
    explicit = _as_text(materials.get("suspected_fraud_type"))
    if explicit and explicit != "不确定":
        return explicit
    text = _source_text(materials)
    for fraud_type in FRAUD_TYPES:
        if fraud_type != "未知" and (fraud_type in text or fraud_type.replace("诈骗", "") in text):
            return fraud_type
    rules = [
        ("刷单返利诈骗", ["刷单", "做任务", "返利", "返佣", "补单"]),
        ("网络贷款诈骗", ["贷款", "放款", "刷流水", "会员费"]),
        ("冒充客服诈骗", ["客服", "退款", "理赔", "百万保障"]),
        ("冒充公检法诈骗", ["公安", "警察", "安全账户", "涉案"]),
        ("虚假投资理财诈骗", ["投资", "理财", "虚拟币", "稳赚", "高收益"]),
        ("屏幕共享/远程控制诈骗", ["屏幕共享", "远程控制", "远程协助"]),
        ("钓鱼链接诈骗", ["链接", "网址", "二维码", "验证"]),
    ]
    for fraud_type, words in rules:
        if any(word in text for word in words):
            return fraud_type
    return _as_text(materials.get("fraud_name")) or "未知"


def _risk_tags(materials: Dict[str, Any]) -> List[str]:
    text = _source_text(materials)
    raw = _as_list(materials.get("risk_actions")) + _as_list(materials.get("risk_tags"))
    normalized = normalize_risk_features(raw, text)
    return normalized or ["陌生人引导"]


def _stage_routes_goals(tags: List[str], materials: Dict[str, Any]) -> Tuple[str, List[str], List[int], List[str], str]:
    user_stage = _as_text(materials.get("user_stage"))
    text = user_stage + " " + _source_text(materials)
    if "已发生转账" in tags or "已经转账" in text or "损失" in text:
        return "损失发生阶段", ["loss_response"], [2], ["preserve_evidence", "call_bank", "call_police"], "高风险"
    if any(tag in tags for tag in ["索要验证码", "索要银行卡或身份信息", "屏幕共享", "远程控制", "诱导下载陌生APP"]):
        goals = ["ask_clarification"]
        if "索要验证码" in tags:
            goals.append("stop_code_leak")
        if "屏幕共享" in tags or "远程控制" in tags:
            goals.append("stop_screen_share")
        if "诱导下载陌生APP" in tags:
            goals.append("stop_app_install")
        return "信息索取阶段", ["prevention_consult"], [1], goals, "高风险"
    if any(tag in tags for tag in ["要求垫付资金", "贷款前收费", "要求缴纳解冻费", "大额垫付"]):
        return "资金转账前阶段", ["prevention_consult"], [1], ["stop_transfer", "ask_clarification"], "高风险"
    if "科普" in user_stage or "了解" in user_stage:
        return "科普学习", ["education"], [3], ["educate"], "不适用"
    return "初步接触阶段", ["prevention_consult", "education"], [1, 3], ["ask_clarification", "educate"], "中风险"


def _record(
    draft_id: str,
    knowledge_type: str,
    fraud_type: str,
    fraud_stage: str,
    title: str,
    summary: str,
    content: str,
    risk_tags: List[str],
    routes: List[str],
    case_types: List[int],
    goals: List[str],
    risk_level: str,
    source: str,
    priority: int,
) -> Dict[str, Any]:
    suffix = secrets.token_hex(3)
    return {
        "knowledge_id": f"{draft_id}_{knowledge_type}_{suffix}",
        "knowledge_type": knowledge_type,
        "fraud_type": fraud_type,
        "fraud_stage": fraud_stage,
        "title": title,
        "summary": summary,
        "content": content,
        "risk_tags": [tag for tag in risk_tags if tag in RISK_FEATURES],
        "applicable_routes": [route for route in routes if route in ROUTES],
        "applicable_case_types": case_types or [3],
        "intervention_goals": [goal for goal in goals if goal in INTERVENTION_GOALS],
        "user_stage": fraud_stage,
        "use_when": f"用户咨询或描述与{fraud_type}相关、且处于{fraud_stage}时使用。",
        "do_not_use_when": "材料来源不足、与用户场景不匹配或需要人工补充核实时不要直接引用。",
        "answer_role": "为智能反诈助手提供可审核的知识、劝阻或处置依据。",
        "priority": max(0, min(int(priority), 100)),
        "risk_level": risk_level if risk_level in RISK_LEVELS else "风险未知",
        "source": source,
    }


def build_agent_draft(materials: Dict[str, Any]) -> Dict[str, Any]:
    draft_id = _id("draft")
    combined = _source_text(materials)
    redacted_text, sensitive = redact_sensitive(combined)
    fraud_type = _infer_fraud_type(materials)
    tags = _risk_tags(materials)
    fraud_stage, routes, case_types, goals, risk_level = _stage_routes_goals(tags, materials)
    fraud_name = _as_text(materials.get("fraud_name")) or fraud_type
    aliases = _as_list(materials.get("aliases"))
    source = _as_text(materials.get("source_url")) or _as_text(materials.get("source_description")) or "新增骗局接入工单"
    case_text = _as_text(materials.get("case_description"))
    process_text = _as_text(materials.get("incident_process"))
    dialogue_text = _as_text(materials.get("raw_dialogue"))
    keyword_text = _as_text(materials.get("keywords"))
    action_text = _as_text(materials.get("requested_actions"))
    scene_text = _as_text(materials.get("scam_scene"))

    knowledge_items = [
        _record(
            draft_id,
            "fraud_definition",
            fraud_type,
            "科普学习",
            f"{fraud_name}是什么",
            f"{fraud_name}的定义、常见包装和核心风险。",
            f"{fraud_name}疑似属于{fraud_type}。从提交材料看，诈骗场景是：{_compact(scene_text or dialogue_text or process_text or fraud_name, 240)}。识别时重点看是否出现{ '、'.join(tags) }等风险信号。",
            tags,
            ["education"],
            [3],
            ["educate"],
            "不适用",
            source,
            72,
        ),
        _record(
            draft_id,
            "fraud_process",
            fraud_type,
            fraud_stage,
            f"{fraud_name}的诱导流程",
            "从接触、建立信任到诱导操作的流程草稿。",
            process_text or f"根据材料，诱导链路包括：接触用户、制造可信身份、提出操作要求、施加收益或风险压力，最终要求用户执行{action_text or '转账、泄露信息或下载陌生工具'}。",
            tags,
            routes,
            case_types,
            goals,
            risk_level,
            source,
            82,
        ),
        _record(
            draft_id,
            "risk_signal",
            fraud_type,
            fraud_stage,
            f"{fraud_name}的风险信号",
            "可用于识别该类骗局的关键风险特征。",
            f"命中的风险信号包括：{ '、'.join(tags) }。典型关键词包括：{_compact(keyword_text or '暂无单独填写', 180)}。如果对方话术中出现这些要求，应先停止操作并核实来源。原始材料摘要：{_compact(redacted_text, 260)}",
            tags,
            routes,
            case_types,
            goals,
            risk_level,
            source,
            88,
        ),
        _record(
            draft_id,
            "prevention_advice",
            fraud_type,
            "资金转账前阶段" if "loss_response" not in routes else fraud_stage,
            f"{fraud_name}的防范建议",
            "面向未操作或准备操作用户的防范建议。",
            "不要点击陌生链接，不要下载陌生 App，不要向私人账户转账，不要提供验证码、银行卡、身份证、人脸识别或屏幕共享。涉及钱款、账号或身份信息时，应回到官方渠道核实。",
            tags,
            ["prevention_consult", "education"],
            [1, 3],
            ["stop_transfer", "educate", "ask_clarification"],
            "高风险" if risk_level == "高风险" else "中风险",
            source,
            84,
        ),
        _record(
            draft_id,
            "persuasion_script",
            fraud_type,
            fraud_stage,
            f"{fraud_name}实时劝阻话术",
            "当用户正在被诱导操作时使用的短劝阻话术。",
            f"先停下，不要继续操作。你描述的场景已经出现{ '、'.join(tags[:5]) }等风险信号，先不要转账、不要发验证码、不要共享屏幕，也不要下载对方发来的 App。把对方身份、链接和收款账户先保存下来，再通过官方渠道核实。",
            tags,
            ["prevention_consult", "loss_response"],
            [1, 2],
            goals + ["preserve_evidence"],
            "高风险",
            source,
            94,
        ),
    ]
    if case_text:
        knowledge_items.append(
            _record(
                draft_id,
                "fraud_case",
                fraud_type,
                fraud_stage,
                f"{fraud_name}典型案例",
                "根据提交材料整理的案例草稿，发布前需核验来源。",
                case_text,
                tags,
                ["education", "prevention_consult"],
                [1, 3],
                ["educate", "ask_clarification"],
                risk_level,
                source,
                76,
            )
        )
    if "loss_response" in routes or "已发生转账" in tags:
        knowledge_items.extend(
            [
                _record(
                    draft_id,
                    "intervention_action",
                    fraud_type,
                    "损失发生阶段",
                    f"{fraud_name}已操作后的止损动作",
                    "已经转账、泄露信息或下载软件后的第一优先级动作。",
                    "立即停止继续转账或补交费用，保存聊天记录、链接、App、收款账户和转账凭证。已转账时尽快联系银行或支付平台申请止付，并报警说明完整时间线。",
                    tags,
                    ["loss_response"],
                    [2],
                    ["preserve_evidence", "call_bank", "call_police"],
                    "高风险",
                    source,
                    98,
                ),
                _record(
                    draft_id,
                    "evidence_guide",
                    fraud_type,
                    "止损报警阶段",
                    f"{fraud_name}证据保存清单",
                    "用于报警、止付和平台举报的证据清单。",
                    "保存对方账号、聊天记录、群聊信息、链接、二维码、App 名称、下载页面、收款账户、转账凭证、通话记录和任何要求保密或删除记录的话术截图。",
                    tags,
                    ["loss_response"],
                    [2],
                    ["preserve_evidence", "call_police"],
                    "高风险",
                    source,
                    92,
                ),
            ]
        )

    duplicate_candidates = []
    try:
        duplicate_candidates = search_anti_fraud_knowledge(fraud_name, limit=5)
    except Exception as exc:
        logger.warning(f"重复知识检索失败：{exc}")

    rule_candidate = {
        "candidate_id": _id("rulecand"),
        "rule_id": f"runtime_{draft_id}",
        "fraud_type": fraud_type,
        "rule_name": f"{fraud_name}风险识别候选规则",
        "risk_score": 92 if risk_level == "高风险" else 72,
        "risk_level": risk_level if risk_level != "不适用" else "中风险",
        "intervention_goal": goals[0] if goals else "ask_clarification",
        "conditions": {
            "any": tags[:6],
            "must_include_any": [[fraud_name] + aliases[:4]] if fraud_name else [],
        },
        "suggested_action": "先停止操作，通过官方渠道核实，涉及钱款或验证码时不要继续。",
        "enabled": False,
    }

    test_case = {
        "case_id": _id("testcase"),
        "input": dialogue_text or keyword_text or case_text or process_text or f"有人向我推荐{fraud_name}，让我继续操作",
        "expected_fraud_type": fraud_type,
        "expected_risk_tags": tags,
        "expected_min_risk_level": risk_level if risk_level != "不适用" else "中风险",
    }

    quality = run_static_checks({"knowledge_items": knowledge_items, "rule_candidates": [rule_candidate]}, materials)
    return {
        "draft_id": draft_id,
        "status": STATUS_PENDING_REVIEW,
        "scam_profile": {
            "fraud_name": fraud_name,
            "fraud_type": fraud_type,
            "is_new_type": fraud_type not in FRAUD_TYPES,
            "aliases": aliases,
            "channels": _as_list(scene_text),
            "target_users": _as_list(materials.get("target_users")),
            "risk_tags": tags,
            "risk_level": risk_level,
            "fraud_stage": fraud_stage,
        },
        "sanitized_material": {
            "redacted_text": redacted_text,
            "sensitive_findings": sensitive,
            "source_type": _as_text(materials.get("source_type")),
            "source_url": _as_text(materials.get("source_url")),
            "source_description": _as_text(materials.get("source_description")),
        },
        "knowledge_items": knowledge_items,
        "rule_candidates": [rule_candidate],
        "test_cases": [test_case],
        "duplicate_candidates": [
            {
                "knowledge_id": item.get("knowledge_id", ""),
                "title": item.get("title", ""),
                "fraud_type": item.get("fraud_type", ""),
                "summary": item.get("summary", ""),
            }
            for item in duplicate_candidates[:5]
        ],
        "quality_checks": quality,
        "agent_notes": [
            "该草稿由系统根据原始材料自动整理，必须人工审核后才能进入发布校验。",
            "如涉及新增诈骗类型，请审核名称、别名、适用范围和规则影响。",
        ],
        "created_at": _now(),
        "updated_at": _now(),
    }


def run_static_checks(draft: Dict[str, Any], materials: Dict[str, Any] | None = None) -> Dict[str, Any]:
    blockers: List[str] = []
    warnings: List[str] = []
    knowledge_items = draft.get("knowledge_items") or []
    if not knowledge_items:
        blockers.append("草稿没有知识条目")
    seen = set()
    for index, item in enumerate(knowledge_items, start=1):
        for field in REQUIRED_KNOWLEDGE_FIELDS:
            if item.get(field) in [None, "", []]:
                blockers.append(f"第 {index} 条知识缺少必填字段：{field}")
        if item.get("knowledge_id") in seen:
            blockers.append(f"knowledge_id 重复：{item.get('knowledge_id')}")
        seen.add(item.get("knowledge_id"))
        if item.get("knowledge_type") not in KNOWLEDGE_TYPES:
            blockers.append(f"第 {index} 条 knowledge_type 非法：{item.get('knowledge_type')}")
        invalid_tags = [tag for tag in item.get("risk_tags") or [] if tag not in RISK_FEATURES]
        if invalid_tags:
            blockers.append(f"第 {index} 条存在非法风险标签：{invalid_tags}")
        invalid_routes = [route for route in item.get("applicable_routes") or [] if route not in ROUTES]
        if invalid_routes:
            blockers.append(f"第 {index} 条 applicable_routes 非法：{invalid_routes}")
        invalid_goals = [goal for goal in item.get("intervention_goals") or [] if goal not in INTERVENTION_GOALS]
        if invalid_goals:
            blockers.append(f"第 {index} 条 intervention_goals 非法：{invalid_goals}")
        _, findings = redact_sensitive("\n".join([str(item.get("title", "")), str(item.get("summary", "")), str(item.get("content", ""))]))
        if findings:
            blockers.append(f"第 {index} 条疑似含敏感信息：{findings}")
    return {
        "passed": not blockers,
        "blockers": blockers,
        "warnings": warnings,
        "checked_at": _now(),
    }


def _default_field_sources(materials: Dict[str, Any], llm_used: bool = False) -> Dict[str, Dict[str, Any]]:
    sources: Dict[str, Dict[str, Any]] = {}
    direct_map = {
        "scam_profile.fraud_name": "fraud_name",
        "scam_profile.channels": "scam_scene",
        "scam_profile.target_users": "target_users",
        "knowledge_items.fraud_process.content": "incident_process",
        "knowledge_items.risk_signal.content": "keywords",
        "test_cases.input": "raw_dialogue",
    }
    for path, field in direct_map.items():
        evidence = _compact(_as_text(materials.get(field)), 160)
        if evidence:
            sources[path] = {
                "source_type": PROVENANCE_USER,
                "evidence": evidence,
                "review_required": False,
            }
    inferred_paths = [
        "scam_profile.fraud_type",
        "scam_profile.risk_level",
        "scam_profile.risk_tags",
        "knowledge_items.prevention_advice",
        "knowledge_items.persuasion_script",
        "rule_candidates",
    ]
    for path in inferred_paths:
        sources.setdefault(
            path,
            {
                "source_type": PROVENANCE_LLM if llm_used else PROVENANCE_RULE,
                "evidence": "根据提交材料和反诈知识库结构推断生成",
                "review_required": True,
            },
        )
    return sources


def _missing_required_facts(materials: Dict[str, Any], draft: Dict[str, Any]) -> List[Dict[str, Any]]:
    facts = [
        ("material_source", "材料来源", "当前精简表单不采集来源，发布前建议管理员确认材料出处。", True),
        ("real_case_status", "是否真实案例", "仅凭表单无法确认是否来自真实案例或内部核验记录。", True),
        ("loss_amount", "涉及金额或损失情况", "材料未说明是否有资金损失、损失金额或是否只是未遂。", False),
        ("platform_app_link_account", "平台/App/链接/账号", "材料未必包含具体平台、App、链接、账号或收款账户。", False),
        ("legal_basis", "法律依据", "法律条款和监管出处不能由模型凭空确定，需要人工补充或保持为空。", False),
        ("duplicate_relation", "是否已有骗局变体", "系统可检索相似知识，但是否作为新骗局接入需要人工判断。", True),
    ]
    duplicate_candidates = draft.get("duplicate_candidates") or []
    values = {
        "loss_amount": _source_text(materials),
        "platform_app_link_account": _source_text(materials),
        "duplicate_relation": "has_duplicate_candidates" if duplicate_candidates else "",
    }
    result: List[Dict[str, Any]] = []
    for field, label, reason, required_for_publish in facts:
        text = values.get(field, "")
        if field == "loss_amount" and any(word in text for word in ["元", "块", "万", "损失", "转账", "付款"]):
            continue
        if field == "platform_app_link_account" and any(word in text for word in ["http", "APP", "App", "app", "平台", "账号", "收款", "银行卡"]):
            continue
        if field == "duplicate_relation" and duplicate_candidates:
            continue
        result.append(
            {
                "field": field,
                "label": label,
                "reason": reason,
                "required_for_publish": required_for_publish,
                "suggested_admin_action": "人工确认后补充，或在审核意见中说明暂不需要。",
            }
        )
    return result


def _completion_assessment(materials: Dict[str, Any], draft: Dict[str, Any], missing: List[Dict[str, Any]], llm_status: str) -> Dict[str, Any]:
    required_fields = ["fraud_name", "scam_scene", "target_users", "incident_process", "raw_dialogue", "keywords"]
    filled = sum(1 for field in required_fields if _as_text(materials.get(field)))
    hard_missing = sum(1 for item in missing if item.get("required_for_publish"))
    item_count = len(draft.get("knowledge_items") or [])
    score = min(100, max(0, int((filled / len(required_fields)) * 55) + min(item_count, 8) * 5 - hard_missing * 8))
    return {
        "score": score,
        "level": "可审核" if score >= 70 else "需补充",
        "llm_status": llm_status,
        "summary": "已形成标准接入草稿，仍需管理员确认事实来源和是否作为新增骗局发布。",
        "must_review_before_publish": [item.get("label") for item in missing if item.get("required_for_publish")],
    }


def _llm_standardize_payload(materials: Dict[str, Any], draft: Dict[str, Any]) -> tuple[Dict[str, Any], str, str]:
    system_prompt = """
你是反诈知识库“新增骗局材料接入”的结构化专家。你只输出 JSON，不直接对用户说话。

边界规则：
1. 只能基于提交材料、现有规则草稿和常见反诈知识补齐结构，不能伪造来源、真实案例、损失金额、具体平台账号或法律依据。
2. 对于无法从材料确认的事实，必须放入 missing_required_facts，不能编造。
3. 每个关键字段需要给 field_sources，标明 from_user_material / llm_inferred / rule_generated / db_matched / needs_review。
4. 输出内容是“待审核草稿”，不是正式知识。措辞要适合进入反诈知识库，不要写成聊天回答。
"""
    human_prompt = f"""
【用户提交材料】
{json.dumps(materials, ensure_ascii=False)}

【系统已有规则草稿】
{json.dumps({k: draft.get(k) for k in ['scam_profile', 'knowledge_items', 'rule_candidates', 'test_cases', 'duplicate_candidates', 'quality_checks']}, ensure_ascii=False)}

【可用枚举】
fraud_types={json.dumps(FRAUD_TYPES, ensure_ascii=False)}
knowledge_types={json.dumps(KNOWLEDGE_TYPES, ensure_ascii=False)}
risk_features={json.dumps(RISK_FEATURES, ensure_ascii=False)}
routes={json.dumps(ROUTES, ensure_ascii=False)}
intervention_goals={json.dumps(INTERVENTION_GOALS, ensure_ascii=False)}
risk_levels={json.dumps(RISK_LEVELS, ensure_ascii=False)}

请返回严格 JSON：
{{
  "standardization_summary": "一句话说明补齐后的接入定位",
  "scam_profile": {{
    "fraud_name": "",
    "fraud_type": "",
    "is_new_type": false,
    "aliases": [],
    "channels": [],
    "target_users": [],
    "risk_tags": [],
    "risk_level": "",
    "fraud_stage": ""
  }},
  "knowledge_items": [
    {{
      "knowledge_type": "fraud_definition",
      "fraud_type": "",
      "fraud_stage": "",
      "title": "",
      "summary": "",
      "content": "",
      "risk_tags": [],
      "applicable_routes": [],
      "applicable_case_types": [1],
      "intervention_goals": [],
      "user_stage": "",
      "use_when": "",
      "do_not_use_when": "",
      "answer_role": "",
      "priority": 80,
      "risk_level": "",
      "source": "AI补齐标准接入草稿（需人工审核）"
    }}
  ],
  "rule_candidates": [
    {{
      "fraud_type": "",
      "rule_name": "",
      "risk_score": 80,
      "risk_level": "",
      "intervention_goal": "",
      "conditions": {{"any": [], "must_include_any": []}},
      "suggested_action": "",
      "enabled": false
    }}
  ],
  "test_cases": [
    {{
      "input": "",
      "expected_fraud_type": "",
      "expected_risk_tags": [],
      "expected_min_risk_level": ""
    }}
  ],
  "field_sources": {{
    "scam_profile.fraud_name": {{"source_type": "from_user_material", "evidence": "", "review_required": false}}
  }},
  "missing_required_facts": [
    {{"field": "", "label": "", "reason": "", "required_for_publish": true, "suggested_admin_action": ""}}
  ],
  "admin_review_notes": []
}}
"""
    try:
        llm = get_llm_client(json_mode=True)
        response = llm.invoke([SystemMessage(content=system_prompt.strip()), HumanMessage(content=human_prompt.strip())])
        raw_text = (getattr(response, "content", "") or "").strip()
        data = _extract_json_object(raw_text)
        if not data:
            raise ValueError("LLM returned empty JSON")
        return data, raw_text, "llm_completed"
    except Exception as exc:
        logger.warning(f"AI 补齐调用失败，使用规则草稿兜底：{exc}")
        return {}, str(exc), "fallback_rule_generated"


def _normalize_profile(raw: Dict[str, Any], base: Dict[str, Any], materials: Dict[str, Any]) -> Dict[str, Any]:
    base_profile = dict(base.get("scam_profile") or {})
    profile = dict(raw or {})
    fraud_type = _as_text(profile.get("fraud_type")) or base_profile.get("fraud_type") or _infer_fraud_type(materials)
    if fraud_type not in FRAUD_TYPES and fraud_type != "未知":
        fraud_type = base_profile.get("fraud_type") or fraud_type
    risk_level = _as_text(profile.get("risk_level")) or base_profile.get("risk_level") or "中风险"
    if risk_level not in RISK_LEVELS:
        risk_level = "风险未知"
    return {
        "fraud_name": _as_text(profile.get("fraud_name")) or base_profile.get("fraud_name") or _as_text(materials.get("fraud_name")) or fraud_type,
        "fraud_type": fraud_type,
        "is_new_type": bool(profile.get("is_new_type", base_profile.get("is_new_type", fraud_type not in FRAUD_TYPES))),
        "aliases": _as_list(profile.get("aliases") or base_profile.get("aliases")),
        "channels": _as_list(profile.get("channels") or base_profile.get("channels") or materials.get("scam_scene")),
        "target_users": _as_list(profile.get("target_users") or base_profile.get("target_users") or materials.get("target_users")),
        "risk_tags": normalize_risk_features(_as_list(profile.get("risk_tags") or base_profile.get("risk_tags")), _source_text(materials)),
        "risk_level": risk_level,
        "fraud_stage": _as_text(profile.get("fraud_stage")) or base_profile.get("fraud_stage") or "初步接触阶段",
    }


def _normalize_knowledge_item(item: Dict[str, Any], draft_id: str, index: int, profile: Dict[str, Any]) -> Dict[str, Any]:
    knowledge_type = _as_text(item.get("knowledge_type"))
    if knowledge_type not in KNOWLEDGE_TYPES:
        knowledge_type = "education_summary" if index > 5 else (KNOWLEDGE_TYPES[index % len(KNOWLEDGE_TYPES)])
    fraud_stage = _as_text(item.get("fraud_stage") or item.get("user_stage") or profile.get("fraud_stage") or "科普学习")
    risk_level = _as_text(item.get("risk_level") or profile.get("risk_level") or "风险未知")
    if risk_level not in RISK_LEVELS:
        risk_level = "风险未知"
    routes = [route for route in _as_list(item.get("applicable_routes")) if route in ROUTES] or ["education"]
    goals = [goal for goal in _as_list(item.get("intervention_goals")) if goal in INTERVENTION_GOALS] or ["educate"]
    tags = normalize_risk_features(_as_list(item.get("risk_tags") or profile.get("risk_tags")), str(item.get("content", "")))
    case_types = item.get("applicable_case_types") or [3]
    if not isinstance(case_types, list):
        case_types = [case_types]
    case_types = [_safe_int(value, 3) for value in case_types if _safe_int(value, 0) in {1, 2, 3}] or [3]
    title = _as_text(item.get("title")) or f"{profile.get('fraud_name', '新增骗局')}标准知识"
    content = _as_text(item.get("content")) or _as_text(item.get("summary")) or title
    return {
        "knowledge_id": _as_text(item.get("knowledge_id")) or f"{draft_id}_{knowledge_type}_{index}_{secrets.token_hex(3)}",
        "knowledge_type": knowledge_type,
        "fraud_type": _as_text(item.get("fraud_type")) or profile.get("fraud_type") or "未知",
        "fraud_stage": fraud_stage,
        "title": title,
        "summary": _as_text(item.get("summary")) or _compact(content, 120),
        "content": content,
        "risk_tags": tags,
        "applicable_routes": routes,
        "applicable_case_types": case_types,
        "intervention_goals": goals,
        "user_stage": _as_text(item.get("user_stage")) or fraud_stage,
        "use_when": _as_text(item.get("use_when")) or f"用户咨询或描述与{profile.get('fraud_type', '该类骗局')}相关时使用。",
        "do_not_use_when": _as_text(item.get("do_not_use_when")) or "材料事实不足、场景不匹配或需要人工核实时不要直接引用。",
        "answer_role": _as_text(item.get("answer_role")) or "为智能反诈助手提供审核后的知识、劝阻或处置依据。",
        "priority": max(0, min(_safe_int(item.get("priority"), 80), 100)),
        "risk_level": risk_level,
        "source": _as_text(item.get("source")) or "AI补齐标准接入草稿（需人工审核）",
        "provenance": item.get("provenance") or {"source_type": PROVENANCE_LLM, "review_required": True},
    }


def _normalize_rule_candidate(item: Dict[str, Any], draft_id: str, index: int, profile: Dict[str, Any]) -> Dict[str, Any]:
    risk_level = _as_text(item.get("risk_level") or profile.get("risk_level") or "中风险")
    if risk_level not in RISK_LEVELS:
        risk_level = "中风险"
    goal = _as_text(item.get("intervention_goal"))
    if goal not in INTERVENTION_GOALS:
        goal = "ask_clarification"
    return {
        "candidate_id": _as_text(item.get("candidate_id")) or _id("rulecand"),
        "rule_id": _as_text(item.get("rule_id")) or f"runtime_{draft_id}_ai_{index}",
        "fraud_type": _as_text(item.get("fraud_type")) or profile.get("fraud_type") or "未知",
        "rule_name": _as_text(item.get("rule_name")) or f"{profile.get('fraud_name', '新增骗局')}AI补齐候选规则",
        "risk_score": max(0, min(_safe_int(item.get("risk_score"), 80), 100)),
        "risk_level": risk_level,
        "intervention_goal": goal,
        "conditions": item.get("conditions") if isinstance(item.get("conditions"), dict) else {"any": profile.get("risk_tags") or [], "must_include_any": [[profile.get("fraud_name", "")]]},
        "suggested_action": _as_text(item.get("suggested_action")) or "先停止操作，通过官方渠道核实，涉及钱款或验证码时不要继续。",
        "enabled": bool(item.get("enabled", False)),
        "provenance": item.get("provenance") or {"source_type": PROVENANCE_LLM, "review_required": True},
    }


def _normalize_test_case(item: Dict[str, Any], index: int, profile: Dict[str, Any], materials: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "case_id": _as_text(item.get("case_id")) or _id("testcase"),
        "input": _as_text(item.get("input")) or _as_text(materials.get("raw_dialogue")) or _as_text(materials.get("scam_scene")) or f"我遇到{profile.get('fraud_name', '可疑骗局')}，对方让我继续操作。",
        "expected_fraud_type": _as_text(item.get("expected_fraud_type")) or profile.get("fraud_type") or "未知",
        "expected_risk_tags": normalize_risk_features(_as_list(item.get("expected_risk_tags") or profile.get("risk_tags")), _source_text(materials)),
        "expected_min_risk_level": _as_text(item.get("expected_min_risk_level")) or profile.get("risk_level") or "中风险",
        "provenance": item.get("provenance") or {"source_type": PROVENANCE_LLM, "review_required": True},
    }


def _standard_enriched_draft(llm_data: Dict[str, Any], base_draft: Dict[str, Any], materials: Dict[str, Any], llm_status: str, raw_llm: str) -> Dict[str, Any]:
    draft_id = base_draft.get("draft_id") or _id("draft")
    profile = _normalize_profile(llm_data.get("scam_profile") if isinstance(llm_data.get("scam_profile"), dict) else {}, base_draft, materials)
    raw_items = llm_data.get("knowledge_items") if isinstance(llm_data.get("knowledge_items"), list) else []
    if not raw_items:
        raw_items = base_draft.get("knowledge_items") or []
    knowledge_items = [_normalize_knowledge_item(item, draft_id, index, profile) for index, item in enumerate(raw_items[:10], start=1) if isinstance(item, dict)]
    if len(knowledge_items) < 5:
        for index, item in enumerate((base_draft.get("knowledge_items") or [])[:8], start=len(knowledge_items) + 1):
            if isinstance(item, dict):
                knowledge_items.append(_normalize_knowledge_item(item, draft_id, index, profile))

    raw_rules = llm_data.get("rule_candidates") if isinstance(llm_data.get("rule_candidates"), list) else []
    if not raw_rules:
        raw_rules = base_draft.get("rule_candidates") or []
    rule_candidates = [_normalize_rule_candidate(item, draft_id, index, profile) for index, item in enumerate(raw_rules[:5], start=1) if isinstance(item, dict)]

    raw_tests = llm_data.get("test_cases") if isinstance(llm_data.get("test_cases"), list) else []
    if not raw_tests:
        raw_tests = base_draft.get("test_cases") or []
    test_cases = [_normalize_test_case(item, index, profile, materials) for index, item in enumerate(raw_tests[:8], start=1) if isinstance(item, dict)]

    enriched = {
        "scam_profile": profile,
        "knowledge_items": knowledge_items,
        "rule_candidates": rule_candidates,
        "test_cases": test_cases,
        "agent_notes": _as_list(llm_data.get("admin_review_notes")) + [
            "AI补齐内容已按知识库结构归一化，仍需人工确认来源、事实和是否作为新增骗局发布。",
            "字段来源中 llm_inferred / needs_review 的内容不得作为事实直接发布。",
        ],
        "sanitized_material": base_draft.get("sanitized_material") or {},
    }
    enriched["quality_checks"] = run_static_checks(enriched, materials)
    missing = llm_data.get("missing_required_facts") if isinstance(llm_data.get("missing_required_facts"), list) else []
    normalized_missing = [
        {
            "field": _as_text(item.get("field")),
            "label": _as_text(item.get("label")),
            "reason": _as_text(item.get("reason")),
            "required_for_publish": bool(item.get("required_for_publish", True)),
            "suggested_admin_action": _as_text(item.get("suggested_admin_action")) or "人工确认后补充或在审核意见中说明。",
        }
        for item in missing
        if isinstance(item, dict) and (_as_text(item.get("field")) or _as_text(item.get("label")))
    ]
    default_missing = _missing_required_facts(materials, base_draft)
    existing_fields = {item.get("field") for item in normalized_missing}
    normalized_missing.extend([item for item in default_missing if item.get("field") not in existing_fields])

    raw_sources = llm_data.get("field_sources") if isinstance(llm_data.get("field_sources"), dict) else {}
    field_sources = _default_field_sources(materials, llm_used=llm_status == "llm_completed")
    for path, value in raw_sources.items():
        if isinstance(value, dict):
            field_sources[str(path)] = {
                "source_type": value.get("source_type") if value.get("source_type") in {PROVENANCE_USER, PROVENANCE_LLM, PROVENANCE_RULE, PROVENANCE_DB, PROVENANCE_REVIEW} else PROVENANCE_REVIEW,
                "evidence": _compact(value.get("evidence", ""), 220),
                "review_required": bool(value.get("review_required", True)),
            }

    assessment = _completion_assessment(materials, enriched, normalized_missing, llm_status)
    return {
        "enrichment_id": _id("enrich"),
        "status": "generated",
        "llm_status": llm_status,
        "generated_at": _now(),
        "standardization_summary": _as_text(llm_data.get("standardization_summary")) or assessment["summary"],
        "completion_assessment": assessment,
        "field_sources": field_sources,
        "missing_required_facts": normalized_missing,
        "enriched_draft": enriched,
        "raw_llm_excerpt": _compact(raw_llm, 1600),
    }


def generate_review_ai_enrichment(review_id: str, user: Dict[str, Any], use_llm: bool = True, force: bool = False) -> Dict[str, Any]:
    detail = get_review_detail(review_id)
    draft = detail["draft"]
    if not force and draft.get("ai_enrichment", {}).get("status") == "generated":
        return {"detail": detail, "ai_enrichment": draft["ai_enrichment"], "reused": True}
    materials = detail.get("submission", {}).get("materials") or {}
    llm_data: Dict[str, Any] = {}
    raw_text = ""
    llm_status = "fallback_rule_generated"
    if use_llm:
        llm_data, raw_text, llm_status = _llm_standardize_payload(materials, draft)
    enrichment = _standard_enriched_draft(llm_data, draft, materials, llm_status, raw_text)
    enrichment["generated_by"] = {"user_id": user.get("user_id", ""), "username": user.get("username", "")}
    tool = get_business_mongo_tool()
    history_item = {key: enrichment.get(key) for key in ["enrichment_id", "llm_status", "generated_at", "completion_assessment", "standardization_summary"]}
    tool.db["scam_draft_packages"].update_one(
        {"draft_id": draft.get("draft_id")},
        {
            "$set": {"ai_enrichment": enrichment, "updated_at": _now()},
            "$push": {"ai_enrichment_history": {"$each": [history_item], "$slice": -8}},
        },
    )
    tool.db["scam_review_tasks"].update_one({"review_id": review_id}, {"$set": {"updated_at": _now()}})
    add_review_comment(review_id, user, "生成 AI 补齐标准接入草稿", "ai_enrich")
    write_audit_log("scam_review_ai_enriched", {"review_id": review_id, "draft_id": draft.get("draft_id"), "llm_status": llm_status, "user": user.get("username")})
    return {"detail": get_review_detail(review_id), "ai_enrichment": enrichment, "reused": False}


def apply_review_ai_enrichment(review_id: str, user: Dict[str, Any], enrichment_id: str = "") -> Dict[str, Any]:
    detail = get_review_detail(review_id)
    draft = detail["draft"]
    enrichment = draft.get("ai_enrichment") or {}
    if not enrichment or enrichment.get("status") != "generated":
        raise HTTPException(status_code=400, detail="请先生成 AI 补齐草稿")
    if enrichment_id and enrichment.get("enrichment_id") != enrichment_id:
        raise HTTPException(status_code=400, detail="AI 补齐版本不匹配，请刷新后重试")
    enriched_draft = enrichment.get("enriched_draft") or {}
    update = {
        "scam_profile": enriched_draft.get("scam_profile") or draft.get("scam_profile") or {},
        "knowledge_items": enriched_draft.get("knowledge_items") or draft.get("knowledge_items") or [],
        "rule_candidates": enriched_draft.get("rule_candidates") or draft.get("rule_candidates") or [],
        "test_cases": enriched_draft.get("test_cases") or draft.get("test_cases") or [],
        "agent_notes": enriched_draft.get("agent_notes") or draft.get("agent_notes") or [],
        "sanitized_material": enriched_draft.get("sanitized_material") or draft.get("sanitized_material") or {},
        "field_sources": enrichment.get("field_sources") or {},
        "missing_required_facts": enrichment.get("missing_required_facts") or [],
        "completion_assessment": enrichment.get("completion_assessment") or {},
        "ai_enrichment.status": "applied",
        "ai_enrichment.applied_at": _now(),
        "ai_enrichment.applied_by": {"user_id": user.get("user_id", ""), "username": user.get("username", "")},
        "updated_at": _now(),
    }
    merged_for_check = {**draft, **{key: value for key, value in update.items() if "." not in key}}
    update["quality_checks"] = run_static_checks(merged_for_check, detail.get("submission", {}).get("materials") or {})
    tool = get_business_mongo_tool()
    tool.db["scam_draft_packages"].update_one({"draft_id": draft.get("draft_id")}, {"$set": update})
    tool.db["scam_review_tasks"].update_one({"review_id": review_id}, {"$set": {"updated_at": _now()}})
    add_review_comment(review_id, user, "已应用 AI 补齐草稿到审核草稿", "ai_enrich_apply")
    write_audit_log("scam_review_ai_enrichment_applied", {"review_id": review_id, "draft_id": draft.get("draft_id"), "enrichment_id": enrichment.get("enrichment_id"), "user": user.get("username")})
    return get_review_detail(review_id)


def create_intake_submission(materials: Dict[str, Any], submitter: Dict[str, Any] | None = None) -> Dict[str, Any]:
    tool = get_business_mongo_tool()
    submission_id = _id("sub")
    sanitized_materials, redactions, raw_hash = sanitize_materials(materials)
    draft = build_agent_draft(sanitized_materials)
    review_id = _id("review")
    now = _now()
    submitter = submitter or {}
    safe_submitter, submitter_redactions, _ = sanitize_materials(
        {
            "name": submitter.get("name") or sanitized_materials.get("submitter_name"),
            "contact": submitter.get("contact") or sanitized_materials.get("submitter_contact"),
            "team": submitter.get("team") or sanitized_materials.get("submitter_team"),
        }
    )
    submission = {
        "submission_id": submission_id,
        "status": STATUS_PENDING_REVIEW,
        "materials": sanitized_materials,
        "submitter": {
            "name": _as_text(safe_submitter.get("name")),
            "contact": _as_text(safe_submitter.get("contact")),
            "team": _as_text(safe_submitter.get("team")),
        },
        "raw_material_hash": raw_hash,
        "privacy_redactions": redactions + submitter_redactions,
        "draft_id": draft["draft_id"],
        "review_id": review_id,
        "created_at": now,
        "updated_at": now,
    }
    draft_doc = {
        **draft,
        "submission_id": submission_id,
        "review_id": review_id,
    }
    review = {
        "review_id": review_id,
        "submission_id": submission_id,
        "draft_id": draft["draft_id"],
        "status": STATUS_PENDING_REVIEW,
        "decision": "",
        "reviewer": {},
        "comments": [],
        "created_at": now,
        "updated_at": now,
    }
    tool.db["scam_intake_submissions"].insert_one(submission)
    tool.db["scam_draft_packages"].insert_one(draft_doc)
    tool.db["scam_review_tasks"].insert_one(review)
    write_audit_log(
        "scam_intake_submitted",
        {
            "submission_id": submission_id,
            "draft_id": draft["draft_id"],
            "review_id": review_id,
            "redaction_count": len(redactions) + len(submitter_redactions),
        },
    )
    return {"submission": _strip_id(submission), "draft": _strip_id(draft_doc), "review": _strip_id(review)}


def _strip_id(doc: Dict[str, Any]) -> Dict[str, Any]:
    result = dict(doc or {})
    result.pop("_id", None)
    return result


def list_review_tasks(status: str = "", limit: int = 50) -> Dict[str, Any]:
    tool = get_business_mongo_tool()
    query: Dict[str, Any] = {}
    if status:
        query["status"] = status
    items = list(
        tool.db["scam_review_tasks"]
        .find(query, {"_id": 0})
        .sort("updated_at", -1)
        .limit(max(1, min(int(limit or 50), 100)))
    )
    draft_ids = [item.get("draft_id") for item in items if item.get("draft_id")]
    drafts = {
        doc.get("draft_id"): doc
        for doc in tool.db["scam_draft_packages"].find({"draft_id": {"$in": draft_ids}}, {"_id": 0})
    }
    for item in items:
        draft = drafts.get(item.get("draft_id"), {})
        item["scam_profile"] = draft.get("scam_profile", {})
        item["quality_checks"] = draft.get("quality_checks", {})
    return {"items": items, "total": len(items)}


def get_review_detail(review_id: str) -> Dict[str, Any]:
    tool = get_business_mongo_tool()
    review = tool.db["scam_review_tasks"].find_one({"review_id": review_id}, {"_id": 0})
    if not review:
        raise HTTPException(status_code=404, detail="审核任务不存在")
    submission = tool.db["scam_intake_submissions"].find_one({"submission_id": review.get("submission_id")}, {"_id": 0}) or {}
    draft = tool.db["scam_draft_packages"].find_one({"draft_id": review.get("draft_id")}, {"_id": 0}) or {}
    comments = list(tool.db["scam_review_comments"].find({"review_id": review_id}, {"_id": 0}).sort("created_at", 1))
    return {"review": review, "submission": submission, "draft": draft, "comments": comments}


def save_review_draft(review_id: str, draft_update: Dict[str, Any], user: Dict[str, Any]) -> Dict[str, Any]:
    detail = get_review_detail(review_id)
    draft = detail["draft"]
    allowed = [
        "scam_profile",
        "knowledge_items",
        "rule_candidates",
        "test_cases",
        "agent_notes",
        "sanitized_material",
        "field_sources",
        "missing_required_facts",
        "completion_assessment",
    ]
    update = {key: draft_update[key] for key in allowed if key in draft_update}
    merged = {**draft, **update}
    merged["quality_checks"] = run_static_checks(merged)
    merged["updated_at"] = _now()
    tool = get_business_mongo_tool()
    tool.db["scam_draft_packages"].update_one({"draft_id": draft["draft_id"]}, {"$set": merged})
    tool.db["scam_review_tasks"].update_one({"review_id": review_id}, {"$set": {"updated_at": _now()}})
    write_audit_log("scam_review_draft_saved", {"review_id": review_id, "draft_id": draft["draft_id"], "user": user.get("username")})
    return get_review_detail(review_id)


def add_review_comment(review_id: str, user: Dict[str, Any], comment: str, action: str = "") -> None:
    if not comment and not action:
        return
    tool = get_business_mongo_tool()
    tool.db["scam_review_comments"].insert_one(
        {
            "comment_id": _id("comment"),
            "review_id": review_id,
            "action": action,
            "comment": comment,
            "user": {"user_id": user.get("user_id", ""), "username": user.get("username", "")},
            "created_at": _now(),
        }
    )


def decide_review(review_id: str, action: str, comment: str, user: Dict[str, Any]) -> Dict[str, Any]:
    action = _as_text(action)
    status_map = {
        "approve": STATUS_APPROVED,
        "reject": STATUS_REJECTED,
        "need_more_info": STATUS_NEED_MORE_INFO,
        "duplicate": STATUS_REJECTED,
    }
    if action not in status_map:
        raise HTTPException(status_code=400, detail="未知审核动作")
    detail = get_review_detail(review_id)
    draft = detail["draft"]
    if action == "approve":
        checks = run_static_checks(draft)
        if checks["blockers"]:
            raise HTTPException(status_code=400, detail="草稿仍有阻断问题：" + "；".join(checks["blockers"][:5]))
    status = status_map[action]
    tool = get_business_mongo_tool()
    update = {
        "status": status,
        "decision": action,
        "reviewer": {"user_id": user.get("user_id", ""), "username": user.get("username", "")},
        "reviewed_at": _now(),
        "updated_at": _now(),
    }
    tool.db["scam_review_tasks"].update_one({"review_id": review_id}, {"$set": update})
    tool.db["scam_draft_packages"].update_one({"draft_id": draft.get("draft_id")}, {"$set": {"status": status, "updated_at": _now()}})
    tool.db["scam_intake_submissions"].update_one({"submission_id": detail["submission"].get("submission_id")}, {"$set": {"status": status, "updated_at": _now()}})
    add_review_comment(review_id, user, comment, action)
    publish_package = None
    if action == "approve":
        publish_package = create_publish_package(review_id, user)
    write_audit_log("scam_review_decision", {"review_id": review_id, "action": action, "user": user.get("username")})
    return {"detail": get_review_detail(review_id), "publish_package": publish_package}


def create_publish_package(review_id: str, user: Dict[str, Any]) -> Dict[str, Any]:
    tool = get_business_mongo_tool()
    existing = tool.db["scam_publish_packages"].find_one({"review_id": review_id, "status": {"$ne": STATUS_ROLLED_BACK}}, {"_id": 0})
    if existing:
        return existing
    detail = get_review_detail(review_id)
    draft = detail["draft"]
    publish_id = _id("publish")
    package = {
        "publish_id": publish_id,
        "review_id": review_id,
        "draft_id": draft.get("draft_id"),
        "submission_id": detail["submission"].get("submission_id"),
        "status": STATUS_APPROVED,
        "scam_profile": draft.get("scam_profile", {}),
        "knowledge_items": draft.get("knowledge_items", []),
        "rule_candidates": draft.get("rule_candidates", []),
        "test_cases": draft.get("test_cases", []),
        "pre_publish_checks": {},
        "created_by": {"user_id": user.get("user_id", ""), "username": user.get("username", "")},
        "created_at": _now(),
        "updated_at": _now(),
    }
    tool.db["scam_publish_packages"].insert_one(package)
    return _strip_id(package)


def list_publish_packages(status: str = "", limit: int = 50) -> Dict[str, Any]:
    tool = get_business_mongo_tool()
    query: Dict[str, Any] = {}
    if status:
        query["status"] = status
    items = list(
        tool.db["scam_publish_packages"]
        .find(query, {"_id": 0})
        .sort("updated_at", -1)
        .limit(max(1, min(int(limit or 50), 100)))
    )
    return {"items": items, "total": len(items)}


def run_pre_publish_checks(publish_id: str) -> Dict[str, Any]:
    tool = get_business_mongo_tool()
    package = tool.db["scam_publish_packages"].find_one({"publish_id": publish_id}, {"_id": 0})
    if not package:
        raise HTTPException(status_code=404, detail="发布包不存在")
    checks = run_static_checks(package)
    ids = [item.get("knowledge_id") for item in package.get("knowledge_items") or [] if item.get("knowledge_id")]
    existing = list(tool.db["anti_fraud_knowledge"].find({"knowledge_id": {"$in": ids}}, {"_id": 0, "knowledge_id": 1, "title": 1}))
    if existing:
        checks.setdefault("warnings", []).append(f"将覆盖已有知识 ID：{[item.get('knowledge_id') for item in existing]}")
    if not package.get("test_cases"):
        checks.setdefault("warnings", []).append("没有测试样例，建议补充后再发布")
    checks["test_result"] = {
        "passed": checks["passed"],
        "case_count": len(package.get("test_cases") or []),
        "checked_items": len(package.get("knowledge_items") or []),
        "checked_at": _now(),
    }
    status = STATUS_READY_TO_PUBLISH if checks["passed"] else "pre_publish_blocked"
    tool.db["scam_publish_packages"].update_one(
        {"publish_id": publish_id},
        {"$set": {"pre_publish_checks": checks, "status": status, "updated_at": _now()}},
    )
    write_audit_log("scam_pre_publish_checked", {"publish_id": publish_id, "passed": checks["passed"]})
    package = tool.db["scam_publish_packages"].find_one({"publish_id": publish_id}, {"_id": 0})
    return package or {}


def _rebuild_milvus_from_mongo(collection_name: str = "anti_fraud_knowledge") -> Dict[str, Any]:
    tool = get_business_mongo_tool()
    records = list(tool.db["anti_fraud_knowledge"].find({}, {"_id": 0}))
    if not records:
        return {"rebuilt": False, "count": 0, "reason": "formal knowledge is empty"}
    enriched: List[Dict[str, Any]] = []
    texts: List[str] = []
    for item in records:
        doc = dict(item)
        doc["embedding_text"] = build_embedding_text(doc)
        doc["risk_tags_text"] = ",".join(doc.get("risk_tags") or [])
        doc["applicable_routes_text"] = ",".join(doc.get("applicable_routes") or [])
        doc["case_types_text"] = ",".join(str(value) for value in doc.get("applicable_case_types") or [])
        doc["intervention_goals_text"] = ",".join(doc.get("intervention_goals") or [])
        enriched.append(doc)
        texts.append(doc["embedding_text"])
    vectors = generate_embeddings(texts)
    for index, item in enumerate(enriched):
        item["dense_vector"] = vectors["dense"][index]
        item["sparse_vector"] = vectors["sparse"][index]
    client = get_milvus_client()
    if client is None:
        raise RuntimeError("Milvus 客户端初始化失败")
    if client.has_collection(collection_name=collection_name):
        client.drop_collection(collection_name=collection_name)
    _create_collection(client, collection_name, len(enriched[0]["dense_vector"]))
    client.insert(collection_name=collection_name, data=_to_milvus_rows(enriched))
    return {"rebuilt": True, "collection_name": collection_name, "count": len(enriched)}


def publish_package(publish_id: str, user: Dict[str, Any], activate_rules: bool = False) -> Dict[str, Any]:
    tool = get_business_mongo_tool()
    package = run_pre_publish_checks(publish_id)
    checks = package.get("pre_publish_checks") or {}
    if checks.get("blockers"):
        raise HTTPException(status_code=400, detail="发布前校验未通过：" + "；".join(checks["blockers"][:5]))
    knowledge_items = package.get("knowledge_items") or []
    if not knowledge_items:
        raise HTTPException(status_code=400, detail="没有可发布的知识条目")
    version_id = f"scam_pkg_v{datetime.now().strftime('%Y%m%d%H%M%S')}_{secrets.token_hex(3)}"
    ids = [item.get("knowledge_id") for item in knowledge_items]
    previous_docs = list(tool.db["anti_fraud_knowledge"].find({"knowledge_id": {"$in": ids}}, {"_id": 0}))
    previous_by_id = {doc.get("knowledge_id"): doc for doc in previous_docs}
    previous_snapshot = [{"knowledge_id": item, "existed": item in previous_by_id, "document": previous_by_id.get(item)} for item in ids]
    count = upsert_anti_fraud_knowledge(knowledge_items, source_file=version_id)
    scam_profile = package.get("scam_profile") or {}
    if scam_profile.get("is_new_type"):
        tool.db["scam_types"].update_one(
            {"scam_type_id": scam_profile.get("fraud_type")},
            {
                "$set": {
                    "scam_type_id": scam_profile.get("fraud_type"),
                    "name": scam_profile.get("fraud_name") or scam_profile.get("fraud_type"),
                    "operational_fraud_type": scam_profile.get("fraud_type"),
                    "aliases": scam_profile.get("aliases") or [],
                    "source": version_id,
                    "updated_at": _now(),
                },
                "$setOnInsert": {"created_at": _now()},
            },
            upsert=True,
        )
    rule_count = 0
    if package.get("rule_candidates"):
        active_rules: List[Dict[str, Any]] = []
        for rule in package.get("rule_candidates") or []:
            doc = dict(rule)
            doc["publish_id"] = publish_id
            doc["version_id"] = version_id
            doc["status"] = "activated" if activate_rules else "candidate"
            if activate_rules:
                doc["enabled"] = True
            doc["updated_at"] = _now()
            tool.db["risk_rule_candidates"].update_one({"candidate_id": doc.get("candidate_id")}, {"$set": doc}, upsert=True)
            active_rules.append(doc)
        if activate_rules:
            rule_count = upsert_risk_rules(active_rules, source=version_id)
    for case in package.get("test_cases") or []:
        doc = dict(case)
        doc["publish_id"] = publish_id
        doc["version_id"] = version_id
        doc.setdefault("created_at", _now())
        doc["updated_at"] = _now()
        tool.db["scam_test_cases"].update_one({"case_id": doc.get("case_id")}, {"$set": doc}, upsert=True)
    milvus_result = _rebuild_milvus_from_mongo("anti_fraud_knowledge")
    version = {
        "version_id": version_id,
        "publish_id": publish_id,
        "review_id": package.get("review_id"),
        "draft_id": package.get("draft_id"),
        "submission_id": package.get("submission_id"),
        "status": STATUS_PUBLISHED,
        "scam_profile": scam_profile,
        "knowledge_ids": ids,
        "knowledge_items": knowledge_items,
        "previous_snapshot": previous_snapshot,
        "rule_candidates": package.get("rule_candidates") or [],
        "rule_count": rule_count,
        "test_cases": package.get("test_cases") or [],
        "pre_publish_checks": checks,
        "impact_scope": {
            "knowledge_count": len(knowledge_items),
            "knowledge_ids": ids,
            "fraud_type": scam_profile.get("fraud_type", ""),
            "is_new_type": bool(scam_profile.get("is_new_type")),
            "rule_candidate_count": len(package.get("rule_candidates") or []),
            "activated_rule_count": rule_count,
            "test_case_count": len(package.get("test_cases") or []),
        },
        "milvus_result": milvus_result,
        "published_by": {"user_id": user.get("user_id", ""), "username": user.get("username", "")},
        "published_at": _now(),
        "created_at": _now(),
    }
    tool.db["scam_publish_versions"].insert_one(version)
    tool.db["scam_publish_packages"].update_one({"publish_id": publish_id}, {"$set": {"status": STATUS_PUBLISHED, "version_id": version_id, "updated_at": _now()}})
    for collection, key in [
        ("scam_review_tasks", "review_id"),
        ("scam_draft_packages", "draft_id"),
        ("scam_intake_submissions", "submission_id"),
    ]:
        value = package.get(key)
        if value:
            tool.db[collection].update_one({key: value}, {"$set": {"status": STATUS_PUBLISHED, "updated_at": _now()}})
    write_audit_log("scam_package_published", {"publish_id": publish_id, "version_id": version_id, "count": count, "user": user.get("username")})
    return _strip_id(version)


def list_versions(limit: int = 50) -> Dict[str, Any]:
    tool = get_business_mongo_tool()
    items = list(
        tool.db["scam_publish_versions"]
        .find({}, {"_id": 0, "previous_snapshot": 0, "knowledge_items": 0})
        .sort("published_at", -1)
        .limit(max(1, min(int(limit or 50), 100)))
    )
    return {"items": items, "total": len(items)}


def rollback_version(version_id: str, user: Dict[str, Any], reason: str = "") -> Dict[str, Any]:
    tool = get_business_mongo_tool()
    version = tool.db["scam_publish_versions"].find_one({"version_id": version_id}, {"_id": 0})
    if not version:
        raise HTTPException(status_code=404, detail="版本不存在")
    if version.get("status") == STATUS_ROLLED_BACK:
        raise HTTPException(status_code=400, detail="该版本已经回滚")
    restored = 0
    deleted = 0
    for item in version.get("previous_snapshot") or []:
        knowledge_id = item.get("knowledge_id")
        if not knowledge_id:
            continue
        if item.get("existed") and item.get("document"):
            doc = dict(item["document"])
            doc["updated_at"] = _now()
            tool.db["anti_fraud_knowledge"].replace_one({"knowledge_id": knowledge_id}, doc, upsert=True)
            restored += 1
        else:
            deleted += int(tool.db["anti_fraud_knowledge"].delete_one({"knowledge_id": knowledge_id}).deleted_count)
    milvus_result = _rebuild_milvus_from_mongo("anti_fraud_knowledge")
    rollback = {
        "rollback_id": _id("rollback"),
        "version_id": version_id,
        "publish_id": version.get("publish_id"),
        "reason": reason,
        "restored_count": restored,
        "deleted_count": deleted,
        "milvus_result": milvus_result,
        "created_by": {"user_id": user.get("user_id", ""), "username": user.get("username", "")},
        "created_at": _now(),
    }
    tool.db["scam_rollback_records"].insert_one(rollback)
    tool.db["scam_publish_versions"].update_one({"version_id": version_id}, {"$set": {"status": STATUS_ROLLED_BACK, "rolled_back_at": _now()}})
    write_audit_log("scam_package_rolled_back", {"version_id": version_id, "user": user.get("username"), "reason": reason})
    return _strip_id(rollback)


def get_submission_status(submission_id: str) -> Dict[str, Any]:
    tool = get_business_mongo_tool()
    submission = tool.db["scam_intake_submissions"].find_one({"submission_id": submission_id}, {"_id": 0})
    if not submission:
        raise HTTPException(status_code=404, detail="提交不存在")
    review = tool.db["scam_review_tasks"].find_one({"review_id": submission.get("review_id")}, {"_id": 0}) or {}
    return {"submission": submission, "review": review}
