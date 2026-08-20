from __future__ import annotations

import json
import os
import random
import re
import uuid
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from langchain_core.messages import HumanMessage, SystemMessage
from pymongo import DESCENDING

from app.anti_fraud.taxonomy import fraud_type_id_for, fraud_type_registry, standard_name_for
from app.clients.mongo_business_utils import get_business_mongo_tool, search_anti_fraud_knowledge
from app.core.logger import logger
from app.lm.lm_utils import get_llm_client, get_llm_config_error
from app.modules.knowledge_assistant.web_fallback import search_trusted_web
from app.query_process.services.anti_fraud_engine import build_anti_fraud_engine_result
from app.query_process.services.risk_video_card_service import attach_video_cards
from app.utils.sse_utils import SSEEvent, push_to_session
from app.utils.task_utils import TASK_STATUS_PROCESSING, update_task_status


EDUCATION_NAMESPACE = "knowledge_assistant_education"
EDUCATION_COLLECTIONS = {
    "scam_types": "education_scam_types",
    "intent_patterns": "education_intent_patterns",
    "rag_documents": "education_rag_documents",
    "rag_chunks": "education_rag_chunks",
    "law_clauses": "education_law_clauses",
    "official_sources": "education_official_sources",
}

INTENT_DEFINITION = "definition"
INTENT_TECHNIQUE = "technique"
INTENT_CASE = "case"
INTENT_PREVENTION = "prevention"
INTENT_LAW = "law"
INTENT_COMPARE = "compare"
INTENT_SUMMARY = "summary"
INTENT_GENERAL = "general"

INTENT_LABELS = {
    INTENT_DEFINITION: "定义讲解",
    INTENT_TECHNIQUE: "套路手法",
    INTENT_CASE: "案例讲解",
    INTENT_PREVENTION: "防范建议",
    INTENT_LAW: "法律法规",
    INTENT_COMPARE: "对比辨析",
    INTENT_SUMMARY: "学习总结",
    INTENT_GENERAL: "综合科普",
}

INTENT_DOC_TYPES = {
    INTENT_DEFINITION: ["scam_definition", "fraud_definition", "education_summary"],
    INTENT_TECHNIQUE: ["scam_features", "scam_process", "fraud_process", "risk_signal"],
    INTENT_CASE: ["typical_case", "fraud_case"],
    INTENT_PREVENTION: ["prevention_advice", "evidence_guide", "report_guide", "risk_signal", "education_summary"],
    INTENT_LAW: ["law_clause", "official_source", "report_guide", "evidence_guide", "prevention_advice"],
    INTENT_COMPARE: ["scam_definition", "scam_features", "risk_rule", "fraud_definition", "risk_signal"],
    INTENT_SUMMARY: ["education_summary", "scam_definition", "prevention_advice", "risk_rule"],
    INTENT_GENERAL: [
        "scam_definition",
        "scam_features",
        "scam_process",
        "prevention_advice",
        "typical_case",
        "risk_rule",
        "report_guide",
        "evidence_guide",
        "official_source",
        "education_summary",
    ],
}

HANDLING_REPORT_TERMS = [
    "报警",
    "报案",
    "立案",
    "举报",
    "止付",
    "冻结",
    "挂失",
    "追回",
    "追钱",
    "受理",
    "笔录",
    "线索",
]

HANDLING_EVIDENCE_TERMS = [
    "证据",
    "取证",
    "截图",
    "聊天记录",
    "转账凭证",
    "通话记录",
    "保存",
    "材料",
]

RISK_REASONING_TERMS = [
    "风险规则",
    "风险判断",
    "风险等级",
    "风险分",
    "怎么判断",
    "判断依据",
    "推理",
    "劝阻",
]

EDUCATION_V2_TYPES = {
    "fraud_definition",
    "fraud_process",
    "risk_signal",
    "prevention_advice",
    "fraud_case",
    "education_summary",
}

ASSISTANT_MODE_KNOWLEDGE = "knowledge_education"
ASSISTANT_MODE_RISK = "risk_dissuasion"
UNIFIED_MODULE = "unified_anti_fraud_assistant"
RISK_WORKFLOW_MODE = "risk_case_flow"
INTENT_RISK_HELP = "risk_help"
INTENT_EMERGENCY_HELP = "emergency_help"
INTENT_RISK_FACT_CLARIFICATION = "risk_fact_clarification"
RISK_ROUTE_INTENTS = {
    INTENT_RISK_HELP,
    INTENT_EMERGENCY_HELP,
    INTENT_RISK_FACT_CLARIFICATION,
}
SPECIALTY_WORKFLOW_MODES: set[str] = set()

RISK_CONTEXT_KEYWORDS = [
    "已经转账",
    "转账了",
    "已转账",
    "垫了",
    "垫付",
    "付款了",
    "付了",
    "充值了",
    "入金",
    "提现不了",
    "不能提现",
    "无法提现",
    "提现失败",
    "账户冻结",
    "补单",
    "联单",
    "解冻费",
    "保证金",
    "认证费",
    "刷流水",
    "验证码",
    "屏幕共享",
    "远程控制",
    "下载app",
    "下载APP",
    "身份证",
    "护照",
    "签证",
    "边境集合",
    "边境",
    "出境",
    "出国务工",
    "银行卡",
    "刷单任务",
    "做刷单",
    "交钱",
    "先交",
    "押金",
    "定金",
    "留房费",
]
RISK_FOLLOWUP_SHORT_RE = re.compile(
    r"^(没有|没|没有了|还没有|不是|是|有|有的|对|对的|嗯|嗯嗯|好|好的|怎么办|现在怎么办|然后呢|下一步|要怎么办|不知道|不清楚|没办法|不能|可以|不可以)[。！？!?,，\s]*$",
    re.IGNORECASE,
)
PERSONAL_RISK_MARKERS = [
    "我遇到",
    "我碰到",
    "我收到",
    "我看到",
    "有人让我",
    "对方让我",
    "对方叫我",
    "对方要我",
    "客服让我",
    "平台让我",
    "他说让我",
    "他们让我",
    "让我转",
    "让我付",
    "让我交",
    "让我垫",
    "让我下载",
    "让我填",
    "让我发",
    "让我共享",
    "正在",
    "已经",
    "刚刚",
    "还在",
    "催我",
    "联系我",
]
CASE_STUDY_MARKERS = [
    "这是一个反诈案例",
    "这是反诈案例",
    "案例中",
    "案例里",
    "有人碰到了",
    "有人遇到",
    "有人碰到",
    "某人遇到",
    "题目中",
    "下列情形",
    "假设有人",
]
EXPLICIT_PERSONAL_RISK_MARKERS = [
    "我遇到",
    "我碰到",
    "我收到",
    "我现在",
    "我已经",
    "我正在",
    "刚刚",
    "对方让我",
    "客服让我",
    "平台让我",
    "让我转",
    "让我付",
    "让我交",
    "让我垫",
    "让我下载",
    "我转了",
    "我付了",
    "我交了",
]
SMALLTALK_OR_FEEDBACK_MARKERS = [
    "我说的是中文",
    "不是中文",
    "听不懂",
    "识别错",
    "识别不对",
    "你听错",
    "你没听懂",
    "不是这个意思",
    "我不是这个意思",
]
KNOWLEDGE_REQUEST_MARKERS = [
    "科普",
    "讲讲",
    "了解",
    "介绍",
    "什么是",
    "是什么",
    "骗局",
    "诈骗",
    "套路",
    "怎么防",
    "如何防",
    "怎么识别",
    "案例",
    "法律",
]
GENERAL_TRANSFER_TOPIC = "通用转账安全/资金风险科普"
CROSS_BORDER_DOMAIN = "cross_border_fraud"
FUND_TRANSFER_DOMAIN = "fund_transfer"
UNKNOWN_QUERY_DOMAIN = "unknown"
KNOWLEDGE_QUERY_PLAN_SOURCE_LLM = "llm_knowledge_query_planner"
KNOWLEDGE_QUERY_PLAN_SOURCE_LOCAL = "local_knowledge_query_planner"
EXPLICIT_TRANSFER_TERMS = ["转账", "汇款", "银行卡", "收款", "银行转账", "打款", "付款"]
QUERY_INTENT_NOISE_TERMS = [
    "科普一下",
    "科普",
    "讲讲",
    "了解一下",
    "了解",
    "介绍一下",
    "介绍",
    "什么是",
    "是什么",
    "帮我讲讲",
    "给我讲讲",
]
CROSS_BORDER_DOMAIN_TERMS = [
    "境外",
    "跨境",
    "海外",
    "国外",
    "电诈园区",
    "境外电诈",
    "跨境电诈",
    "跨境诈骗",
    "境外诈骗",
    "跨境电信网络诈骗",
]
CROSS_BORDER_JOB_TERMS = [
    "高薪",
    "招工",
    "招聘",
    "客服",
    "出国务工",
    "护照",
    "边境",
    "签证",
    "园区",
    "境外高薪",
    "海外客服",
    "电诈园区",
]
CROSS_BORDER_INVESTMENT_TERMS = ["投资", "理财", "虚拟币", "数字货币", "币", "黄金", "外汇", "usdt", "USDT"]
CROSS_BORDER_RELATIONSHIP_TERMS = ["交友", "恋爱", "婚恋", "情感", "网恋"]
LOCAL_KNOWLEDGE_TOPIC_ALIASES = {
    "租房骗局": "租房合租押金诈骗",
    "租房诈骗": "租房合租押金诈骗",
    "租房押金诈骗": "租房合租押金诈骗",
    "租房被骗": "租房合租押金诈骗",
    "房租押金诈骗": "租房合租押金诈骗",
    "押金看房骗局": "租房合租押金诈骗",
    "银行转账骗局": GENERAL_TRANSFER_TOPIC,
    "转账骗局": GENERAL_TRANSFER_TOPIC,
    "汇款骗局": GENERAL_TRANSFER_TOPIC,
    "银行汇款骗局": GENERAL_TRANSFER_TOPIC,
    "转账安全": GENERAL_TRANSFER_TOPIC,
    "转账前核验": GENERAL_TRANSFER_TOPIC,
}

_SESSION_MEMORY: Dict[str, Dict[str, Any]] = {}
_MAX_MEMORY_TURNS = 8


def _project_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _knowledge_dir() -> Path:
    return _project_root() / "data" / "knowledge"


@lru_cache(maxsize=1)
def load_knowledge_seed() -> List[Dict[str, Any]]:
    data_path = _project_root() / "data" / "anti_fraud_knowledge_v2.json"
    with data_path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    return data if isinstance(data, list) else []


@lru_cache(maxsize=16)
def _load_structured_seed(name: str) -> List[Dict[str, Any]]:
    path = _knowledge_dir() / f"{name}.json"
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError(f"{path} 顶层必须是数组")
    return [item for item in data if isinstance(item, dict)]


def clear_education_memory() -> None:
    _SESSION_MEMORY.clear()


def clear_education_session_memory(session_id: str) -> bool:
    if not session_id:
        return False
    return _SESSION_MEMORY.pop(session_id, None) is not None


def clear_education_cache() -> None:
    _load_structured_seed.cache_clear()
    _build_local_education_documents.cache_clear()
    _load_local_scam_types.cache_clear()


def _summarize(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "knowledge_id": item.get("knowledge_id", ""),
        "knowledge_type": item.get("knowledge_type", ""),
        "fraud_type": item.get("fraud_type", ""),
        "title": item.get("title", ""),
        "summary": item.get("summary", ""),
        "risk_level": item.get("risk_level", ""),
        "priority": item.get("priority", 0),
        "source": item.get("source", ""),
    }


def _search_seed(query: str, limit: int) -> List[Dict[str, Any]]:
    items = load_knowledge_seed()
    tokens = [token for token in re.split(r"\s+", query.strip()) if token]
    if not tokens and query.strip():
        tokens = [query.strip()]
    if not tokens:
        return []

    scored = []
    for item in items:
        text = " ".join(
            [
                str(item.get("title", "")),
                str(item.get("summary", "")),
                str(item.get("content", "")),
                str(item.get("fraud_type", "")),
                " ".join(item.get("risk_tags") or []),
            ]
        )
        score = sum(text.count(token) for token in tokens)
        if score > 0:
            scored.append((score, item))
    scored.sort(key=lambda pair: (pair[0], pair[1].get("priority", 0)), reverse=True)
    return [_summarize(item) for _, item in scored[:limit]]


def search_knowledge(query: str, limit: int = 5) -> Dict[str, Any]:
    """Debug search endpoint.

    This remains intentionally simple and separate from the chat endpoint. It
    first searches the isolated education RAG documents, then falls back to the
    old anti_fraud_knowledge search for compatibility.
    """
    limit = max(1, min(int(limit or 5), 20))
    query = (query or "").strip()
    if not query:
        return {"message": "查询词为空", "items": [], "source": "none"}

    education = retrieve_education_context(query, limit=limit, include_content=False)
    if education["items"]:
        return {
            "message": "教育知识库检索完成",
            "items": education["items"],
            "source": education["source"],
        }

    try:
        mongo_items = search_anti_fraud_knowledge(query, limit=limit)
        if mongo_items:
            return {
                "message": "知识库检索完成",
                "items": [_summarize(item) for item in mongo_items[:limit]],
                "source": "mongo_legacy",
            }
    except Exception as e:
        logger.warning(f"MongoDB 知识检索失败，降级使用本地 JSON：{e}")

    return {
        "message": "知识库检索完成",
        "items": _search_seed(query, limit),
        "source": "json_fallback_legacy",
    }


def _mongo_collection(name: str):
    tool = get_business_mongo_tool()
    return tool.db[name]


def _mongo_find_education_docs(limit: int = 500) -> List[Dict[str, Any]]:
    docs = list(
        _mongo_collection(EDUCATION_COLLECTIONS["rag_documents"])
        .find({"namespace": EDUCATION_NAMESPACE}, {"_id": 0})
        .sort([("priority", DESCENDING)])
        .limit(limit)
    )
    return docs


def _mongo_find_scam_types() -> List[Dict[str, Any]]:
    return list(
        _mongo_collection(EDUCATION_COLLECTIONS["scam_types"])
        .find({"namespace": EDUCATION_NAMESPACE}, {"_id": 0})
    )


def _text_join(values: List[Any] | Any, sep: str = "、") -> str:
    if isinstance(values, list):
        return sep.join(str(item) for item in values if str(item).strip())
    return str(values or "")


def _make_doc(
    *,
    doc_id: str,
    doc_type: str,
    fraud_type: str,
    title: str,
    summary: str,
    content: str,
    keywords: Optional[List[str]] = None,
    aliases: Optional[List[str]] = None,
    target_users: Optional[List[str]] = None,
    source_dataset: str,
    source_ids: Optional[List[str]] = None,
    priority: int = 50,
) -> Dict[str, Any]:
    return {
        "namespace": EDUCATION_NAMESPACE,
        "doc_id": doc_id,
        "doc_type": doc_type,
        "fraud_type": fraud_type,
        "title": title,
        "summary": summary,
        "content": content.strip(),
        "keywords": sorted({item for item in (keywords or []) if item}),
        "aliases": sorted({item for item in (aliases or []) if item}),
        "target_users": sorted({item for item in (target_users or []) if item}),
        "source_dataset": source_dataset,
        "source_ids": source_ids or [],
        "priority": priority,
    }


def _safe_id(raw: str) -> str:
    value = "".join(ch if ch.isalnum() or ch in {"_", "-"} else "_" for ch in raw)
    return "_".join(part for part in value.split("_") if part)[:128]


@lru_cache(maxsize=1)
def _load_local_scam_types() -> List[Dict[str, Any]]:
    return _load_structured_seed("scam_types")


@lru_cache(maxsize=1)
def _build_local_education_documents() -> List[Dict[str, Any]]:
    scam_types = _load_local_scam_types()
    scam_features = _load_structured_seed("scam_features")
    risk_rules = _load_structured_seed("risk_rules")
    prevention_advice = _load_structured_seed("prevention_advice")
    typical_cases = _load_structured_seed("typical_cases")
    law_clauses = _load_structured_seed("law_clauses")
    report_guides = _load_structured_seed("report_guides")
    evidence_guides = _load_structured_seed("evidence_guides")
    official_sources = _load_structured_seed("official_sources")

    features_by_scam: Dict[str, List[Dict[str, Any]]] = {}
    for feature in scam_features:
        features_by_scam.setdefault(str(feature.get("scam_id") or ""), []).append(feature)

    advice_by_type: Dict[str, List[Dict[str, Any]]] = {}
    for advice in prevention_advice:
        advice_by_type.setdefault(str(advice.get("fraud_type") or ""), []).append(advice)

    cases_by_type: Dict[str, List[Dict[str, Any]]] = {}
    for case in typical_cases:
        cases_by_type.setdefault(str(case.get("fraud_type") or ""), []).append(case)

    rules_by_type: Dict[str, List[Dict[str, Any]]] = {}
    for rule in risk_rules:
        rules_by_type.setdefault(str(rule.get("fraud_type") or ""), []).append(rule)

    reports_by_type: Dict[str, List[Dict[str, Any]]] = {}
    for guide in report_guides:
        reports_by_type.setdefault(str(guide.get("fraud_type") or ""), []).append(guide)

    evidence_by_type: Dict[str, List[Dict[str, Any]]] = {}
    for guide in evidence_guides:
        evidence_by_type.setdefault(str(guide.get("fraud_type") or ""), []).append(guide)

    documents: List[Dict[str, Any]] = []
    for scam in scam_types:
        scam_id = str(scam.get("scam_id") or "")
        name = str(scam.get("name") or "")
        aliases = list(scam.get("aliases") or [])
        targets = list(scam.get("target_users") or [])
        channels = list(scam.get("common_channels") or [])
        stages = list(scam.get("typical_stages") or [])
        features = features_by_scam.get(scam_id, [])
        feature_keywords = [
            keyword
            for feature in features
            for keyword in (feature.get("keywords") or [])
            if keyword
        ]
        feature_names = [str(feature.get("feature_name") or "") for feature in features if feature.get("feature_name")]
        profile_terms = [
            str(scam.get("one_sentence_rule") or ""),
            str(scam.get("risk_formula") or ""),
            *[str(item) for item in (scam.get("critical_facts") or [])],
            *[str(item) for item in (scam.get("loss_signals") or [])],
        ]
        keywords = [name, *aliases, *feature_keywords, *feature_names, *profile_terms]

        documents.append(
            _make_doc(
                doc_id=_safe_id(f"local_{scam_id}_definition"),
                doc_type="scam_definition",
                fraud_type=name,
                title=f"什么是{name}",
                summary=str(scam.get("description") or "")[:180],
                content="\n".join(
                    [
                        f"诈骗类型：{name}",
                        f"常见叫法：{_text_join(aliases) or '暂无'}",
                        f"重点人群：{_text_join(targets) or '泛个人用户'}",
                        f"常见渠道：{_text_join(channels) or '社交平台、短信、电话或陌生网页'}",
                        f"核心说明：{scam.get('description') or ''}",
                        f"一句话识别：{scam.get('one_sentence_rule') or ''}",
                        f"风险组合：{scam.get('risk_formula') or ''}",
                        f"关键确认事实：{_text_join(scam.get('critical_facts') or [])}",
                        f"损失/暴露信号：{_text_join(scam.get('loss_signals') or [])}",
                        f"典型阶段：{_text_join(stages) or '接触、建立信任、提出危险要求、造成损失'}",
                    ]
                ),
                keywords=keywords,
                aliases=aliases,
                target_users=targets,
                source_dataset="data/knowledge/scam_types.json",
                source_ids=[scam_id],
                priority=95,
            )
        )

        stage_lines = [f"{name}常见套路："]
        for feature in features:
            stage_lines.append(
                f"- {feature.get('stage') or '常见阶段'} / {feature.get('feature_name')}："
                f"{feature.get('explanation')} 常见关键词：{_text_join(feature.get('keywords') or [])}。"
            )
        documents.append(
            _make_doc(
                doc_id=_safe_id(f"local_{scam_id}_features"),
                doc_type="scam_features",
                fraud_type=name,
                title=f"{name}怎么识别",
                summary=f"整理{name}的高频关键词、话术和阶段特征。",
                content="\n".join(stage_lines),
                keywords=keywords,
                aliases=aliases,
                target_users=targets,
                source_dataset="data/knowledge/scam_features.json",
                source_ids=[str(item.get("feature_id")) for item in features if item.get("feature_id")],
                priority=92,
            )
        )

        if advice_by_type.get(name):
            advice_lines = [f"{name}防范建议："]
            source_ids = []
            for advice in advice_by_type[name]:
                source_ids.append(str(advice.get("advice_id")))
                advice_lines.extend(
                    [
                        f"- 核心建议：{advice.get('advice')}",
                        f"- 应该做：{_text_join(advice.get('do') or [])}",
                        f"- 不要做：{_text_join(advice.get('dont') or [])}",
                        f"- 官方核验：{_text_join(advice.get('official_verification_methods') or [])}",
                        f"- 常见误区：{_text_join(advice.get('common_misconceptions') or [])}",
                    ]
                )
            documents.append(
                _make_doc(
                    doc_id=_safe_id(f"local_{scam_id}_prevention"),
                    doc_type="prevention_advice",
                    fraud_type=name,
                    title=f"{name}如何防范",
                    summary=f"围绕{name}的核验方式、不要做事项和常见误区给出科普建议。",
                    content="\n".join(advice_lines),
                    keywords=keywords,
                    aliases=aliases,
                    target_users=targets,
                    source_dataset="data/knowledge/prevention_advice.json",
                    source_ids=source_ids,
                    priority=94,
                )
            )

        if cases_by_type.get(name):
            case_lines = [f"{name}典型案例讲解："]
            source_ids = []
            for case in cases_by_type[name]:
                source_ids.append(str(case.get("case_id")))
                case_lines.extend(
                    [
                        f"- 案例概述：{case.get('summary')}",
                        f"- 关键套路：{case.get('key_pattern')}",
                        f"- 学习提醒：{case.get('lesson')}",
                    ]
                )
            documents.append(
                _make_doc(
                    doc_id=_safe_id(f"local_{scam_id}_case"),
                    doc_type="typical_case",
                    fraud_type=name,
                    title=f"{name}案例复盘",
                    summary=f"通过脱敏案例理解{name}的关键套路和防范点。",
                    content="\n".join(case_lines),
                    keywords=keywords,
                    aliases=aliases,
                    target_users=targets,
                    source_dataset="data/knowledge/typical_cases.json",
                    source_ids=source_ids,
                    priority=88,
                )
            )

        if rules_by_type.get(name):
            rule_lines = [f"{name}规则化风险推理材料："]
            source_ids = []
            for rule in rules_by_type[name]:
                source_ids.append(str(rule.get("rule_id")))
                rule_lines.extend(
                    [
                        f"- 规则：{rule.get('rule_id')} / {rule.get('risk_level')} / {rule.get('risk_score')}分",
                        f"- 适用阶段：{_text_join(rule.get('stages') or [])}",
                        f"- 条件：{json.dumps(rule.get('conditions') or {}, ensure_ascii=False)}",
                        f"- 结构化条件：{json.dumps(rule.get('semantic_condition_groups') or [], ensure_ascii=False)}",
                        f"- 处置目标：{rule.get('intervention_goal')}",
                        f"- 推理说明：{rule.get('explanation')}",
                    ]
                )
            documents.append(
                _make_doc(
                    doc_id=_safe_id(f"local_{scam_id}_risk_rules"),
                    doc_type="risk_rule",
                    fraud_type=name,
                    title=f"{name}风险判断规则",
                    summary=f"用于支撑{name}的风险推理、等级判断和劝阻目标选择。",
                    content="\n".join(rule_lines),
                    keywords=keywords + ["风险规则", "规则推理", "风险判断", "劝阻话术"],
                    aliases=aliases,
                    target_users=targets,
                    source_dataset="data/knowledge/risk_rules.json",
                    source_ids=source_ids,
                    priority=89,
                )
            )

        report_rows = reports_by_type.get(name, []) + reports_by_type.get("通用", [])
        if report_rows:
            report_lines = [f"{name}报案和线索整理指南："]
            source_ids = []
            for guide in report_rows:
                source_ids.append(str(guide.get("guide_id")))
                report_lines.extend(
                    [
                        f"- 输入类型：{guide.get('input_type')}",
                        f"- 必要信息：{_text_join(guide.get('required_fields') or [])}",
                        f"- 摘要模板：{guide.get('suggested_summary_template')}",
                        f"- 证据清单：{_text_join(guide.get('evidence_checklist') or [])}",
                        f"- 下一步：{_text_join(guide.get('next_actions') or [])}",
                    ]
                )
            documents.append(
                _make_doc(
                    doc_id=_safe_id(f"local_{scam_id}_report_guide"),
                    doc_type="report_guide",
                    fraud_type=name,
                    title=f"{name}怎么报案和整理线索",
                    summary=f"整理{name}报案、平台举报或补充线索时需要准备的信息。",
                    content="\n".join(report_lines),
                    keywords=keywords + ["报案", "举报", "线索", "追回", "止付"],
                    aliases=aliases,
                    target_users=targets,
                    source_dataset="data/knowledge/report_guides.json",
                    source_ids=source_ids,
                    priority=87,
                )
            )

        evidence_rows = evidence_by_type.get(name, []) + evidence_by_type.get("通用", [])
        if evidence_rows:
            evidence_lines = [f"{name}证据保存指南："]
            source_ids = []
            for guide in evidence_rows:
                source_ids.append(str(guide.get("guide_id")))
                evidence_lines.extend(
                    [
                        f"- 场景：{guide.get('scenario')}",
                        f"- 证据项：{_text_join(guide.get('evidence_items') or [])}",
                        f"- 取证提示：{_text_join(guide.get('collection_tips') or [])}",
                        f"- 风险提醒：{guide.get('warning')}",
                    ]
                )
            documents.append(
                _make_doc(
                    doc_id=_safe_id(f"local_{scam_id}_evidence_guide"),
                    doc_type="evidence_guide",
                    fraud_type=name,
                    title=f"{name}证据怎么保存",
                    summary=f"整理{name}中聊天、转账、链接、App、账号等证据的保存方法。",
                    content="\n".join(evidence_lines),
                    keywords=keywords + ["证据", "取证", "截图", "聊天记录", "转账凭证"],
                    aliases=aliases,
                    target_users=targets,
                    source_dataset="data/knowledge/evidence_guides.json",
                    source_ids=source_ids,
                    priority=86,
                )
            )

    for law in law_clauses:
        topic = str(law.get("topic") or "")
        documents.append(
            _make_doc(
                doc_id=_safe_id(f"local_{law.get('law_id')}_law"),
                doc_type="law_clause",
                fraud_type="通用法律法规与处置常识",
                title=topic,
                summary=str(law.get("plain_summary") or "")[:180],
                content="\n".join(
                    [
                        f"主题：{topic}",
                        f"相关行为：{_text_join(law.get('related_behaviors') or [])}",
                        f"相关诈骗类型：{_text_join(law.get('related_scam_types') or [])}",
                        f"通俗说明：{law.get('plain_summary') or ''}",
                        f"一般动作：{_text_join(law.get('actions') or [])}",
                        f"建议保留材料：{_text_join(law.get('evidence_to_preserve') or [])}",
                        f"提示：{law.get('disclaimer') or '以下为一般科普，不替代专业法律意见。'}",
                    ]
                ),
                keywords=list(law.get("related_behaviors") or []) + [topic],
                target_users=["学生", "泛个人用户"],
                source_dataset="data/knowledge/law_clauses.json",
                source_ids=[str(law.get("law_id"))],
                priority=75,
            )
        )

    for source in official_sources:
        source_id = str(source.get("source_id") or "")
        title = str(source.get("title") or "")
        authority = str(source.get("authority") or "")
        url = str(source.get("url") or "")
        domains = list(source.get("domains") or [])
        used_for = list(source.get("used_for") or [])
        documents.append(
            _make_doc(
                doc_id=_safe_id(f"local_{source_id}_source"),
                doc_type="official_source",
                fraud_type="通用法律法规与处置常识",
                title=f"官方来源：{title}",
                summary=str(source.get("coverage") or "")[:220],
                content="\n".join(
                    [
                        f"官方来源：{title}",
                        f"来源机构：{authority}",
                        f"来源类型：{source.get('source_type') or ''}",
                        f"链接：{url}",
                        f"覆盖领域：{_text_join(domains)}",
                        f"用于支撑：{_text_join(used_for)}",
                        f"覆盖说明：{source.get('coverage') or ''}",
                        f"最近核验日期：{source.get('last_checked') or ''}",
                    ]
                ),
                keywords=[title, authority, url, *domains, *used_for, "官方来源", "引用来源", "资料来源"],
                target_users=["学生", "泛个人用户"],
                source_dataset="data/knowledge/official_sources.json",
                source_ids=[source_id],
                priority=72,
            )
        )

    for item in load_knowledge_seed():
        if str(item.get("knowledge_type") or "") not in EDUCATION_V2_TYPES:
            continue
        documents.append(
            _make_doc(
                doc_id=_safe_id(f"v2_{item.get('knowledge_id') or item.get('title')}"),
                doc_type=str(item.get("knowledge_type") or ""),
                fraud_type=str(item.get("fraud_type") or ""),
                title=str(item.get("title") or ""),
                summary=str(item.get("summary") or "")[:220],
                content="\n".join(
                    [
                        f"标题：{item.get('title') or ''}",
                        f"诈骗类型：{item.get('fraud_type') or ''}",
                        f"摘要：{item.get('summary') or ''}",
                        f"正文：{item.get('content') or ''}",
                    ]
                ),
                keywords=list(item.get("risk_tags") or []) + [str(item.get("fraud_type") or "")],
                target_users=["学生", "泛个人用户"],
                source_dataset="data/anti_fraud_knowledge_v2.json",
                source_ids=[str(item.get("knowledge_id") or "")],
                priority=int(item.get("priority") or 60),
            )
        )
    return documents


def _education_docs() -> Tuple[List[Dict[str, Any]], str]:
    try:
        docs = _mongo_find_education_docs()
        if docs:
            return docs, "mongo_education"
    except Exception as exc:
        logger.warning(f"教育 RAG Mongo 检索不可用，降级本地 JSON：{exc}")
    return _build_local_education_documents(), "json_education_fallback"


def _scam_types() -> List[Dict[str, Any]]:
    try:
        rows = _mongo_find_scam_types()
        if rows:
            return rows
    except Exception as exc:
        logger.warning(f"教育 RAG Mongo 诈骗类型不可用，降级本地 JSON：{exc}")
    return _load_local_scam_types()


def _normalize_text(text: str) -> str:
    return (text or "").strip().lower()


def _query_terms(query: str) -> List[str]:
    query = (query or "").strip()
    clean_query = _clean_knowledge_query(query)
    terms = [query] if query else []
    if clean_query and clean_query != query:
        terms.append(clean_query)
    for target in [query, clean_query]:
        terms.extend(re.findall(r"[a-zA-Z0-9_./:-]+|[\u4e00-\u9fff]{2,}", target or ""))
    compact = re.sub(r"\s+", "", query)
    for word in [
        "境外",
        "跨境",
        "海外",
        "国外",
        "电诈",
        "境外电诈",
        "跨境电诈",
        "跨境电信网络诈骗",
        "电诈园区",
        "刷单",
        "返利",
        "游戏交易",
        "游戏装备",
        "公检法",
        "投资",
        "理财",
        "校园贷",
        "培训贷",
        "就业班",
        "求职",
        "实习",
        "招聘",
        "新媒体",
        "运营",
        "推荐实习",
        "月薪",
        "保offer",
        "助学金",
        "学费退费",
        "两卡",
        "跑分",
        "USDT",
        "虚拟币",
        "数字货币",
        "出国高工资",
        "境外高薪",
        "跨境高薪",
        "养老保健品",
        "免费体检",
        "民族资产解冻",
        "国家项目",
        "医保卡",
        "医保码",
        "医保骗保",
        "直播带货",
        "私域交易",
        "裸聊",
        "征信修复",
        "冒充老师",
        "辅导员",
        "案例",
        "防范",
        "法律",
        "报案",
        "报警",
        "举报",
        "证据",
        "取证",
        "止付",
        "追回",
        "风险规则",
        "风险判断",
    ]:
        if word in compact:
            terms.append(word)
    seen = set()
    result = []
    for term in terms:
        term = term.strip()
        if len(term) >= 2 and term not in seen:
            result.append(term)
            seen.add(term)
    return result


def _domain_terms_for_query_plan(query_plan: Dict[str, Any]) -> List[str]:
    query_plan = query_plan or {}
    values: List[Any] = []
    values.extend(query_plan.get("scenario_terms") or [])
    values.extend(query_plan.get("risk_action_terms") or [])
    if str(query_plan.get("domain") or "") == CROSS_BORDER_DOMAIN:
        values.extend(
            [
                "境外",
                "跨境",
                "海外",
                "电诈",
                "境外电诈",
                "跨境电诈",
                "跨境电信网络诈骗",
                "电诈园区",
                "境外高薪",
                "跨境高薪",
                "海外客服",
                "边境招工",
                "出国高工资",
                "出境",
                "边境集合",
                "护照",
                "签证",
                "虚拟币",
                "数字货币",
                "外汇",
                "跨境交友",
                "跑分",
                "两卡",
                "洗钱工具人",
            ]
        )
    return _dedupe_strings(values, limit=32)


def _topic_from_local_semantics(message: str) -> Dict[str, str]:
    compact = re.sub(r"[\s，。,.!！?？、~～]+", "", message or "")
    for alias, topic in LOCAL_KNOWLEDGE_TOPIC_ALIASES.items():
        if alias in compact:
            fraud_type_id = fraud_type_id_for(topic)
            return {
                "normalized_topic": topic,
                "fraud_type_id": fraud_type_id or ("general_anti_fraud" if topic == GENERAL_TRANSFER_TOPIC else ""),
                "query_rewrite": (
                    "转账前如何识别诈骗、核验收款账户和避免资金损失"
                    if topic == GENERAL_TRANSFER_TOPIC
                    else f"{topic} 如何识别 防范 案例"
                ),
                "topic_source": "local_semantic_alias",
            }
    standard_name = standard_name_for(message)
    fraud_type_id = fraud_type_id_for(message)
    if fraud_type_id:
        return {
            "normalized_topic": standard_name,
            "fraud_type_id": fraud_type_id,
            "query_rewrite": f"{standard_name} 如何识别 防范 案例",
            "topic_source": "taxonomy_alias",
        }
    return {}


def _has_knowledge_request(text: str) -> bool:
    compact = re.sub(r"\s+", "", text or "")
    return bool(compact and any(marker in compact for marker in KNOWLEDGE_REQUEST_MARKERS))


def _enrich_route_with_local_knowledge_hints(route: Dict[str, Any], message: str) -> Dict[str, Any]:
    route = dict(route or {})
    hints = _topic_from_local_semantics(message)
    query_rewrite = str(route.get("query_rewrite") or "").strip()
    normalized_topic = str(route.get("normalized_topic") or "").strip()
    fraud_type_id = str(route.get("fraud_type_id") or "").strip()
    if hints:
        normalized_topic = normalized_topic or hints.get("normalized_topic", "")
        fraud_type_id = fraud_type_id or hints.get("fraud_type_id", "")
        query_rewrite = query_rewrite or hints.get("query_rewrite", "")
    route["normalized_topic"] = normalized_topic
    route["fraud_type_id"] = fraud_type_id
    route["query_rewrite"] = query_rewrite or str((route.get("turn_rewrite") or {}).get("rewritten_text") or message)
    if hints:
        route["knowledge_topic_source"] = hints.get("topic_source", "")
    routing_decision = dict(route.get("routing_decision") or {})
    prefill_slots = dict(routing_decision.get("prefill_slots") or {})
    if normalized_topic:
        prefill_slots.setdefault("normalized_topic", normalized_topic)
        prefill_slots.setdefault("education_topic", normalized_topic)
    if fraud_type_id:
        prefill_slots.setdefault("fraud_type_id", fraud_type_id)
    if route["query_rewrite"]:
        prefill_slots.setdefault("query_rewrite", route["query_rewrite"])
    routing_decision["prefill_slots"] = prefill_slots
    route["routing_decision"] = routing_decision
    return route


def _dedupe_strings(values: List[Any], *, limit: int = 12) -> List[str]:
    result: List[str] = []
    seen = set()
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        result.append(text)
        seen.add(text)
        if len(result) >= limit:
            break
    return result


def _clean_knowledge_query(message: str) -> str:
    text = re.sub(r"[\s，。,.!！?？、~～]+", "", message or "")
    for term in QUERY_INTENT_NOISE_TERMS:
        text = text.replace(term, "")
    return text or str(message or "").strip()


def _candidate_topic_item(fraud_type: str, reason: str, confidence: float = 0.7) -> Dict[str, Any]:
    fraud_type = standard_name_for(fraud_type)
    fraud_type_id = fraud_type_id_for(fraud_type)
    return {
        "fraud_type": fraud_type,
        "fraud_type_id": fraud_type_id,
        "reason": reason,
        "confidence": confidence,
    }


def _normalize_candidate_topics(items: Any) -> List[Dict[str, Any]]:
    result: List[Dict[str, Any]] = []
    seen = set()
    raw_items = items if isinstance(items, list) else []
    for item in raw_items:
        if isinstance(item, dict):
            fraud_type = str(item.get("fraud_type") or item.get("standard_name") or item.get("topic") or "").strip()
            reason = str(item.get("reason") or "").strip()
            confidence = item.get("confidence", 0.0)
        else:
            fraud_type = str(item or "").strip()
            reason = ""
            confidence = 0.0
        if not fraud_type:
            continue
        fraud_type = standard_name_for(fraud_type)
        fraud_type_id = fraud_type_id_for(fraud_type)
        if not fraud_type_id or fraud_type in seen:
            continue
        result.append(
            {
                "fraud_type": fraud_type,
                "fraud_type_id": fraud_type_id,
                "reason": reason,
                "confidence": confidence,
            }
        )
        seen.add(fraud_type)
    return result[:8]


def _normalize_knowledge_query_plan(raw: Dict[str, Any], message: str, source: str) -> Dict[str, Any]:
    raw = raw if isinstance(raw, dict) else {}
    query_type = str(raw.get("query_type") or "general_safety").strip()
    if query_type not in {"broad_domain", "specific_fraud_type", "general_safety", "clarify"}:
        query_type = "general_safety"
    answer_scope = str(raw.get("answer_scope") or "").strip()
    if answer_scope not in {"domain_overview", "single_type", "compare", "clarify"}:
        answer_scope = "single_type" if query_type == "specific_fraud_type" else "domain_overview"
    domain = str(raw.get("domain") or UNKNOWN_QUERY_DOMAIN).strip() or UNKNOWN_QUERY_DOMAIN
    clean_query = str(raw.get("clean_query") or _clean_knowledge_query(message) or message).strip()
    user_intent = str(raw.get("user_intent") or classify_education_intent(clean_query or message)).strip()
    if user_intent not in INTENT_LABELS:
        user_intent = classify_education_intent(clean_query or message)
    normalized_topic = str(raw.get("normalized_topic") or "").strip()
    fraud_type_id = str(raw.get("fraud_type_id") or "").strip()
    if normalized_topic:
        normalized_topic = standard_name_for(normalized_topic)
        fraud_type_id = fraud_type_id or fraud_type_id_for(normalized_topic)
    candidate_topics = _normalize_candidate_topics(raw.get("candidate_topics"))
    query_expansions = _dedupe_strings(list(raw.get("query_expansions") or []), limit=10)
    scenario_terms = _dedupe_strings(list(raw.get("scenario_terms") or []), limit=12)
    risk_action_terms = _dedupe_strings(list(raw.get("risk_action_terms") or []), limit=12)
    return {
        "query_type": query_type,
        "answer_scope": answer_scope,
        "domain": domain,
        "clean_query": clean_query,
        "user_intent": user_intent,
        "normalized_topic": normalized_topic,
        "fraud_type_id": fraud_type_id,
        "candidate_topics": candidate_topics,
        "query_expansions": query_expansions,
        "scenario_terms": scenario_terms,
        "risk_action_terms": risk_action_terms,
        "needs_clarification": bool(raw.get("needs_clarification", query_type == "clarify")),
        "reason": str(raw.get("reason") or ""),
        "source": source,
    }


def _local_knowledge_query_plan(message: str, route_decision: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    route_decision = route_decision or {}
    clean_query = _clean_knowledge_query(message)
    compact = re.sub(r"\s+", "", message or "")
    route_topic = str(route_decision.get("normalized_topic") or "").strip()
    route_fraud_type_id = str(route_decision.get("fraud_type_id") or "").strip()

    if route_topic == GENERAL_TRANSFER_TOPIC or any(term in compact for term in EXPLICIT_TRANSFER_TERMS):
        return _normalize_knowledge_query_plan(
            {
                "query_type": "general_safety",
                "answer_scope": "domain_overview",
                "domain": FUND_TRANSFER_DOMAIN,
                "clean_query": clean_query or "转账安全",
                "user_intent": classify_education_intent(message),
                "normalized_topic": GENERAL_TRANSFER_TOPIC,
                "fraud_type_id": route_fraud_type_id or "general_anti_fraud",
                "query_expansions": [
                    "转账前如何识别诈骗",
                    "核验收款账户 防范资金损失",
                    "银行转账诈骗 防范",
                ],
                "scenario_terms": [term for term in EXPLICIT_TRANSFER_TERMS if term in compact],
                "risk_action_terms": ["转账", "汇款", "收款账户核验"],
                "reason": "本地查询理解判断为资金转账安全科普。",
            },
            message,
            KNOWLEDGE_QUERY_PLAN_SOURCE_LOCAL,
        )

    if route_topic and route_fraud_type_id:
        return _normalize_knowledge_query_plan(
            {
                "query_type": "specific_fraud_type",
                "answer_scope": "single_type",
                "domain": UNKNOWN_QUERY_DOMAIN,
                "clean_query": clean_query or route_topic,
                "user_intent": classify_education_intent(message),
                "normalized_topic": route_topic,
                "fraud_type_id": route_fraud_type_id,
                "candidate_topics": [_candidate_topic_item(route_topic, "入口路由已归一到具体诈骗类型。", 0.9)],
                "query_expansions": [f"{route_topic} 如何识别 防范 案例"],
                "reason": "入口路由已提供具体诈骗类型。",
            },
            message,
            KNOWLEDGE_QUERY_PLAN_SOURCE_LOCAL,
        )

    has_cross_border = any(term in compact for term in CROSS_BORDER_DOMAIN_TERMS)
    if has_cross_border:
        has_job_context = any(term in compact for term in CROSS_BORDER_JOB_TERMS)
        candidates = [
            _candidate_topic_item("跨境高薪招工诱骗诈骗", "境外/跨境诈骗常覆盖境外高薪招工、电诈园区诱骗。", 0.72),
            _candidate_topic_item("虚假投资理财诈骗", "境外/跨境诈骗常借投资理财、虚拟币、外汇等包装。", 0.55),
            _candidate_topic_item("情感交友诱导投资诈骗", "跨境交友可能与诱导投资、杀猪盘结合。", 0.5),
            _candidate_topic_item("两卡出租出借与跑分诈骗", "跨境电诈链条常涉及两卡、跑分和洗钱工具人。", 0.48),
        ]
        normalized_topic = "跨境高薪招工诱骗诈骗" if has_job_context else ""
        return _normalize_knowledge_query_plan(
            {
                "query_type": "specific_fraud_type" if has_job_context else "broad_domain",
                "answer_scope": "single_type" if has_job_context else "domain_overview",
                "domain": CROSS_BORDER_DOMAIN,
                "clean_query": clean_query or "境外诈骗",
                "user_intent": classify_education_intent(message),
                "normalized_topic": normalized_topic,
                "fraud_type_id": fraud_type_id_for(normalized_topic) if normalized_topic else "",
                "candidate_topics": candidates,
                "query_expansions": [
                    "跨境电信网络诈骗 常见类型 防范",
                    "境外电诈 园区 招工 诱骗",
                    "跨境高薪招工诈骗",
                    "境外投资理财诈骗 虚拟币 外汇",
                    "跨境交友诱导投资诈骗",
                    "两卡 跑分 洗钱工具人 跨境电诈",
                ],
                "scenario_terms": [term for term in CROSS_BORDER_DOMAIN_TERMS + CROSS_BORDER_JOB_TERMS if term in compact],
                "risk_action_terms": ["高收益", "保密", "私聊", "交证件", "交保证金", "出境", "边境安排"],
                "reason": "用户询问境外/跨境诈骗，应先做领域综述并召回多个相关小类，不强行归一单一类型。",
            },
            message,
            KNOWLEDGE_QUERY_PLAN_SOURCE_LOCAL,
        )

    return _normalize_knowledge_query_plan(
        {
            "query_type": "general_safety",
            "answer_scope": "domain_overview",
            "domain": UNKNOWN_QUERY_DOMAIN,
            "clean_query": clean_query or message,
            "user_intent": classify_education_intent(message),
            "query_expansions": [clean_query or message],
            "reason": "本地查询理解未识别到明确领域，按通用反诈科普处理。",
        },
        message,
        KNOWLEDGE_QUERY_PLAN_SOURCE_LOCAL,
    )


def _llm_knowledge_query_plan(
    message: str,
    route_decision: Dict[str, Any],
    history: Optional[List[Dict[str, Any]]] = None,
) -> Optional[Dict[str, Any]]:
    if get_llm_config_error():
        return None
    taxonomy_catalog = [
        {
            "fraud_type_id": row.get("fraud_type_id", ""),
            "standard_name": row.get("standard_name", ""),
            "aliases": row.get("aliases", [])[:8],
            "parent_category": row.get("parent_category", ""),
        }
        for row in fraud_type_registry()
    ]
    recent_history = [
        {"role": item.get("role", ""), "text": str(item.get("content") or item.get("text") or "")[:180]}
        for item in (history or [])[-4:]
        if isinstance(item, dict)
    ]
    system_prompt = """
你是反诈知识库的检索计划器，只输出 JSON，不回答用户。

任务：理解用户问题，生成可用于本地 RAG 的检索计划。不要把宽泛上位概念强行归成单一诈骗类型。
关键规则：
1. “境外诈骗/跨境诈骗/境外电诈/跨境电诈”是 broad_domain，domain=cross_border_fraud，answer_scope=domain_overview。
2. 只有明确出现境外高薪、招工、客服、出国务工、护照、边境、签证、园区等，才可 normalized_topic=跨境高薪招工诱骗诈骗。
3. query_expansions 要包含适合本地知识库检索的多个中文查询。
4. 如果是银行转账、汇款、收款账户核验，domain=fund_transfer。
"""
    human_prompt = f"""
用户问题：{message}
入口路由：{json.dumps({
    "workflow_mode": route_decision.get("workflow_mode", ""),
    "normalized_topic": route_decision.get("normalized_topic", ""),
    "fraud_type_id": route_decision.get("fraud_type_id", ""),
    "query_rewrite": route_decision.get("query_rewrite", ""),
}, ensure_ascii=False)}
最近历史：{json.dumps(recent_history, ensure_ascii=False)}
可用诈骗类型 taxonomy：{json.dumps(taxonomy_catalog, ensure_ascii=False)}

请返回严格 JSON，字段固定：
{{
  "query_type": "broad_domain|specific_fraud_type|general_safety|clarify",
  "answer_scope": "domain_overview|single_type|compare|clarify",
  "domain": "cross_border_fraud|fund_transfer|housing|investment|job_recruitment|unknown",
  "clean_query": "",
  "user_intent": "definition|prevention|case|law|general|technique|summary|compare",
  "normalized_topic": "",
  "fraud_type_id": "",
  "candidate_topics": [{{"fraud_type": "", "reason": "", "confidence": 0.0}}],
  "query_expansions": [],
  "scenario_terms": [],
  "risk_action_terms": [],
  "needs_clarification": false,
  "reason": ""
}}
"""
    try:
        from app.query_process.agent.nodes.common import extract_json_object, get_message_content

        client = get_llm_client(json_mode=True)
        response = client.invoke([SystemMessage(content=system_prompt.strip()), HumanMessage(content=human_prompt.strip())])
        data = extract_json_object(get_message_content(response))
        if not data:
            return None
        return _normalize_knowledge_query_plan(data, message, KNOWLEDGE_QUERY_PLAN_SOURCE_LLM)
    except Exception as exc:
        logger.warning(f"Knowledge query planner LLM failed: {exc}", exc_info=True)
        return None


def _build_knowledge_query_plan(
    message: str,
    route_decision: Optional[Dict[str, Any]] = None,
    history: Optional[List[Dict[str, Any]]] = None,
    use_llm: bool = True,
) -> Dict[str, Any]:
    route_decision = route_decision or {}
    if use_llm:
        llm_plan = _llm_knowledge_query_plan(message, route_decision, history=history)
        if llm_plan:
            return llm_plan
    return _local_knowledge_query_plan(message, route_decision)


def _topics_from_query_plan(query_plan: Dict[str, Any]) -> List[Dict[str, Any]]:
    if str((query_plan or {}).get("answer_scope") or "") != "single_type":
        return []
    topic = _route_topic(str((query_plan or {}).get("normalized_topic") or ""))
    if topic:
        return [topic]
    topics: List[Dict[str, Any]] = []
    for item in (query_plan or {}).get("candidate_topics") or []:
        topic = _route_topic(str(item.get("fraud_type") or ""))
        if topic:
            topics.append(topic)
            break
    return topics


def classify_education_intent(query: str) -> str:
    text = _normalize_text(query)
    if not text:
        return INTENT_GENERAL
    if any(word in text for word in ["区别", "不同", "对比", "一样吗", "相比", " vs ", "VS"]):
        return INTENT_COMPARE
    if any(word in text for word in ["法律", "法规", "违法", "犯法吗", "处罚", "刑法", "责任", "条款", "两卡犯罪", "报警", "报案", "立案", "举报", "追回", "止付", "取证", "证据"]):
        return INTENT_LAW
    if any(word in text for word in ["案例", "例子", "举例", "真实", "复盘", "讲个故事"]):
        return INTENT_CASE
    if any(word in text for word in ["怎么防", "如何防", "防范", "预防", "避免", "保护", "核验", "怎么识别", "识别方法"]):
        return INTENT_PREVENTION
    if any(word in text for word in ["套路", "手法", "流程", "步骤", "话术", "特征", "信号", "怎么骗", "如何骗", "怎么操作", "如何操作"]):
        return INTENT_TECHNIQUE
    if any(word in text for word in ["总结", "概括", "口诀", "给同学", "给家长", "一段话", "简短"]):
        return INTENT_SUMMARY
    if any(word in text for word in ["什么是", "是什么", "定义", "概念", "介绍", "讲讲", "了解"]):
        return INTENT_DEFINITION
    return INTENT_GENERAL


def match_education_topics(query: str, previous_topic: str | None = None, limit: int = 3) -> List[Dict[str, Any]]:
    text = _normalize_text(query)
    rows = _scam_types()
    scored: List[Tuple[int, Dict[str, Any], List[str]]] = []
    for row in rows:
        name = str(row.get("name") or "")
        aliases = list(row.get("aliases") or [])
        score = 0
        matched: List[str] = []
        if name and name in query:
            score += 20
            matched.append(name)
        base_name = name.replace("诈骗", "")
        name_variants = {
            base_name,
            base_name.replace("理财", ""),
            base_name.replace("服务", ""),
            base_name.replace("返利", ""),
            base_name.replace("与", ""),
        }
        for part in re.split(r"[/、和与]", base_name):
            if len(part) >= 2:
                name_variants.add(part)
        for variant in sorted(name_variants, key=len, reverse=True):
            if variant and len(variant) >= 2 and variant in query:
                score += 12 if len(variant) >= 4 else 6
                matched.append(variant)
                break
        for alias in aliases:
            alias = str(alias)
            if alias and alias.lower() in text:
                score += 9 if len(alias) >= 3 else 5
                matched.append(alias)
        for target in row.get("target_users") or []:
            if str(target) in query:
                score += 1
        if previous_topic and name == previous_topic and _is_followup_query(query):
            score += 8
            matched.append("上一轮主题")
        if score > 0:
            scored.append((score, row, matched))

    scored.sort(key=lambda item: item[0], reverse=True)
    topics = []
    for score, row, matched in scored[:limit]:
        topics.append(
            {
                "fraud_type": row.get("name", ""),
                "score": score,
                "matched_terms": sorted(set(matched)),
                "aliases": row.get("aliases", []),
                "target_users": row.get("target_users", []),
            }
        )
    return topics


def _is_followup_query(query: str) -> bool:
    stripped = (query or "").strip()
    return bool(
        stripped
        and (
            len(stripped) <= 18
            or any(word in stripped for word in ["那", "这个", "这种", "它", "怎么防", "案例", "法律", "总结", "套路"])
        )
    )


def _has_direct_topic(topics: List[Dict[str, Any]]) -> bool:
    for topic in topics:
        terms = [term for term in topic.get("matched_terms") or [] if term and term != "上一轮主题"]
        if terms and int(topic.get("score") or 0) >= 5:
            return True
    return False


def _should_use_history_for_query(query: str, direct_topics: List[Dict[str, Any]]) -> bool:
    """Only carry previous turns for explicit follow-up questions.

    The education module is often used as a topic browser. Treat standalone
    questions as new topics so the model does not keep forcing older examples
    into unrelated answers.
    """
    text = (query or "").strip()
    compact = re.sub(r"\s+", "", text)
    if not compact:
        return False
    if _has_direct_topic(direct_topics):
        return False

    standalone_markers = [
        "什么是",
        "是什么",
        "介绍",
        "科普",
        "讲讲",
        "我最近",
        "我看到",
        "我想咨询",
        "咨询一件事",
        "可以买吗",
        "能买吗",
        "靠谱吗",
        "靠不靠谱",
    ]
    if any(marker in compact for marker in standalone_markers):
        return False

    followup_markers = [
        "那",
        "这个",
        "这种",
        "刚才",
        "上面",
        "前面",
        "它",
        "其",
        "继续",
        "还有",
        "怎么防",
        "如何防",
        "讲个案例",
        "举个例子",
        "法律呢",
        "总结一下",
        "套路呢",
    ]
    return any(marker in compact for marker in followup_markers) or len(compact) <= 8


def _doc_text(doc: Dict[str, Any], include_content: bool = True) -> str:
    fields = [
        doc.get("title", ""),
        doc.get("summary", ""),
        doc.get("fraud_type", ""),
        doc.get("doc_type", ""),
        _text_join(doc.get("keywords") or []),
        _text_join(doc.get("aliases") or []),
    ]
    if include_content:
        fields.append(doc.get("content", ""))
    return "\n".join(str(item) for item in fields)


def _contains_any(text: str, terms: List[str]) -> bool:
    return any(term in text for term in terms)


def _handling_focus_doc_types(query: str) -> List[str]:
    text = _normalize_text(query)
    doc_types: List[str] = []
    if _contains_any(text, HANDLING_REPORT_TERMS):
        doc_types.extend(["report_guide", "evidence_guide", "law_clause"])
    if _contains_any(text, HANDLING_EVIDENCE_TERMS):
        doc_types.extend(["evidence_guide", "report_guide", "law_clause"])
    result: List[str] = []
    for doc_type in doc_types:
        if doc_type not in result:
            result.append(doc_type)
    return result


def _risk_focus_doc_types(query: str) -> List[str]:
    text = _normalize_text(query)
    if _contains_any(text, RISK_REASONING_TERMS):
        return ["risk_rule", "scam_features", "scam_definition"]
    return []


def _preferred_doc_types_for_query(intent: str, query: str) -> List[str]:
    focused = _handling_focus_doc_types(query) + _risk_focus_doc_types(query)
    if _contains_any(_normalize_text(query), ["来源", "出处", "依据", "官方", "引用"]):
        focused = ["official_source"] + focused
    base = INTENT_DOC_TYPES.get(intent, INTENT_DOC_TYPES[INTENT_GENERAL])
    preferred: List[str] = []
    for doc_type in focused + base:
        if doc_type not in preferred:
            preferred.append(doc_type)
    return preferred


def _semantic_doc_type_boost(doc_type: str, query: str) -> int:
    text = _normalize_text(query)
    boost = 0
    if _contains_any(text, HANDLING_REPORT_TERMS):
        if doc_type == "report_guide":
            boost += 45
        elif doc_type == "evidence_guide":
            boost += 18
        elif doc_type == "law_clause":
            boost += 10
    if _contains_any(text, HANDLING_EVIDENCE_TERMS):
        if doc_type == "evidence_guide":
            boost += 45
        elif doc_type == "report_guide":
            boost += 18
        elif doc_type == "law_clause":
            boost += 10
    if _contains_any(text, RISK_REASONING_TERMS):
        if doc_type == "risk_rule":
            boost += 45
        elif doc_type in {"scam_features", "risk_signal"}:
            boost += 16
        elif doc_type == "scam_definition":
            boost += 8
    if _contains_any(text, ["来源", "出处", "依据", "官方", "引用"]) and doc_type == "official_source":
        boost += 45
    return boost


def _score_doc(
    doc: Dict[str, Any],
    query: str,
    intent: str,
    topics: List[Dict[str, Any]],
    terms: List[str],
) -> int:
    text = _doc_text(doc)
    score = 0
    topic_names = [topic["fraud_type"] for topic in topics if topic.get("fraud_type")]
    matched_terms = [term for term in terms if term and term in text]
    doc_type = str(doc.get("doc_type") or doc.get("knowledge_type") or "")
    fraud_type = str(doc.get("fraud_type") or "")
    is_generic_doc = fraud_type in {"通用", "通用法律法规与处置常识"}
    if topic_names and fraud_type and fraud_type not in topic_names and not is_generic_doc and doc_type != "law_clause":
        return 0
    if not topic_names and not matched_terms and not (intent == INTENT_LAW and doc_type == "law_clause"):
        return 0
    if topic_names and fraud_type in topic_names:
        score += 60
    elif topic_names and doc_type == "law_clause":
        if any(topic_name in text for topic_name in topic_names):
            score += 28
        else:
            score -= 18
    preferred = _preferred_doc_types_for_query(intent, query)
    if doc_type in preferred:
        score += 35 - min(preferred.index(doc_type), 6) * 3
    for term in matched_terms:
        score += min(text.count(term), 4) * (6 if len(term) >= 3 else 3)
    if intent == INTENT_LAW and doc_type == "law_clause":
        score += 25
    if intent == INTENT_COMPARE and topic_names and doc.get("fraud_type") in topic_names:
        score += 20
    score += _semantic_doc_type_boost(doc_type, query)
    score += min(int(doc.get("priority") or 0), 100) // 10
    return score


def _score_domain_doc(
    doc: Dict[str, Any],
    query_plan: Dict[str, Any],
    intent: str,
) -> Tuple[int, List[str]]:
    domain = str((query_plan or {}).get("domain") or "")
    if domain != CROSS_BORDER_DOMAIN:
        return 0, []
    text = _doc_text(doc)
    doc_type = str(doc.get("doc_type") or doc.get("knowledge_type") or "")
    fraud_type = str(doc.get("fraud_type") or "")
    domain_terms = _domain_terms_for_query_plan(query_plan)
    matched_terms = [term for term in domain_terms if term and term in text]
    candidate_names = {
        str(item.get("fraud_type") or "")
        for item in (query_plan.get("candidate_topics") or [])
        if str(item.get("fraud_type") or "")
    }
    score = 0
    if matched_terms:
        score += 22 + min(len(matched_terms), 6) * 6
    if fraud_type and fraud_type in candidate_names:
        score += 45
    if doc_type in {"official_source", "law_clause"} and matched_terms:
        score += 20
    elif doc_type in {"scam_definition", "scam_features", "prevention_advice", "typical_case", "risk_rule"} and (matched_terms or fraud_type in candidate_names):
        score += 12
    if intent == INTENT_PREVENTION and doc_type in {"prevention_advice", "risk_rule", "scam_features"}:
        score += 8
    if score <= 0:
        return 0, []
    score += min(int(doc.get("priority") or 0), 100) // 10
    return score, _dedupe_strings(matched_terms, limit=8)


def _format_reference(doc: Dict[str, Any], include_content: bool = False) -> Dict[str, Any]:
    item = {
        "doc_id": doc.get("doc_id") or doc.get("knowledge_id") or "",
        "doc_type": doc.get("doc_type") or doc.get("knowledge_type") or "",
        "fraud_type": doc.get("fraud_type", ""),
        "title": doc.get("title", ""),
        "summary": doc.get("summary", ""),
        "source_dataset": doc.get("source_dataset") or doc.get("source") or "",
        "source_ids": doc.get("source_ids", []),
        "priority": doc.get("priority", 0),
        "retrieval_score": doc.get("_retrieval_score", 0),
        "retrieval_path": doc.get("_retrieval_path", ""),
        "matched_terms": doc.get("_matched_terms", []),
        "expanded_query": doc.get("_expanded_query", ""),
    }
    if include_content:
        item["content"] = doc.get("content", "")
    return item


def _select_diverse_education_docs(
    scored: List[Tuple[int, Dict[str, Any]]],
    *,
    intent: str,
    query: str,
    limit: int,
) -> List[Dict[str, Any]]:
    selected: List[Dict[str, Any]] = []
    seen = set()
    score_by_id = {
        (doc.get("doc_id") or doc.get("knowledge_id") or doc.get("title")): score
        for score, doc in scored
    }

    def append_doc(doc: Dict[str, Any]) -> None:
        if len(selected) >= limit:
            return
        doc_id = doc.get("doc_id") or doc.get("knowledge_id") or doc.get("title")
        if doc_id in seen:
            return
        seen.add(doc_id)
        item = dict(doc)
        item["_retrieval_score"] = int(score_by_id.get(doc_id, 0) or 0)
        selected.append(item)

    desired_types = _handling_focus_doc_types(query) + _risk_focus_doc_types(query)
    if intent == INTENT_LAW and not desired_types:
        desired_types = ["law_clause", "report_guide", "evidence_guide"]

    for doc_type in desired_types:
        for _, doc in scored:
            current_type = str(doc.get("doc_type") or doc.get("knowledge_type") or "")
            if current_type == doc_type:
                append_doc(doc)
                break

    for _, doc in scored:
        append_doc(doc)
        if len(selected) >= limit:
            break

    return selected


def retrieve_education_context(
    query: str,
    *,
    intent: str | None = None,
    topics: Optional[List[Dict[str, Any]]] = None,
    limit: int = 8,
    include_content: bool = True,
    query_plan: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    limit = max(1, min(int(limit or 8), 20))
    intent = intent or classify_education_intent(query)
    topics = topics or match_education_topics(query, previous_topic=None, limit=4 if intent == INTENT_COMPARE else 3)
    query_plan = query_plan or {}
    docs, source = _education_docs()
    answer_scope = str(query_plan.get("answer_scope") or "")
    base_topics = topics if answer_scope != "domain_overview" else []

    scored_by_id: Dict[str, Tuple[int, Dict[str, Any]]] = {}
    all_terms: List[str] = []
    query_variants: List[Tuple[str, str]] = []

    def add_query_variant(path: str, value: Any) -> None:
        text = str(value or "").strip()
        if not text:
            return
        pair = (path, text)
        if pair not in query_variants:
            query_variants.append(pair)

    add_query_variant("original_query", query)
    add_query_variant("clean_query", query_plan.get("clean_query"))
    for expansion in query_plan.get("query_expansions") or []:
        add_query_variant("llm_expansion", expansion)

    def doc_key(doc: Dict[str, Any]) -> str:
        return str(doc.get("doc_id") or doc.get("knowledge_id") or doc.get("title") or id(doc))

    def add_scored_doc(
        score: int,
        doc: Dict[str, Any],
        *,
        retrieval_path: str,
        matched_terms: List[str],
        expanded_query: str,
    ) -> None:
        if score > 0:
            key = doc_key(doc)
            previous = scored_by_id.get(key)
            merged_terms = _dedupe_strings(
                list((previous[1].get("_matched_terms") if previous else []) or []) + matched_terms,
                limit=12,
            )
            retrieval_paths = _dedupe_strings(
                list(str((previous[1].get("_retrieval_path") if previous else "") or "").split("+"))
                + [retrieval_path],
                limit=8,
            )
            if previous and previous[0] >= score:
                previous[1]["_matched_terms"] = merged_terms
                previous[1]["_retrieval_path"] = "+".join(retrieval_paths)
                return
            item = dict(doc)
            item["_matched_terms"] = merged_terms
            item["_retrieval_path"] = "+".join(retrieval_paths)
            item["_expanded_query"] = expanded_query
            scored_by_id[key] = (score, item)

    for retrieval_path, variant_query in query_variants:
        terms = _query_terms(variant_query)
        all_terms.extend(terms)
        for doc in docs:
            score = _score_doc(doc, variant_query, intent, base_topics, terms)
            if score > 0:
                text = _doc_text(doc)
                matched_terms = [term for term in terms if term and term in text]
                add_scored_doc(
                    score,
                    doc,
                    retrieval_path=retrieval_path,
                    matched_terms=matched_terms,
                    expanded_query=variant_query,
                )

    for candidate in query_plan.get("candidate_topics") or []:
        fraud_type = str(candidate.get("fraud_type") or "").strip()
        if not fraud_type:
            continue
        candidate_query = " ".join(
            _dedupe_strings(
                [
                    fraud_type,
                    candidate.get("reason", ""),
                    query_plan.get("clean_query", ""),
                ],
                limit=4,
            )
        )
        candidate_terms = _query_terms(candidate_query)
        all_terms.extend(candidate_terms)
        candidate_topics = [{"fraud_type": fraud_type}]
        for doc in docs:
            score = _score_doc(doc, candidate_query, intent, candidate_topics, candidate_terms)
            if score > 0:
                text = _doc_text(doc)
                matched_terms = [term for term in candidate_terms if term and term in text]
                add_scored_doc(
                    score,
                    doc,
                    retrieval_path="candidate_topic",
                    matched_terms=matched_terms or [fraud_type],
                    expanded_query=candidate_query,
                )

    domain_terms = _domain_terms_for_query_plan(query_plan)
    all_terms.extend(domain_terms)
    if domain_terms:
        for doc in docs:
            score, matched_terms = _score_domain_doc(doc, query_plan, intent)
            add_scored_doc(
                score,
                doc,
                retrieval_path="domain_recall",
                matched_terms=matched_terms,
                expanded_query=str(query_plan.get("domain") or ""),
            )

    scored: List[Tuple[int, Dict[str, Any]]] = list(scored_by_id.values())
    if not scored and topics:
        names = {topic["fraud_type"] for topic in topics if topic.get("fraud_type")}
        for doc in docs:
            if doc.get("fraud_type") in names:
                score = 10 + int(doc.get("priority") or 0) // 10
                item = dict(doc)
                item["_retrieval_path"] = "topic_fallback"
                item["_matched_terms"] = sorted(names)
                item["_expanded_query"] = query
                scored.append((score, item))

    terms = _dedupe_strings(all_terms or _query_terms(query), limit=40)
    if not scored and terms:
        for doc in docs:
            text = _doc_text(doc)
            matched_terms = [term for term in terms if term and term in text]
            if matched_terms:
                item = dict(doc)
                item["_retrieval_path"] = "term_fallback"
                item["_matched_terms"] = _dedupe_strings(matched_terms, limit=8)
                item["_expanded_query"] = query
                scored.append((5 + int(doc.get("priority") or 0) // 10, item))

    scored.sort(key=lambda pair: pair[0], reverse=True)
    deduped = _select_diverse_education_docs(scored, intent=intent, query=query, limit=limit)

    return {
        "items": [_format_reference(doc, include_content=include_content) for doc in deduped],
        "source": source,
        "intent": intent,
        "topics": topics,
        "top_score": int(scored[0][0] if scored else 0),
        "scored_count": len(scored),
        "query_terms": terms,
        "query_variants": [{"path": path, "query": value} for path, value in query_variants],
    }


def _route_topic(topic: str) -> Optional[Dict[str, Any]]:
    topic = str(topic or "").strip()
    if not topic:
        return None
    if topic == GENERAL_TRANSFER_TOPIC:
        return {
            "fraud_type": topic,
            "score": 70,
            "matched_terms": ["LLM/本地语义归一"],
            "aliases": ["银行转账骗局", "转账骗局", "汇款骗局"],
            "target_users": ["泛个人用户"],
            "topic_kind": "general",
        }
    standard_name = standard_name_for(topic)
    fraud_type_id = fraud_type_id_for(topic)
    if fraud_type_id:
        return {
            "fraud_type": standard_name,
            "score": 80,
            "matched_terms": ["LLM/本地语义归一"],
            "aliases": [],
            "target_users": [],
            "fraud_type_id": fraud_type_id,
            "topic_kind": "fraud_type",
        }
    return None


def _topics_from_route(route_decision: Dict[str, Any]) -> List[Dict[str, Any]]:
    candidates = [
        route_decision.get("normalized_topic"),
        (route_decision.get("routing_decision") or {}).get("prefill_slots", {}).get("normalized_topic")
        if isinstance((route_decision.get("routing_decision") or {}).get("prefill_slots"), dict)
        else "",
        (route_decision.get("routing_decision") or {}).get("prefill_slots", {}).get("education_topic")
        if isinstance((route_decision.get("routing_decision") or {}).get("prefill_slots"), dict)
        else "",
    ]
    topics: List[Dict[str, Any]] = []
    seen = set()
    for candidate in candidates:
        topic = _route_topic(str(candidate or ""))
        if not topic:
            continue
        key = topic.get("fraud_type")
        if key in seen:
            continue
        topics.append(topic)
        seen.add(key)
    return topics


def _merge_topics(*groups: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    merged: List[Dict[str, Any]] = []
    seen = set()
    for group in groups:
        for topic in group or []:
            name = str(topic.get("fraud_type") or "").strip()
            if not name or name in seen:
                continue
            merged.append(topic)
            seen.add(name)
    return merged


def _retrieval_quality(
    *,
    query: str,
    topics: List[Dict[str, Any]],
    retrieval: Dict[str, Any],
    references: List[Dict[str, Any]],
) -> Dict[str, Any]:
    query_plan = retrieval.get("query_understanding") if isinstance(retrieval.get("query_understanding"), dict) else {}
    top_score = max([int(item.get("retrieval_score") or 0) for item in references] or [0])
    topic_names = {str(topic.get("fraud_type") or "") for topic in topics if topic.get("fraud_type")}
    concrete_topic_names = {name for name in topic_names if name != GENERAL_TRANSFER_TOPIC}
    reference_types = {
        str(item.get("fraud_type") or "")
        for item in references
        if str(item.get("fraud_type") or "").strip()
    }
    mismatch_types = sorted(
        item
        for item in reference_types
        if concrete_topic_names and item not in concrete_topic_names and item not in {"通用", "通用法律法规与处置常识"}
    )
    has_topic_match = bool(concrete_topic_names and any(item in reference_types for item in concrete_topic_names))
    weak_only = bool(not references or top_score < 35 or (not has_topic_match and concrete_topic_names))
    general_topic = bool(GENERAL_TRANSFER_TOPIC in topic_names)
    retrieval_paths = sorted(
        {
            path
            for item in references
            for path in str(item.get("retrieval_path") or "").split("+")
            if path
        }
    )
    return {
        "query": query,
        "top_score": top_score,
        "scored_count": int(retrieval.get("scored_count") or 0),
        "item_count": len(references),
        "topic_names": sorted(topic_names),
        "has_topic_match": has_topic_match,
        "mismatch_types": mismatch_types,
        "weak_only": weak_only,
        "general_topic": general_topic,
        "source": retrieval.get("source", ""),
        "query_type": query_plan.get("query_type", ""),
        "domain": query_plan.get("domain", ""),
        "expanded_query_count": len(query_plan.get("query_expansions") or []),
        "retrieval_paths": retrieval_paths,
        "coverage_reason": (
            f"通过 {', '.join(retrieval_paths)} 召回到本地知识材料。"
            if references and retrieval_paths
            else "召回到本地知识材料。"
            if references
            else "本地知识暂未召回可用材料。"
        ),
    }


def _llm_decide_knowledge_strategy(
    message: str,
    route_decision: Dict[str, Any],
    retrieval_quality: Dict[str, Any],
    references: List[Dict[str, Any]],
    use_llm: bool,
) -> Optional[Dict[str, Any]]:
    if not use_llm or get_llm_config_error():
        return None
    ref_brief = [
        {
            "title": item.get("title", ""),
            "fraud_type": item.get("fraud_type", ""),
            "doc_type": item.get("doc_type", ""),
            "summary": item.get("summary", ""),
            "retrieval_score": item.get("retrieval_score", 0),
        }
        for item in references[:6]
    ]
    system_prompt = """
你是反诈知识问答的 RAG 质量裁决器，只输出 JSON，不回答用户。

判断本地知识库材料是否足以回答本轮问题。不要因为有低分材料就强行使用；也不要因为用户说法口语化就放弃明显相关的本地材料。
"""
    human_prompt = f"""
【用户问题】
{message}

【入口语义路由】
{json.dumps({
    "normalized_topic": route_decision.get("normalized_topic", ""),
    "fraud_type_id": route_decision.get("fraud_type_id", ""),
    "query_rewrite": route_decision.get("query_rewrite", ""),
    "reason": route_decision.get("reason", ""),
}, ensure_ascii=False)}

【本地检索质量】
{json.dumps(retrieval_quality, ensure_ascii=False)}

【本地候选材料】
{json.dumps(ref_brief, ensure_ascii=False)}

请返回严格 JSON：
{{
  "strategy": "use_local_rag|use_web_fallback|use_general_template|clarify",
  "confidence": 0.0,
  "reason": "简短说明",
  "clarification_question": ""
}}
"""
    try:
        client = get_llm_client(json_mode=True)
        response = client.invoke([SystemMessage(content=system_prompt.strip()), HumanMessage(content=human_prompt.strip())])
        from app.query_process.agent.nodes.common import extract_json_object, get_message_content

        data = extract_json_object(get_message_content(response))
        strategy = str((data or {}).get("strategy") or "").strip()
        if strategy not in {"use_local_rag", "use_web_fallback", "use_general_template", "clarify"}:
            return None
        return {
            "strategy": strategy,
            "confidence": data.get("confidence", 0),
            "reason": str(data.get("reason") or ""),
            "clarification_question": str(data.get("clarification_question") or ""),
            "source": "llm_rag_quality_judge",
        }
    except Exception as exc:
        logger.warning(f"RAG quality LLM judge failed: {exc}", exc_info=True)
        return None


def _heuristic_knowledge_strategy(
    route_decision: Dict[str, Any],
    retrieval_quality: Dict[str, Any],
) -> Dict[str, Any]:
    if retrieval_quality.get("general_topic"):
        return {
            "strategy": "use_web_fallback",
            "confidence": 0.72,
            "reason": "通用资金安全主题不强行套单一诈骗类型，优先使用可信 Web 或通用模板。",
            "source": "heuristic_rag_quality",
        }
    if retrieval_quality.get("item_count", 0) <= 0:
        return {
            "strategy": "use_web_fallback",
            "confidence": 0.7,
            "reason": "本地知识库没有可用材料。",
            "source": "heuristic_rag_quality",
        }
    if retrieval_quality.get("weak_only") or retrieval_quality.get("mismatch_types"):
        return {
            "strategy": "use_web_fallback",
            "confidence": 0.68,
            "reason": "本地材料弱相关或存在主题错配。",
            "source": "heuristic_rag_quality",
        }
    return {
        "strategy": "use_local_rag",
        "confidence": 0.8,
        "reason": "本地知识库主题命中和检索分数足够。",
        "source": "heuristic_rag_quality",
    }


def _decide_knowledge_strategy(
    message: str,
    route_decision: Dict[str, Any],
    retrieval_quality: Dict[str, Any],
    references: List[Dict[str, Any]],
    use_llm: bool,
) -> Dict[str, Any]:
    return _llm_decide_knowledge_strategy(message, route_decision, retrieval_quality, references, use_llm) or _heuristic_knowledge_strategy(
        route_decision,
        retrieval_quality,
    )


def _build_cross_border_template_answer() -> str:
    return (
        "可以，我先按“境外/跨境诈骗”给你做一个总览。\n"
        "这不是单一骗局名称，而是一组常见场景：境外高薪招工或电诈园区诱骗、跨境投资理财和虚拟币骗局、跨境交友诱导投资、两卡出租出借与跑分洗钱工具人。\n"
        "共同风险信号是：承诺高收益或高薪、要求保密私聊、绕开官方渠道、先交保证金/路费/解冻费、索要身份证护照银行卡，或安排出境、边境集合、提交证件。\n"
        "防范时先抓一句话：凡是让你脱离正规渠道、交钱交证件、保密行动或去边境/境外集合的，都先停止联系，保存广告、聊天、账号和转账证据，通过公安、人社、学校或官方平台核验。"
    )


def _build_general_template_answer(
    message: str,
    topic: str = "",
    query_plan: Optional[Dict[str, Any]] = None,
) -> str:
    query_plan = query_plan or {}
    domain = str(query_plan.get("domain") or "")
    if domain == CROSS_BORDER_DOMAIN:
        return _build_cross_border_template_answer()
    if topic == GENERAL_TRANSFER_TOPIC or any(word in message for word in EXPLICIT_TRANSFER_TERMS):
        return (
            "可以，我先按“转账前防骗”给你讲。\n"
            "真正要看的不是它叫什么骗局，而是有没有这些危险动作：催你马上转账、让你转到陌生个人账户、发来所谓已转账截图让你垫付、要求验证码或屏幕共享、让你绕开官方平台私下付款。\n"
            "转账前先做三件事：第一，确认收款账户是否和真实交易主体一致；第二，通过官方 App、客服电话或线下渠道核实，不点陌生链接；第三，只要对方催促、保密、先交钱解冻或补资料，就先停。\n"
            "如果已经转了钱，尽快联系银行或支付平台申请止付，保存聊天记录、收款账号、转账凭证和链接，再报警或通过官方渠道举报。"
        )
    if not topic:
        return (
            "可以，我先按通用反诈识别给你讲。\n"
            "先看对方是不是在制造紧迫感、绕开官方平台、要求提前付款、索要验证码/银行卡/身份证，或让你下载陌生 App、共享屏幕。\n"
            "如果只是了解知识，可以先记住一句话：身份可以包装，流程可以伪造，但只要开始要钱、要码、要权限，就先停下来核验官方渠道。"
        )
    return (
        f"可以，我先按“{topic}”给你做通用科普。\n"
        "识别这类风险，先看对方是否在制造紧迫感、绕开官方平台、要求提前付款、索要验证码/银行卡/身份证，或让你下载陌生 App、共享屏幕。\n"
        "如果只是了解知识，可以先记住一句话：身份可以包装，流程可以伪造，但只要开始要钱、要码、要权限，就先停下来核验官方渠道。"
    )


def _build_web_fallback_answer(
    message: str,
    topic: str,
    web_result: Dict[str, Any],
    use_llm: bool,
    query_plan: Optional[Dict[str, Any]] = None,
) -> Tuple[str, str]:
    items = web_result.get("items") or []
    if not items:
        return _build_general_template_answer(message, topic, query_plan=query_plan), "general_template_after_web_unavailable"
    if use_llm and not get_llm_config_error():
        try:
            source_lines = [
                {
                    "title": item.get("title", ""),
                    "url": item.get("url", ""),
                    "content": item.get("content", ""),
                }
                for item in items[:5]
            ]
            prompt = f"""
你是智能反诈助手。请基于可信 Web 检索结果回答用户的反诈科普问题。

要求：
- 只使用给定来源里的信息做支撑，不编造来源。
- 如果来源信息不足，明确用通用反诈原则补充。
- 口吻自然、专业、克制。

用户问题：{message}
归一主题：{topic or "未明确"}
检索计划：{json.dumps(query_plan or {}, ensure_ascii=False)}
可信 Web 来源：
{json.dumps(source_lines, ensure_ascii=False)}
"""
            client = get_llm_client()
            result = client.invoke(prompt)
            answer = str(getattr(result, "content", result) or "").strip()
            if answer and _knowledge_answer_satisfies_contract(answer, topic, items, message):
                return answer, "llm_web_fallback"
            if answer:
                logger.warning("Web fallback answer failed the concrete-topic knowledge contract")
        except Exception as exc:
            logger.warning(f"Web fallback LLM answer failed: {exc}", exc_info=True)

    lines = [_build_general_template_answer(message, topic, query_plan=query_plan), "我还能参考到这些可信来源摘要："]
    for index, item in enumerate(items[:3], start=1):
        title = item.get("title") or item.get("url") or f"来源{index}"
        content = str(item.get("content") or "").strip()
        lines.append(f"{index}. {title}：{content[:120] or '该来源与问题相关，可进一步核验。'}")
    return "\n".join(lines), "template_web_fallback"


def _memory_for_session(session_id: str) -> Dict[str, Any]:
    if session_id not in _SESSION_MEMORY:
        _SESSION_MEMORY[session_id] = {"history": []}
    return _SESSION_MEMORY[session_id]


def _build_prompt(
    message: str,
    intent: str,
    topics: List[Dict[str, Any]],
    references: List[Dict[str, Any]],
    memory: Dict[str, Any],
) -> str:
    topic_text = _text_join([topic.get("fraud_type") for topic in topics if topic.get("fraud_type")]) or "未明确"
    history_lines = []
    for turn in memory.get("prompt_history", memory.get("history", [])[-4:]):
        role = "用户" if turn.get("role") == "user" else "助手"
        text = str(turn.get("content") or turn.get("text") or "")
        history_lines.append(f"{role}：{text[:160]}")

    ref_lines = []
    for index, ref in enumerate(references[:8], start=1):
        ref_lines.append(
            "\n".join(
                [
                    f"[材料{index}] {ref.get('title')}",
                    f"诈骗类型：{ref.get('fraud_type')}",
                    f"材料类型：{ref.get('doc_type')}",
                    f"摘要：{ref.get('summary')}",
                    f"内容：{str(ref.get('content') or '')[:1200]}",
                ]
            )
        )

    return f"""你是“智能反诈助手”的科普回答生成器。当前回合已经由统一意图识别模块判定为知识问答模式。

职责边界：
- 聚焦反诈知识普及、骗局套路讲解、案例复盘、防范建议、法律法规常识、报案取证和风险识别方法。
- 不要声称“我只是科普模块”“不能处理现场止损”“不能追款”等，因为智能反诈助手整体同时支持科普与实时劝阻。
- 如果当前问题仍明显带有现场风险、已付款、验证码、共享屏幕、下载 App、追款止损等求助语义，先给出“停止继续付款并联系官方渠道/警方”的通用安全提醒，再用知识材料解释风险；不要把自己描述成能力受限的独立模块。

回答要求：
- 优先使用检索到的自建反诈知识库材料增强回答。材料可能来自结构化诈骗画像/特征、规则化风险判断、半结构化案例/防范建议/报案指南/证据指南/法律处置常识。
- 需要解释“为什么像诈骗”时，结合风险规则、关键事实、损失信号和命中特征进行推理；需要回答“怎么办/怎么报案/怎么取证”时，优先使用报案指南、证据指南和法律处置常识。
- 法律法规内容只能做通俗科普，不编造具体条文号。
- 用学生和个人用户听得懂的话回答，结构清楚，避免恐吓。
- 如果当前输入或上一轮上下文包含【内部情绪提示】，该提示只用于调整表达方式；不要在回答中提到“语音识别”“情绪识别”或提示内容，也不要把它当成用户事实。
- 语气要更自然、有安抚感：焦虑或惊慌时，先短句稳住并强调“先别继续操作”；愤怒时，先承接不满，再转向证据、止付和举报；困惑时，先解释判断依据，再只问一个关键问题。
- 只有当“上一轮上下文”不是“无”，且用户明显在追问“那怎么防/讲个案例/法律呢/刚才那个”时，才延续上一轮主题。
- 如果用户提出了新的骗局、行业、讲座、培训、租房、购物、街头交易等独立问题，不要引用或类比上一轮旧话题。
- 不要在每次回答末尾机械引导到其他模块。

当前意图：{INTENT_LABELS.get(intent, intent)}
当前主题：{topic_text}
上一轮上下文：
{chr(10).join(history_lines) if history_lines else "无"}

检索材料：
{chr(10).join(ref_lines) if ref_lines else "无匹配材料"}

用户问题：{message}

    请直接给出中文回答。"""


KNOWLEDGE_EVIDENCE_DEFAULTS = {
    "校园二手/票务交易诈骗": [
        "陌生票源或低价票把人引到微信、私聊等平台外沟通",
        "以先付定金、订金或全款锁票为由绕开平台担保",
        "付款后出现改签、补款、无法出票或卖家失联",
    ],
    "屏幕共享/远程控制诈骗": [
        "对方以退款、认证或办案为由要求安装会议软件",
        "要求开启屏幕共享，让对方看到银行、支付页面或验证码",
        "把远程指导包装成客服协助，催促你不要挂断或核实",
    ],
    "两卡出租出借与跑分诈骗": [
        "以兼职、收卡或高额租金为名要求实名办卡、借卡或交出收款码",
        "让你代收代付、刷流水、走账或取现并承诺按笔返佣",
        "交易脱离正规平台，资金来源和用途无法由本人独立核实",
    ],
    "AI换脸冒充熟人诈骗": [
        "视频、语音或头像看似亲友，但身份信息无法通过原号码二次核验",
        "利用亲友关系制造手术费、借钱或紧急代付理由",
        "催促保密并要求转入非本人账户或第三方收款账户",
    ],
    "征信修复/注销账户诈骗": [
        "自称金融平台客服或征信处理专员，制造征信异常、账户未注销恐慌",
        "以修复、清零、注销或认证对接为由要求转账、贷款或刷流水",
        "要求下载陌生 App、提供验证码/身份证或把贷款额度转到指定账户",
    ],
    "刷单返利诈骗": [
        "先用点赞、做任务或小额返利建立信任",
        "再以组合任务、数据异常或补单为由要求继续垫付",
        "提现前不断追加充值、解冻费或手续费，拒绝让你停止",
    ],
}


def _knowledge_answer_satisfies_contract(
    answer: str,
    topic: str,
    references: List[Dict[str, Any]],
    message: str = "",
) -> bool:
    """Keep concrete-topic education answers from collapsing into generic advice."""
    topic = str(topic or "").strip()
    if not topic or not fraud_type_id_for(topic):
        return bool(str(answer or "").strip())
    answer = str(answer or "").strip()
    canonical = standard_name_for(topic)
    aliases = {topic, canonical}
    row = next((item for item in fraud_type_registry() if item.get("fraud_type_id") == fraud_type_id_for(topic)), {})
    aliases.update(str(item) for item in row.get("aliases") or [] if item)
    has_type = any(alias and alias in answer for alias in aliases)
    numbered_points = re.findall(r"(?m)^\s*(?:\d+[.、)]|[一二三四五六七八九十]+[、.])\s*\S+", answer)
    has_three_points = len(numbered_points) >= 3
    has_explanation = any(token in answer for token in ["因为", "说明", "体现", "危险在", "原因", "关键在", "为什么"])
    has_safety_principle = any(token in answer for token in ["官方", "核验", "先停", "不要", "不转账", "保留证据"])
    return bool(has_type and has_three_points and has_explanation and has_safety_principle)


def _build_local_knowledge_answer(
    message: str,
    intent: str,
    topics: List[Dict[str, Any]],
    references: List[Dict[str, Any]],
) -> str:
    topic = _text_join([topic.get("fraud_type") for topic in topics if topic.get("fraud_type")])
    if not topic and references:
        topic = str(references[0].get("fraud_type") or "").strip()
    topic = topic or "这类风险"
    canonical_topic = standard_name_for(topic) if fraud_type_id_for(topic) else topic

    lines = [f"判断类型：{canonical_topic}。这类风险需要重点留意。"]
    summaries: List[str] = []
    for ref in references[:4]:
        summary = str(ref.get("summary") or ref.get("content") or "").strip()
        if summary:
            summaries.append(summary[:120])
    defaults = list(KNOWLEDGE_EVIDENCE_DEFAULTS.get(canonical_topic, []))
    if not defaults:
        defaults = [
            "对方是否制造紧迫感、绕开官方渠道或要求私下沟通",
            "对方是否要求提前付款、提供验证码/银行卡/身份证或下载陌生 App",
            "付款、信息提交或操作后是否出现继续交费、提现受阻或失联",
        ]
    evidence_points = []
    for item in [*summaries, *defaults]:
        item = str(item or "").strip()
        if item and item not in evidence_points:
            evidence_points.append(item)
        if len(evidence_points) >= 3:
            break
    lines.append("与当前主题对应的三个信号：")
    lines.extend([f"{index}. {item}" for index, item in enumerate(evidence_points[:3], start=1)])
    lines.append("为什么这样判断：这些行为把交易或账户安全交给无法独立核验的对象，风险不在于对方怎么自称，而在于是否绕开正规流程并推动高风险动作。")
    lines.append("安全原则：先停止付款和信息提交，只通过官方 App、官网客服电话或线下机构核验，并保留聊天、链接和转账证据。")

    if intent in {INTENT_LAW, INTENT_PREVENTION} or any(word in message for word in ["报警", "举报", "追回", "转账", "验证码", "屏幕共享"]):
        lines.append("如果已经发生转账或泄露信息，请马上联系银行止付，保留聊天记录、转账凭证、链接和账号信息，再通过官方渠道报警或举报。")
    else:
        lines.append("如果您愿意，可以把对方的话术、链接或要求发出来，我可以继续帮您拆解风险点。")
    return "\n".join(lines)


def _generate_answer(
    message: str,
    intent: str,
    topics: List[Dict[str, Any]],
    references: List[Dict[str, Any]],
    memory: Dict[str, Any],
    use_llm: bool,
) -> Tuple[str, str]:
    config_error = get_llm_config_error() if use_llm else "LLM generation is disabled"
    concrete_topic = next(
        (
            str(item.get("fraud_type") or "").strip()
            for item in topics
            if fraud_type_id_for(item.get("fraud_type"))
        ),
        str(references[0].get("fraud_type") or "").strip() if references and fraud_type_id_for(references[0].get("fraud_type")) else "",
    )
    if config_error:
        logger.warning(f"Use local knowledge answer: {config_error}")
        return _build_local_knowledge_answer(message, intent, topics, references), "local_template"

    prompt = _build_prompt(message, intent, topics, references, memory)
    try:
        client = get_llm_client()
        result = client.invoke(prompt)
        answer = getattr(result, "content", result)
        answer = str(answer or "").strip()
        if not answer:
            raise ValueError("教育 RAG LLM 生成了空回答")
        if concrete_topic and not _knowledge_answer_satisfies_contract(answer, concrete_topic, references, message):
            logger.warning("LLM knowledge answer failed the concrete-topic contract, use typed local answer")
            return _build_local_knowledge_answer(message, intent, topics, references), "local_template_after_quality_gate"
        return answer, "llm"
    except Exception as exc:
        logger.warning(f"LLM knowledge answer failed, use local answer: {exc}", exc_info=True)
        return _build_local_knowledge_answer(message, intent, topics, references), "local_template_after_llm_error"


def _stream_chunk_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        chunks: List[str] = []
        for item in value:
            if isinstance(item, str):
                chunks.append(item)
            elif isinstance(item, dict):
                text = item.get("text")
                if text:
                    chunks.append(str(text))
            else:
                text = getattr(item, "text", "")
                if text:
                    chunks.append(str(text))
        return "".join(chunks)
    return str(value or "")


def _push_text_deltas(session_id: str, text: str, chunk_size: int = 24) -> None:
    if not session_id or not text:
        return
    for start in range(0, len(text), chunk_size):
        push_to_session(session_id, SSEEvent.DELTA, {"delta": text[start:start + chunk_size]})


def _is_quiz_request(message: str) -> bool:
    compact = re.sub(r"\s+", "", message or "")
    if not compact:
        return False
    return bool(
        re.search(r"(给我|帮我|来|出|生成|做|考考|测试).{0,8}(反诈)?(测试题|测验题|练习题|选择题|问答题|题目|题)", compact)
        or re.search(r"(反诈)?(测试题|测验题|答题|闯关)", compact)
    )


def _quiz_disabled_answer() -> str:
    return (
        "智能反诈助手不提供反诈测试题或闯关出题功能。"
        "你可以直接问某类骗局的定义、套路、案例、防范建议和法律常识；"
        "如果你正在遇到转账、验证码、共享屏幕、下载陌生 App 等情况，也可以直接描述，我会优先做风险研判和劝阻建议。"
    )


def _build_quiz_disabled_response(session_id: str) -> Dict[str, Any]:
    return {
        "message": "反诈测试题功能未启用",
        "answer": _quiz_disabled_answer(),
        "session_id": session_id,
        "intent": INTENT_GENERAL,
        "intent_label": INTENT_LABELS[INTENT_GENERAL],
        "topics": [],
        "references": [],
        "source": "policy",
        "generation": "template",
        "module": "knowledge_assistant",
        "scope": "anti_fraud_education_rag",
    }


def _history_item_text(item: Dict[str, Any]) -> str:
    return str(item.get("text") or item.get("content") or "").strip()


def _normalize_chat_history(history: Optional[List[Dict[str, Any]]], limit: int = _MAX_MEMORY_TURNS) -> List[Dict[str, Any]]:
    normalized: List[Dict[str, Any]] = []
    for item in (history or [])[-limit:]:
        if not isinstance(item, dict):
            continue
        role = str(item.get("role") or "").strip()
        if role == "bot":
            role = "assistant"
        if role not in {"user", "assistant"}:
            continue
        text = _history_item_text(item)
        if not text:
            continue
        normalized.append({"role": role, "content": text, "text": text})
    return normalized


def _recent_user_history_text(history: Optional[List[Dict[str, Any]]], limit: int = 6) -> str:
    normalized = _normalize_chat_history(history, limit=limit)
    return "\n".join(item["text"] for item in normalized if item.get("role") == "user")


def _has_recent_unresolved_risk_context(history: Optional[List[Dict[str, Any]]], memory_context: Dict[str, Any] | None = None) -> bool:
    memory_context = memory_context or {}
    history_text = _recent_user_history_text(history, limit=8)
    recent_memory_text = "\n".join(
        str(item.get("text_redacted") or item.get("text") or "")
        for item in (memory_context.get("recent_user_messages") or [])[-8:]
        if isinstance(item, dict)
    )
    case_state = memory_context.get("case_state") if isinstance(memory_context.get("case_state"), dict) else {}
    case_text = json.dumps(
        {
            "fraud_type": case_state.get("fraud_type", ""),
            "fraud_stage": case_state.get("fraud_stage", ""),
            "risk_level": case_state.get("risk_level", ""),
            "slots": case_state.get("slots", {}),
            "semantic_risk_analysis": case_state.get("semantic_risk_analysis", {}),
            "risk_resolved": case_state.get("risk_resolved", False),
            "case_status": case_state.get("case_status", ""),
        },
        ensure_ascii=False,
        default=str,
    )
    combined = re.sub(r"\s+", "", f"{history_text}\n{recent_memory_text}\n{case_text}")
    if not combined:
        return False
    closed_markers = ["risk_resolvedtrue", "case_statusprevented", "case_statusclosed", "case_statusstop_loss_done"]
    if any(marker in combined for marker in closed_markers):
        return False
    return any(keyword in combined for keyword in RISK_CONTEXT_KEYWORDS)


def _is_risk_followup_turn(message: str) -> bool:
    compact = re.sub(r"\s+", "", message or "")
    if not compact:
        return False
    if RISK_FOLLOWUP_SHORT_RE.match(compact):
        return True
    return any(word in compact for word in ["怎么办", "提现", "继续", "还能", "对方", "平台", "催我", "让我", "交钱", "转钱", "补单"])


def _contextual_risk_followup_route(
    message: str,
    history: Optional[List[Dict[str, Any]]],
    memory_context: Dict[str, Any] | None = None,
) -> Optional[Dict[str, Any]]:
    compact_message = re.sub(r"\s+", "", message or "")
    if any(marker in compact_message for marker in CASE_STUDY_MARKERS) and not any(
        marker in compact_message for marker in EXPLICIT_PERSONAL_RISK_MARKERS
    ):
        return None
    if not _is_risk_followup_turn(message):
        return None
    if not _has_recent_unresolved_risk_context(history, memory_context):
        return None
    history_text = _recent_user_history_text(history, limit=6)
    compact_history = re.sub(r"\s+", "", history_text)
    fraud_hint = "刷单返利诈骗" if any(word in compact_history for word in ["刷单", "做任务", "返利", "返佣", "补单"]) else ""
    risk_features = []
    if any(word in compact_history for word in ["垫了", "垫付", "转账了", "已经转账", "充值了", "付了"]):
        risk_features.append("已发生转账")
    if any(word in compact_history for word in ["提现不了", "不能提现", "无法提现", "提现失败"]):
        risk_features.append("无法提现")
    if any(word in compact_history for word in ["补单", "联单"]):
        risk_features.append("要求继续补单")
    if any(word in compact_history for word in ["解冻费", "保证金", "认证费"]):
        risk_features.append("要求缴纳解冻费")
    if any(word in compact_history for word in ["刷单", "做任务", "返利", "返佣"]):
        risk_features.append("任务返佣")
    risk_features = list(dict.fromkeys(risk_features))
    prefill_slots = {
        "fraud_type_hint": fraud_hint,
        "education_topic": fraud_hint,
        "history_risk_context": history_text[-600:],
        "followup_answer": message,
    }
    if fraud_hint:
        prefill_slots["fraud_candidates"] = [fraud_hint]
    return {
        "primary_intent": INTENT_EMERGENCY_HELP,
        "secondary_intents": ["risk_help"],
        "workflow_mode": RISK_WORKFLOW_MODE,
        "confidence": 0.97,
        "urgency": "urgent" if "已发生转账" in risk_features or "无法提现" in risk_features else "normal",
        "safety_override": True,
        "deterministic_risk_route": True,
        "is_personal_risk_scene": True,
        "is_case_study": False,
        "continue_current_workflow": True,
        "reason": "确定性风险续接：用户本轮是简短回答/追问，近几轮已确认垫付、不能提现、补单等未处置风险，继续进入实时劝阻链路。",
        "need_clarification": False,
        "clarification_question": "",
        "clarification_options": [],
        "risk_signals": {
            "personal_risk_claim": True,
            "has_current_transfer_request": any(item in risk_features for item in ["要求继续补单", "要求缴纳解冻费"]),
            "confirmed_exposure_signal": any(item in risk_features for item in ["已发生转账", "无法提现"]),
            "risk_features": risk_features,
        },
        "safety_signals": {
            "personal_risk_claim": True,
            "confirmed_exposure_signal": any(item in risk_features for item in ["已发生转账", "无法提现"]),
            "requested_action_signal": any(item in risk_features for item in ["要求继续补单", "要求缴纳解冻费"]),
        },
        "risk_prefill": {
            "fraud_candidates": [fraud_hint] if fraud_hint else [],
            "education_topic": fraud_hint,
            "risk_features": risk_features,
        },
        "routing_decision": {
            "target": RISK_WORKFLOW_MODE,
            "force_high_risk": True,
            "prefill_slots": prefill_slots,
        },
        "semantic_scene": {
            "scene_type": "risk_followup",
            "is_risk_scene": True,
            "user_text": message,
            "reason": "承接上一轮风险追问，不能退回科普。",
        },
        "turn_rewrite": {
            "judge_source": "deterministic_contextual_risk_followup",
            "original_text": message,
            "rewritten_text": f"用户正在对刷单/返利类风险处置追问作答；历史风险事实：{history_text[-500:]}；本轮回答：{message}",
            "confidence": 0.97,
            "reason": "短答需要结合未处置风险上下文解释。",
        },
        "pending_answer_decision": {
            "is_pending_answer": True,
            "slot_updates": {"followup_answer": message},
            "completed_actions": [],
            "denied_actions": [],
            "confidence": 0.92,
            "reason": "本轮是对上一轮风险追问的回答。",
        },
    }


def _local_unified_route(message: str, history: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    text = re.sub(r"\s+", "", message or "")
    history_text = re.sub(r"\s+", "", _recent_user_history_text(history, limit=4))
    combined = f"{history_text} {text}"
    risk_features: List[str] = []
    if any(word in combined for word in ["转账", "转到安全账户", "安全账户", "付款", "汇款", "垫付", "垫了", "充值", "入金"]):
        risk_features.append("转账或垫付")
    if any(word in combined for word in ["提现不了", "不能提现", "无法提现", "提现失败", "账户冻结"]):
        risk_features.append("提现异常")
    if any(word in combined for word in ["验证码", "动态码", "密码", "银行卡", "身份证"]):
        risk_features.append("敏感信息索取")
    if any(word in combined for word in ["屏幕共享", "共享屏幕", "远程控制", "远程协助"]):
        risk_features.append("屏幕共享或远程控制")
    if any(word in combined for word in ["下载app", "下载APP", "安装app", "安装APP", "陌生链接", "链接", "二维码"]):
        risk_features.append("陌生链接或App")
    if any(word in combined for word in ["刷单", "做任务", "返利", "返佣", "补单", "联单"]):
        risk_features.append("刷单返利话术")
    if any(word in combined for word in ["保证金", "解冻费", "认证费", "手续费", "刷流水"]):
        risk_features.append("保证金/解冻费等收费理由")
    if any(word in combined for word in ["交钱", "先交", "押金", "定金", "留房费"]):
        risk_features.append("押金/定金等预付款")
    if any(word in combined for word in ["护照", "签证", "边境集合", "边境", "出境", "出国务工", "偷渡", "接应"]):
        risk_features.append("跨境出行或证件高危要求")
    risk_features = list(dict.fromkeys(risk_features))

    has_personal_marker = any(word in text for word in PERSONAL_RISK_MARKERS) or any(
        word in text
        for word in ["让我", "叫我", "要我", "我点了", "我填了", "我填写了", "我提供了", "我下载了", "我安装了"]
    )
    has_risk_keyword = any(word in combined for word in RISK_CONTEXT_KEYWORDS) or bool(risk_features)
    asks_action = any(word in text for word in ["怎么办", "能不能", "可以吗", "要不要", "靠谱吗", "是不是诈骗"])
    is_feedback = any(word in text for word in SMALLTALK_OR_FEEDBACK_MARKERS)
    has_knowledge_request = _has_knowledge_request(text)
    is_case_study = any(marker in text for marker in CASE_STUDY_MARKERS)
    has_explicit_personal_risk = any(marker in text for marker in EXPLICIT_PERSONAL_RISK_MARKERS)
    topic_hints = _topic_from_local_semantics(message)

    # A case-study question may contain the same risk words as a live incident.
    # Keep it in education mode unless the user explicitly switches to their own
    # current exposure or a previous unresolved case is being continued.
    risk_context_is_personal = not is_case_study or has_explicit_personal_risk
    if has_risk_keyword and risk_context_is_personal and (has_personal_marker or asks_action or _has_recent_unresolved_risk_context(history, None)):
        fraud_hint = (
            "刷单返利诈骗"
            if any(word in combined for word in ["刷单", "做任务", "返利", "返佣", "补单", "联单"])
            else "跨境高薪招工诱骗诈骗"
            if any(item in risk_features for item in ["跨境出行或证件高危要求"])
            else topic_hints.get("normalized_topic", "")
            if topic_hints.get("normalized_topic") != GENERAL_TRANSFER_TOPIC
            else ""
        )
        prefill_slots = {
            "fraud_type_hint": fraud_hint,
            "education_topic": fraud_hint,
            "history_risk_context": _recent_user_history_text(history, limit=6)[-600:],
            "local_risk_features": risk_features,
        }
        if fraud_hint:
            prefill_slots["fraud_candidates"] = [fraud_hint]
        return {
            "primary_intent": INTENT_EMERGENCY_HELP,
            "secondary_intents": ["risk_help", "anti_fraud_qa"],
            "workflow_mode": RISK_WORKFLOW_MODE,
            "confidence": 0.82,
            "urgency": "urgent" if any(item in risk_features for item in ["转账或垫付", "提现异常", "敏感信息索取", "屏幕共享或远程控制"]) else "normal",
            "safety_override": True,
            "deterministic_risk_route": True,
            "is_personal_risk_scene": True,
            "is_case_study": False,
            "continue_current_workflow": _has_recent_unresolved_risk_context(history, None),
            "reason": "本地规则识别到用户正在描述自身或当前接触的风险处境，进入实时劝阻。",
            "need_clarification": False,
            "clarification_question": "",
            "clarification_options": [],
            "risk_signals": {
                "personal_risk_claim": True,
                "has_current_transfer_request": any(item in risk_features for item in ["转账或垫付", "保证金/解冻费等收费理由", "押金/定金等预付款"]),
                "confirmed_exposure_signal": any(item in risk_features for item in ["转账或垫付", "提现异常", "敏感信息索取", "屏幕共享或远程控制"]),
                "cross_border_travel_or_id_signal": any(item in risk_features for item in ["跨境出行或证件高危要求"]),
                "risk_features": risk_features,
            },
            "safety_signals": {
                "personal_risk_claim": True,
                "confirmed_exposure_signal": any(item in risk_features for item in ["转账或垫付", "提现异常", "敏感信息索取", "屏幕共享或远程控制"]),
                "requested_action_signal": any(item in risk_features for item in ["保证金/解冻费等收费理由", "押金/定金等预付款", "陌生链接或App", "跨境出行或证件高危要求"]),
            },
            "risk_prefill": {
                "fraud_candidates": [fraud_hint] if fraud_hint else [],
                "education_topic": fraud_hint,
                "risk_features": risk_features,
            },
            "routing_decision": {
                "target": RISK_WORKFLOW_MODE,
                "force_high_risk": any(item in risk_features for item in ["转账或垫付", "提现异常", "敏感信息索取", "屏幕共享或远程控制", "押金/定金等预付款", "跨境出行或证件高危要求"]),
                "prefill_slots": prefill_slots,
            },
            "semantic_scene": {
                "scene_type": "personal_risk_scene",
                "is_risk_scene": True,
                "is_personal_risk_scene": True,
                "is_case_study": False,
                "user_text": message,
                "reason": "本地规则兜底：存在个人处境和风险动作。",
            },
            "turn_rewrite": {
                "judge_source": "local_unified_route",
                "original_text": message,
                "rewritten_text": message,
                "confidence": 0.82,
                "reason": "LLM 路由不可用时使用本地风险规则。",
            },
            "pending_answer_decision": {
                "is_pending_answer": False,
                "slot_updates": {},
                "completed_actions": [],
                "denied_actions": [],
                "confidence": 0.0,
                "reason": "",
            },
        }

    if is_feedback or (text and len(text) <= 18 and not has_risk_keyword and not has_knowledge_request):
        return {
            "primary_intent": "smalltalk",
            "secondary_intents": [],
            "workflow_mode": "fallback",
            "confidence": 0.75,
            "urgency": "none",
            "safety_override": False,
            "continue_current_workflow": False,
            "reason": "用户本轮是语音识别/表达纠正或普通反馈，不展示风险研判。",
            "need_clarification": False,
            "clarification_question": "",
            "clarification_options": [],
            "risk_signals": {},
            "routing_decision": {"target": "fallback", "force_high_risk": False, "prefill_slots": {}},
            "semantic_scene": {"scene_type": "smalltalk", "is_risk_scene": False, "user_text": message},
            "turn_rewrite": {
                "judge_source": "local_unified_route",
                "original_text": message,
                "rewritten_text": message,
                "confidence": 0.75,
                "reason": "普通反馈。",
            },
            "pending_answer_decision": {
                "is_pending_answer": False,
                "slot_updates": {},
                "completed_actions": [],
                "denied_actions": [],
                "confidence": 0.0,
                "reason": "",
            },
        }

    route = {
        "primary_intent": "anti_fraud_qa",
        "secondary_intents": [],
        "workflow_mode": "knowledge_answer",
        "confidence": 0.65,
        "urgency": "none",
        "safety_override": False,
        "deterministic_risk_route": False,
        "is_personal_risk_scene": False,
        "is_case_study": is_case_study,
        "continue_current_workflow": False,
        "reason": "本地规则识别为反诈知识咨询。",
        "need_clarification": False,
        "clarification_question": "",
        "clarification_options": [],
        "risk_signals": {},
        "routing_decision": {"target": "knowledge_answer", "force_high_risk": False, "prefill_slots": {}},
        "semantic_scene": {
            "scene_type": "case_study" if is_case_study else "knowledge_consultation",
            "is_risk_scene": False,
            "is_personal_risk_scene": False,
            "is_case_study": is_case_study,
            "user_text": message,
        },
        "turn_rewrite": {
            "judge_source": "local_unified_route",
            "original_text": message,
            "rewritten_text": message,
            "confidence": 0.65,
            "reason": "LLM 路由不可用时使用本地知识咨询兜底。",
        },
        "pending_answer_decision": {
            "is_pending_answer": False,
            "slot_updates": {},
            "completed_actions": [],
            "denied_actions": [],
            "confidence": 0.0,
            "reason": "",
        },
    }
    return _enrich_route_with_local_knowledge_hints(route, message)


def _wall_cross_border_job_risk_route(message: str) -> Optional[Dict[str, Any]]:
    text = re.sub(r"\s+", "", message or "")
    if not text:
        return None
    if any(marker in text for marker in ["什么是", "怎么识别", "如何防范", "案例", "科普", "定义"]):
        return None
    has_ad_context = any(word in text for word in ["墙上", "墙壁", "墙面", "小广告", "广告", "贴着", "看到"])
    has_cross_border_job = bool(
        re.search(r"(出国|境外|海外|国外|跨境).{0,12}(高工资|高薪|高收入|月薪|客服|招工|招聘|工作)", text)
        or re.search(r"(高工资|高薪|高收入|月薪).{0,12}(出国|境外|海外|国外|跨境)", text)
    )
    if not (has_ad_context and has_cross_border_job):
        return None
    return {
        "primary_intent": INTENT_RISK_HELP,
        "secondary_intents": ["anti_fraud_qa"],
        "workflow_mode": RISK_WORKFLOW_MODE,
        "confidence": 0.96,
        "urgency": "normal",
        "safety_override": True,
        "deterministic_risk_route": True,
        "is_personal_risk_scene": True,
        "is_case_study": False,
        "continue_current_workflow": False,
        "reason": "用户描述墙面或小广告中的出国高薪招工信息，属于可能正在接触的跨境招工诱骗风险场景，优先进入实时劝阻。",
        "need_clarification": False,
        "clarification_question": "",
        "clarification_options": [],
        "risk_signals": {
            "personal_risk_claim": True,
            "has_current_transfer_request": False,
            "confirmed_exposure_signal": False,
        },
        "risk_prefill": {
            "fraud_candidates": ["跨境高薪招工诱骗诈骗"],
            "education_topic": "跨境高薪招工诱骗诈骗",
        },
        "routing_decision": {
            "target": RISK_WORKFLOW_MODE,
            "force_high_risk": False,
            "prefill_slots": {
                "fraud_type_hint": "跨境高薪招工诱骗诈骗",
                "education_topic": "跨境高薪招工诱骗诈骗",
            },
        },
        "semantic_scene": {
            "scene_type": "personal_risk_scene",
            "is_risk_scene": True,
            "user_text": message,
            "reason": "墙面或小广告中的出国高薪招工需要先确认是否联系、缴费或提交证件。",
        },
        "turn_rewrite": {
            "judge_source": "deterministic_wall_cross_border_job_route",
            "original_text": message,
            "rewritten_text": message,
            "confidence": 0.96,
            "reason": "墙面出国高薪招工风险入口",
        },
        "pending_answer_decision": {
            "is_pending_answer": False,
            "slot_updates": {},
            "completed_actions": [],
            "denied_actions": [],
            "confidence": 0.0,
            "reason": "",
        },
    }


def _merge_frontend_history_into_route_memory(
    memory_context: Dict[str, Any],
    history: Optional[List[Dict[str, Any]]],
    message: str,
) -> Dict[str, Any]:
    case_state = memory_context.get("case_state") if isinstance(memory_context.get("case_state"), dict) else {}
    resolution = case_state.get("resolution") if isinstance(case_state.get("resolution"), dict) else {}
    if not resolution and isinstance(case_state.get("resolution_memory"), dict):
        resolution = case_state.get("resolution_memory") or {}
    post_closure_reset = bool(
        case_state.get("case_memory_cleared_after_closure")
        or case_state.get("closure_summary_delivered")
        or resolution.get("closure_summary_delivered")
    )
    if post_closure_reset:
        enriched = dict(memory_context or {})
        enriched["recent_user_messages"] = []
        enriched["memory_summary"] = ""
        route_context = dict(enriched.get("route_context") or {})
        route_context["active_workflow"] = "idle"
        route_context["pending_question"] = {}
        route_context["post_closure_memory_reset"] = True
        enriched["route_context"] = route_context
        return enriched

    normalized_history = _normalize_chat_history(history, limit=6)
    if not normalized_history:
        return memory_context

    enriched = dict(memory_context or {})
    user_messages = [
        {"role": "user", "text_redacted": item["text"], "ts": item.get("ts")}
        for item in normalized_history
        if item.get("role") == "user"
    ]
    if user_messages:
        enriched["recent_user_messages"] = (list(enriched.get("recent_user_messages") or []) + user_messages)[-10:]
    return enriched


def _prepare_knowledge_turn(
    message: str,
    *,
    session_id: str,
    history: Optional[List[Dict[str, Any]]] = None,
    route_decision: Optional[Dict[str, Any]] = None,
    limit: int = 8,
    use_llm: bool = True,
) -> Tuple[Dict[str, Any], str, Optional[str], List[Dict[str, Any]], Dict[str, Any], List[Dict[str, Any]]]:
    memory = _memory_for_session(session_id)
    frontend_history = _normalize_chat_history(history)
    route_decision = route_decision or {}
    query_plan = _build_knowledge_query_plan(
        message,
        route_decision=route_decision,
        history=frontend_history,
        use_llm=use_llm,
    )
    retrieval_query = str(
        query_plan.get("clean_query")
        or route_decision.get("query_rewrite")
        or message
    ).strip() or message

    intent = str(query_plan.get("user_intent") or "") or classify_education_intent(retrieval_query)
    previous_topic = memory.get("last_topic")

    route_topics = _topics_from_route(route_decision)
    direct_topics = _merge_topics(
        route_topics,
        _topics_from_query_plan(query_plan),
        match_education_topics(retrieval_query, previous_topic=None, limit=4 if intent == INTENT_COMPARE else 3),
        match_education_topics(message, previous_topic=None, limit=4 if intent == INTENT_COMPARE else 3),
    )
    use_history = _should_use_history_for_query(message, direct_topics)
    if frontend_history and use_history:
        memory["history"] = frontend_history
    if not use_history:
        memory["prompt_history"] = []
    else:
        memory["prompt_history"] = memory.get("history", [])[-4:]

    topics = direct_topics
    if not topics and previous_topic and use_history:
        topics = [{"fraud_type": previous_topic, "score": 5, "matched_terms": ["上一轮主题"], "aliases": [], "target_users": []}]

    retrieval = retrieve_education_context(
        retrieval_query,
        intent=intent,
        topics=topics,
        limit=limit,
        include_content=True,
        query_plan=query_plan,
    )
    retrieval["query"] = retrieval_query
    retrieval["query_understanding"] = query_plan
    references = retrieval["items"]
    return memory, intent, previous_topic, topics, retrieval, references


def _build_knowledge_response(
    *,
    message: str,
    session_id: str,
    memory: Dict[str, Any],
    intent: str,
    previous_topic: Optional[str],
    topics: List[Dict[str, Any]],
    retrieval: Dict[str, Any],
    references: List[Dict[str, Any]],
    answer: str,
    generation: str,
) -> Dict[str, Any]:
    active_topic = topics[0]["fraud_type"] if topics else (
        references[0].get("fraud_type") if references else (previous_topic if memory.get("prompt_history") else None)
    )
    if active_topic and active_topic != "通用法律法规与处置常识":
        memory["last_topic"] = active_topic
    elif not memory.get("prompt_history"):
        memory.pop("last_topic", None)
    memory["last_intent"] = intent
    memory.setdefault("history", []).extend(
        [
            {"role": "user", "content": message},
            {"role": "assistant", "content": answer[:600]},
        ]
    )
    memory["history"] = memory["history"][-_MAX_MEMORY_TURNS:]

    public_refs = [{key: value for key, value in ref.items() if key != "content"} for ref in references]
    active_type = standard_name_for(active_topic) if active_topic and fraud_type_id_for(active_topic) else str(active_topic or "")
    active_type_id = fraud_type_id_for(active_topic) if active_topic else ""
    return {
        "message": "教育 RAG 问答完成",
        "answer": answer,
        "session_id": session_id,
        "intent": intent,
        "intent_label": INTENT_LABELS.get(intent, intent),
        "topics": topics,
        "fraud_type_id": active_type_id,
        "primary_type": active_type,
        "candidate_types": [active_type] if active_type else [],
        "candidate_type_ids": [active_type_id] if active_type_id else [],
        "type_confidence": 0.8 if active_type_id else 0.0,
        "references": public_refs,
        "source": retrieval["source"],
        "generation": generation,
        "module": "knowledge_assistant",
        "scope": "anti_fraud_education_rag",
        "assistant_mode": ASSISTANT_MODE_KNOWLEDGE,
        "workflow_mode": "knowledge_answer",
        "retrieval_quality": retrieval.get("retrieval_quality", {}),
        "knowledge_strategy": retrieval.get("knowledge_strategy", {}),
        "web_fallback": retrieval.get("web_fallback", {}),
        "query_understanding": retrieval.get("query_understanding", {}),
        "retrieval_paths": sorted(
            {
                path
                for ref in public_refs
                for path in str(ref.get("retrieval_path") or "").split("+")
                if path
            }
        ),
    }


def _route_for_unified_assistant(
    message: str,
    session_id: str,
    history: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    deterministic_route = _wall_cross_border_job_risk_route(message)
    if deterministic_route:
        return _enrich_route_with_local_knowledge_hints(deterministic_route, message)
    # Compute the cheap local envelope before touching Mongo or an LLM.  A
    # high-confidence live-risk turn must be able to produce its safety card
    # even when history storage is unavailable or slow.
    local_route = _enrich_route_with_local_knowledge_hints(_local_unified_route(message, history), message)
    local_risk_signals = local_route.get("risk_signals") or {}
    if local_route.get("is_case_study") and not local_route.get("is_personal_risk_scene"):
        local_route["route_source"] = "deterministic_case_study"
        local_route["first_response_mode"] = "knowledge_answer"
        return local_route
    if (
        local_route.get("deterministic_risk_route")
        and local_route.get("workflow_mode") == RISK_WORKFLOW_MODE
        and not local_route.get("is_case_study")
        and float(local_route.get("confidence") or 0) >= 0.8
        and (
            local_risk_signals.get("confirmed_exposure_signal")
            or local_risk_signals.get("has_current_transfer_request")
            or (local_route.get("safety_signals") or {}).get("requested_action_signal")
        )
    ):
        local_route["route_source"] = "deterministic_local_first"
        local_route["llm_async_supplement"] = True
        local_route["first_response_mode"] = "structured_safety_card"
        return local_route
    try:
        from app.query_process.agent.memory import get_memory_manager
        from app.query_process.services.llm_scene_router import route_user_input_llm

        memory_context = get_memory_manager().load_context(session_id, message, intent_hint="")
        memory_context = _merge_frontend_history_into_route_memory(memory_context, history, message)
        contextual_risk_route = _contextual_risk_followup_route(message, history, memory_context)
        if contextual_risk_route:
            return _enrich_route_with_local_knowledge_hints(contextual_risk_route, message)
        if get_llm_config_error():
            return local_route
        return _enrich_route_with_local_knowledge_hints(route_user_input_llm(message, memory_context, intent_hint=""), message)
    except Exception as exc:
        logger.warning(f"Unified assistant route fallback because LLM route failed: {exc}", exc_info=True)
        return _enrich_route_with_local_knowledge_hints(_local_unified_route(message, history), message)


def _should_enter_risk_dissuasion(route_decision: Dict[str, Any]) -> bool:
    workflow = str(route_decision.get("workflow_mode") or "")
    primary_intent = str(route_decision.get("primary_intent") or "")
    if workflow == RISK_WORKFLOW_MODE:
        return True
    if primary_intent in RISK_ROUTE_INTENTS:
        return True
    risk_signals = route_decision.get("risk_signals") or {}
    safety_signals = route_decision.get("safety_signals") or {}
    return bool(
        risk_signals.get("confirmed_exposure_signal")
        or risk_signals.get("has_current_transfer_request")
        or safety_signals.get("confirmed_exposure_signal")
        or safety_signals.get("requested_action_signal")
        or safety_signals.get("personal_risk_claim")
    )


def _should_enter_lightweight_specialty(route_decision: Dict[str, Any]) -> bool:
    return False


def _should_answer_as_smalltalk(route_decision: Dict[str, Any]) -> bool:
    return (
        str(route_decision.get("primary_intent") or "") == "smalltalk"
        or str(route_decision.get("workflow_mode") or "") == "fallback"
    )


def _knowledge_dialogue_memory(session_id: str, history: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    memory = _memory_for_session(session_id)
    frontend_history = _normalize_chat_history(history)
    if frontend_history:
        memory["history"] = frontend_history
    return memory


def _route_with_knowledge_dialogue_context(route_decision: Dict[str, Any], session_id: str) -> Dict[str, Any]:
    state = (_memory_for_session(session_id).get("knowledge_dialogue_state") or {})
    topic = str(state.get("topic") or "").strip()
    if not topic:
        return route_decision
    if str(state.get("active_workflow") or "") != "knowledge_dialogue_flow":
        return route_decision
    enriched = dict(route_decision or {})
    education_context = {
        "source": "knowledge_dialogue_state",
        "active_workflow": state.get("active_workflow", ""),
        "topic": topic,
        "scam_id": state.get("scam_id", ""),
        "learning_stage": state.get("learning_stage", ""),
        "learning_stage_label": state.get("learning_stage_label", ""),
        "completed_sections": state.get("completed_sections", []),
        "risk_interruptible": bool(state.get("risk_interruptible", True)),
    }
    enriched["education_context"] = education_context
    routing_decision = dict(enriched.get("routing_decision") or {})
    prefill_slots = dict(routing_decision.get("prefill_slots") or {})
    prefill_slots.setdefault("fraud_type_hint", topic)
    prefill_slots.setdefault("education_topic", topic)
    routing_decision["prefill_slots"] = prefill_slots
    enriched["routing_decision"] = routing_decision
    risk_prefill = dict(enriched.get("risk_prefill") or {})
    candidates = [item for item in risk_prefill.get("fraud_candidates", []) if item]
    if topic not in candidates:
        candidates.insert(0, topic)
    risk_prefill["fraud_candidates"] = candidates[:5]
    risk_prefill["education_topic"] = topic
    enriched["risk_prefill"] = risk_prefill
    return enriched


def _knowledge_turn_semantics_for_service(
    message: str,
    session_id: str,
    route_decision: Dict[str, Any],
) -> Dict[str, Any]:
    state = (_memory_for_session(session_id).get("knowledge_dialogue_state") or {})
    if not state.get("topic"):
        return {}
    existing = route_decision.get("knowledge_turn_semantics") if isinstance(route_decision, dict) else {}
    if isinstance(existing, dict) and existing:
        return existing
    config_error = get_llm_config_error()
    if config_error:
        logger.warning(f"Skip knowledge turn semantics LLM: {config_error}")
        return {}
    from app.modules.knowledge_assistant.knowledge_dialogue_agent import analyze_learning_turn_semantics

    try:
        semantics = analyze_learning_turn_semantics(
            message=message,
            state=state,
            route_decision=route_decision,
            use_llm=True,
        )
        route_decision["knowledge_turn_semantics"] = semantics
        return semantics
    except Exception as exc:
        logger.warning(f"Knowledge turn semantics fallback: {exc}", exc_info=True)
        return {}


def _build_post_knowledge_idle_response(
    session_id: str,
    route_decision: Dict[str, Any],
    message: str,
) -> Dict[str, Any]:
    answer = (
        "可以，刚才这类科普先讲到这里。\n"
        "后面你可以继续问案例、套路、防范方法，也可以直接发一段可疑聊天或转账要求，我会先判断是风险求助还是知识咨询。"
    )
    response = {
        "message": "科普完成后的日常引导",
        "answer": answer,
        "session_id": session_id,
        "intent": "smalltalk",
        "intent_label": "日常引导",
        "topics": [],
        "references": [],
        "source": "knowledge_dialogue_lifecycle",
        "generation": "template",
        "module": UNIFIED_MODULE,
        "scope": "anti_fraud_unified_assistant",
        "assistant_mode": ASSISTANT_MODE_KNOWLEDGE,
        "workflow_mode": "fallback",
        "route_decision": route_decision,
        "knowledge_dialogue_state": _memory_for_session(session_id).get("knowledge_dialogue_state", {}),
    }
    response["anti_fraud_engine"] = build_anti_fraud_engine_result(input_text=message, route_decision=route_decision)
    return response


def _should_continue_knowledge_dialogue(message: str, session_id: str, route_decision: Dict[str, Any]) -> bool:
    try:
        semantics = _knowledge_turn_semantics_for_service(message, session_id, route_decision)
        if not semantics:
            return False
        if semantics.get("is_risk_interrupt"):
            return False
        return bool(semantics.get("should_continue_knowledge") or semantics.get("should_close_learning"))
    except Exception as exc:
        logger.warning(f"知识对话续接判断失败：{exc}")
        return False


def _run_knowledge_dialogue_flow(
    message: str,
    *,
    session_id: str,
    history: Optional[List[Dict[str, Any]]] = None,
    route_decision: Optional[Dict[str, Any]] = None,
    use_llm: bool = True,
    limit: int = 8,
) -> Dict[str, Any]:
    from app.modules.knowledge_assistant.knowledge_dialogue_agent import run_knowledge_dialogue_agent

    config_error = get_llm_config_error() if use_llm else None
    if config_error:
        logger.warning(f"Run knowledge dialogue without LLM: {config_error}")
        use_llm = False

    memory, intent, previous_topic, topics, retrieval, references = _prepare_knowledge_turn(
        message,
        session_id=session_id,
        history=history,
        route_decision=route_decision,
        limit=limit,
        use_llm=use_llm,
    )
    retrieval_quality = _retrieval_quality(
        query=str(retrieval.get("query") or message),
        topics=topics,
        retrieval=retrieval,
        references=references,
    )
    strategy = _decide_knowledge_strategy(message, route_decision or {}, retrieval_quality, references, use_llm)
    retrieval["retrieval_quality"] = retrieval_quality
    retrieval["knowledge_strategy"] = strategy

    query_plan = retrieval.get("query_understanding") if isinstance(retrieval.get("query_understanding"), dict) else {}
    route_topic = str((route_decision or {}).get("normalized_topic") or "").strip()
    active_topic = topics[0].get("fraud_type") if topics else route_topic
    is_single_type_plan = str(query_plan.get("answer_scope") or "") == "single_type"
    is_concrete_fraud_topic = bool(
        is_single_type_plan
        and active_topic
        and active_topic != GENERAL_TRANSFER_TOPIC
        and fraud_type_id_for(active_topic)
    )

    if strategy.get("strategy") == "clarify":
        answer = strategy.get("clarification_question") or "这个问题可能有几种理解。你想了解的是具体骗局套路，还是正在遇到的转账/押金/验证码风险？"
        return _build_knowledge_response(
            message=message,
            session_id=session_id,
            memory=memory,
            intent=INTENT_GENERAL,
            previous_topic=previous_topic,
            topics=topics,
            retrieval=retrieval,
            references=[],
            answer=answer,
            generation="clarification",
        )

    if strategy.get("strategy") == "use_web_fallback":
        web_query = str((route_decision or {}).get("query_rewrite") or retrieval.get("query") or message)
        web_result = search_trusted_web(web_query, limit=5)
        retrieval["web_fallback"] = {
            "web_status": web_result.get("web_status", ""),
            "provider": web_result.get("provider", ""),
            "reason": web_result.get("reason", ""),
            "item_count": len(web_result.get("items") or []),
        }
        answer, generation = _build_web_fallback_answer(
            message,
            active_topic or route_topic,
            web_result,
            use_llm,
            query_plan=query_plan,
        )
        web_refs = [
            {
                "doc_id": item.get("url", ""),
                "doc_type": "trusted_web",
                "fraud_type": active_topic or route_topic or "",
                "title": item.get("title", ""),
                "summary": item.get("content", ""),
                "source_dataset": item.get("url", ""),
                "source_ids": [item.get("url", "")],
                "priority": 0,
                "retrieval_score": item.get("score", 0),
            }
            for item in (web_result.get("items") or [])[:5]
        ]
        return _build_knowledge_response(
            message=message,
            session_id=session_id,
            memory=memory,
            intent=intent,
            previous_topic=previous_topic,
            topics=topics or ([{"fraud_type": active_topic or route_topic, "score": 0, "matched_terms": ["通用主题"], "aliases": [], "target_users": []}] if (active_topic or route_topic) else []),
            retrieval=retrieval,
            references=web_refs,
            answer=answer,
            generation=generation,
        )

    if strategy.get("strategy") == "use_general_template" or (not is_concrete_fraud_topic and not references):
        answer = _build_general_template_answer(message, active_topic or route_topic, query_plan=query_plan)
        return _build_knowledge_response(
            message=message,
            session_id=session_id,
            memory=memory,
            intent=intent,
            previous_topic=previous_topic,
            topics=topics or ([{"fraud_type": active_topic or route_topic, "score": 0, "matched_terms": ["通用主题"], "aliases": [], "target_users": []}] if (active_topic or route_topic) else []),
            retrieval=retrieval,
            references=references,
            answer=answer,
            generation="general_template",
        )

    if (
        not is_concrete_fraud_topic
        and str(query_plan.get("answer_scope") or "") == "domain_overview"
        and str(query_plan.get("domain") or "") == CROSS_BORDER_DOMAIN
        and not use_llm
    ):
        answer = _build_general_template_answer(message, active_topic or route_topic, query_plan=query_plan)
        return _build_knowledge_response(
            message=message,
            session_id=session_id,
            memory=memory,
            intent=intent,
            previous_topic=previous_topic,
            topics=topics,
            retrieval=retrieval,
            references=references,
            answer=answer,
            generation="local_domain_template_with_rag",
        )

    if not is_concrete_fraud_topic:
        answer, generation = _generate_answer(
            message,
            intent,
            topics,
            references,
            memory,
            use_llm=use_llm,
        )
        return _build_knowledge_response(
            message=message,
            session_id=session_id,
            memory=memory,
            intent=intent,
            previous_topic=previous_topic,
            topics=topics,
            retrieval=retrieval,
            references=references,
            answer=answer,
            generation=generation,
        )

    memory = _knowledge_dialogue_memory(session_id, history)
    dialogue_response = run_knowledge_dialogue_agent(
        message=message,
        session_id=session_id,
        memory=memory,
        history=history,
        route_decision=route_decision or {},
        use_llm=use_llm,
        limit=limit,
    )
    dialogue_response = dict(dialogue_response or {})
    if is_concrete_fraud_topic:
        dialogue_answer = str(dialogue_response.get("answer") or "").strip()
        if not _knowledge_answer_satisfies_contract(dialogue_answer, active_topic, references, message):
            logger.warning("Knowledge dialogue answer failed the concrete-topic contract, use typed local answer")
            dialogue_response["answer"] = _build_local_knowledge_answer(message, intent, topics, references)
            dialogue_response["generation"] = "local_template_after_quality_gate"
    dialogue_response.setdefault("retrieval_quality", retrieval_quality)
    dialogue_response.setdefault("knowledge_strategy", strategy)
    dialogue_response.setdefault("web_fallback", retrieval.get("web_fallback", {}))
    dialogue_response.setdefault("query_understanding", query_plan)
    dialogue_response.setdefault(
        "retrieval_paths",
        sorted(
            {
                path
                for ref in references
                for path in str(ref.get("retrieval_path") or "").split("+")
                if path
            }
        ),
    )
    dialogue_response.setdefault("assistant_mode", ASSISTANT_MODE_KNOWLEDGE)
    return dialogue_response


def _build_smalltalk_unified_response(session_id: str, route_decision: Dict[str, Any]) -> Dict[str, Any]:
    user_text = str((route_decision.get("semantic_scene") or {}).get("user_text") or "").strip()
    answer = ""
    if not get_llm_config_error():
        try:
            system_prompt = """
你是智能反诈助手。你可以自然闲聊，但身份边界清楚：你不是人工民警，也不会编造已经查询过的事实。

风格：
- 温和、聪明、自然，不要固定口号式问候。
- 如果用户只是打招呼或问你是谁，简短介绍自己能帮忙识别骗局、拆话术、做止损建议。
- 如果用户在纠正你没听懂，先承认理解偏差，再邀请他重发原话。
- 不要主动恐吓，不要过度追问隐私。
"""
            human_prompt = f"用户本轮：{user_text or '你好'}\n请直接回复中文，1-3 句话。"
            client = get_llm_client()
            result = client.invoke([SystemMessage(content=system_prompt.strip()), HumanMessage(content=human_prompt)])
            answer = str(getattr(result, "content", result) or "").strip()
        except Exception as exc:
            logger.warning(f"Smalltalk LLM failed, use persona fallback: {exc}", exc_info=True)

    if not answer:
        if any(marker in user_text for marker in SMALLTALK_OR_FEEDBACK_MARKERS):
            variants = [
                "你说得对，刚才我理解偏了。你可以把原话再发一遍，我会按反诈咨询重新判断。",
                "收到，是我刚才没贴住你的意思。你直接按自己的说法重发，我会先判断是科普、风险求助还是普通聊天。",
                "明白，我先不套模板了。你把想问的那句话重新发给我，我会按语义来分流处理。",
            ]
        else:
            variants = [
                "我在。你可以跟我聊具体可疑情况，也可以让我科普某类骗局；如果涉及转账、验证码或陌生链接，我会优先帮你拦风险。",
                "你好，我可以帮你拆诈骗话术、判断可疑操作，也能讲某类骗局的套路。你随便用日常说法问就行。",
                "嗨，我是智能反诈助手。你可以发一段聊天记录、一个可疑要求，或者直接问某类骗局怎么识别。",
                "我可以陪你把可疑点捋清楚：对方是谁、让你做什么、有没有要钱或验证码。只是闲聊也可以，我会尽量说人话。",
                "在的。你要是拿不准一件事，直接描述对方怎么说、让你做什么，我先帮你判断有没有风险。",
            ]
        answer = random.choice(variants)
    response = {
        "message": "智能反诈助手问候完成",
        "answer": answer,
        "session_id": session_id,
        "intent": "smalltalk",
        "intent_label": "问候",
        "topics": [],
        "references": [],
        "source": "template",
        "generation": "template",
        "module": UNIFIED_MODULE,
        "scope": "anti_fraud_unified_assistant",
        "assistant_mode": ASSISTANT_MODE_KNOWLEDGE,
        "workflow_mode": str(route_decision.get("workflow_mode") or "fallback"),
        "route_decision": route_decision,
    }
    response["anti_fraud_engine"] = build_anti_fraud_engine_result(input_text="", route_decision=route_decision)
    return response


def _annotate_knowledge_unified(response: Dict[str, Any], route_decision: Dict[str, Any]) -> Dict[str, Any]:
    response = dict(response or {})
    engine = response.get("anti_fraud_engine") or route_decision.get("anti_fraud_engine")
    workflow_mode = str(response.get("workflow_mode") or "knowledge_answer")
    response.update(
        {
            "module": UNIFIED_MODULE,
            "scope": "anti_fraud_unified_assistant",
            "assistant_mode": ASSISTANT_MODE_KNOWLEDGE,
            "workflow_mode": workflow_mode,
            "route_decision": route_decision,
            "anti_fraud_engine": engine
            or build_anti_fraud_engine_result(
                input_text=str(response.get("input") or ""),
                route_decision=route_decision,
            ),
        }
    )
    response["risk_judgement_card"] = (response.get("anti_fraud_engine") or {}).get("risk_judgement_card", {})
    return attach_video_cards(response, str(response.get("session_id") or ""))


def _annotate_risk_unified(response: Dict[str, Any], route_decision: Dict[str, Any]) -> Dict[str, Any]:
    response = dict(response or {})
    summary = dict(response.get("summary") or {})
    engine = summary.get("anti_fraud_engine") or route_decision.get("anti_fraud_engine")
    closed_statuses = {"prevented", "stop_loss_done", "education_ready", "closed", "observation"}
    post_resolution_reset = (
        str(summary.get("case_status") or response.get("case_status") or "") in closed_statuses
        and bool(summary.get("post_resolution_education_delivered") or response.get("post_resolution_education_delivered"))
    )
    assistant_mode = ASSISTANT_MODE_KNOWLEDGE if post_resolution_reset else ASSISTANT_MODE_RISK
    workflow_mode = "knowledge_answer" if post_resolution_reset else RISK_WORKFLOW_MODE
    if summary:
        summary.setdefault("route_decision", route_decision)
        summary["workflow_mode"] = workflow_mode
        summary["assistant_mode"] = assistant_mode
        summary.setdefault("module", UNIFIED_MODULE)
        summary.setdefault(
            "anti_fraud_engine",
            engine
            or build_anti_fraud_engine_result(
                input_text=str((summary.get("basic_input") or {}).get("original_query") or ""),
                route_decision=route_decision,
                risk_result=summary.get("rule_engine") or {},
            ),
        )
        response["summary"] = summary
        engine = summary.get("anti_fraud_engine")
        summary["risk_judgement_card"] = (engine or {}).get("risk_judgement_card", summary.get("risk_judgement_card", {}))
    response.update(
        {
            "module": UNIFIED_MODULE,
            "scope": "anti_fraud_unified_assistant",
            "assistant_mode": assistant_mode,
            "workflow_mode": workflow_mode,
            "route_decision": response.get("route_decision") or route_decision,
            "anti_fraud_engine": engine
            or build_anti_fraud_engine_result(input_text="", route_decision=route_decision),
        }
    )
    response["risk_judgement_card"] = (response.get("anti_fraud_engine") or {}).get(
        "risk_judgement_card",
        summary.get("risk_judgement_card", {}),
    )
    return attach_video_cards(response, str(response.get("session_id") or summary.get("session_id") or ""))


def _annotate_specialty_unified(response: Dict[str, Any], route_decision: Dict[str, Any]) -> Dict[str, Any]:
    response = dict(response or {})
    summary = dict(response.get("summary") or {})
    engine = (
        response.get("anti_fraud_engine")
        or summary.get("anti_fraud_engine")
        or route_decision.get("anti_fraud_engine")
    )
    if summary:
        summary.setdefault("route_decision", route_decision)
        summary.setdefault("assistant_mode", ASSISTANT_MODE_KNOWLEDGE)
        summary.setdefault("module", UNIFIED_MODULE)
        summary.setdefault("anti_fraud_engine", engine)
        response["summary"] = summary
        engine = summary.get("anti_fraud_engine")
    response.update(
        {
            "module": UNIFIED_MODULE,
            "scope": "anti_fraud_unified_assistant",
            "assistant_mode": ASSISTANT_MODE_KNOWLEDGE,
            "workflow_mode": str(route_decision.get("workflow_mode") or response.get("workflow_mode") or ""),
            "route_decision": route_decision,
            "anti_fraud_engine": engine
            or build_anti_fraud_engine_result(
                input_text=str(response.get("answer") or ""),
                route_decision=route_decision,
            ),
        }
    )
    response["risk_judgement_card"] = (response.get("anti_fraud_engine") or {}).get("risk_judgement_card", {})
    return attach_video_cards(response, str(response.get("session_id") or summary.get("session_id") or ""))


def _run_unified_specialty_flow(
    message: str,
    *,
    session_id: str,
    history: Optional[List[Dict[str, Any]]],
    route_decision: Dict[str, Any],
    is_stream: bool,
) -> Dict[str, Any]:
    from app.query_process.services.lightweight_flows import run_lightweight_flow

    try:
        from app.query_process.agent.memory import get_memory_manager

        memory_context = get_memory_manager().load_context(session_id, message, intent_hint="")
        memory_context = _merge_frontend_history_into_route_memory(memory_context, history, message)
    except Exception:
        memory_context = {"session_id": session_id, "case_id": "", "case_state": {}, "route_context": {}}
    return run_lightweight_flow(
        session_id=session_id,
        user_query=message,
        memory_context=memory_context,
        route_decision=route_decision,
        is_stream=is_stream,
    )


def run_knowledge_chat_stream(
    message: str,
    *,
    session_id: str,
    history: Optional[List[Dict[str, Any]]] = None,
    use_llm: bool = True,
    limit: int = 8,
) -> None:
    message = (message or "").strip()
    try:
        if not message:
            response = {
                "message": "问题为空",
                "answer": "请先输入一个反诈科普问题。",
                "session_id": session_id or str(uuid.uuid4()),
                "intent": INTENT_GENERAL,
                "intent_label": INTENT_LABELS[INTENT_GENERAL],
                "topics": [],
                "references": [],
                "source": "none",
                "generation": "template",
            }
            _push_text_deltas(response["session_id"], response["answer"])
            push_to_session(response["session_id"], SSEEvent.FINAL, response)
            return
        if _is_quiz_request(message):
            response = _build_quiz_disabled_response(session_id or str(uuid.uuid4()))
            _push_text_deltas(response["session_id"], response["answer"])
            push_to_session(response["session_id"], SSEEvent.FINAL, response)
            return

        memory, intent, previous_topic, topics, retrieval, references = _prepare_knowledge_turn(
            message,
            session_id=session_id,
            history=history,
            limit=limit,
        )

        config_error = get_llm_config_error() if use_llm else "LLM generation is disabled"
        if config_error:
            answer, generation = _generate_answer(
                message,
                intent,
                topics,
                references,
                memory,
                use_llm=False,
            )
            response = _build_knowledge_response(
                message=message,
                session_id=session_id,
                memory=memory,
                intent=intent,
                previous_topic=previous_topic,
                topics=topics,
                retrieval=retrieval,
                references=references,
                answer=answer,
                generation=generation,
            )
            _push_text_deltas(session_id, response.get("answer", ""))
            push_to_session(session_id, SSEEvent.FINAL, response)
            return

        prompt = _build_prompt(message, intent, topics, references, memory)
        client = get_llm_client()
        chunks: List[str] = []
        for chunk in client.stream([HumanMessage(content=prompt)]):
            delta = _stream_chunk_text(getattr(chunk, "content", chunk))
            if not delta or not delta.strip():
                continue
            chunks.append(delta)
            push_to_session(session_id, SSEEvent.DELTA, {"delta": delta})
        answer = "".join(chunks).strip()
        if not answer:
            raise ValueError("教育 RAG LLM 流式生成了空回答")
        generation = "llm"
        concrete_topic = next(
            (
                str(item.get("fraud_type") or "").strip()
                for item in topics
                if fraud_type_id_for(item.get("fraud_type"))
            ),
            str(references[0].get("fraud_type") or "").strip() if references and fraud_type_id_for(references[0].get("fraud_type")) else "",
        )
        if concrete_topic and not _knowledge_answer_satisfies_contract(answer, concrete_topic, references, message):
            answer = _build_local_knowledge_answer(message, intent, topics, references)
            generation = "local_template_after_quality_gate"
            _push_text_deltas(session_id, answer)

        response = _build_knowledge_response(
            message=message,
            session_id=session_id,
            memory=memory,
            intent=intent,
            previous_topic=previous_topic,
            topics=topics,
            retrieval=retrieval,
            references=references,
            answer=answer,
            generation=generation,
        )
        push_to_session(session_id, SSEEvent.FINAL, response)
    except Exception as exc:
        logger.exception("知识问答流式处理失败")
        push_to_session(session_id, SSEEvent.ERROR, {"error": f"知识问答流式处理失败：{exc}"})


def run_unified_anti_fraud_chat_stream(
    message: str,
    *,
    session_id: str,
    history: Optional[List[Dict[str, Any]]] = None,
    use_llm: bool = True,
    limit: int = 8,
) -> None:
    message = (message or "").strip()
    if not message:
        response = _annotate_knowledge_unified(
            {
                "message": "问题为空",
                "answer": "请先输入一个反诈咨询问题。",
                "session_id": session_id or str(uuid.uuid4()),
                "intent": INTENT_GENERAL,
                "intent_label": INTENT_LABELS[INTENT_GENERAL],
                "topics": [],
                "references": [],
                "source": "none",
                "generation": "template",
            },
            {
                "primary_intent": "anti_fraud_qa",
                "workflow_mode": "knowledge_answer",
                "confidence": 1.0,
                "reason": "empty message",
                "risk_signals": {},
                "routing_decision": {"target": "knowledge_answer", "force_high_risk": False, "prefill_slots": {}},
            },
        )
        _push_text_deltas(response["session_id"], response["answer"])
        push_to_session(response["session_id"], SSEEvent.FINAL, response)
        return
    if _is_quiz_request(message):
        response = _annotate_knowledge_unified(
            _build_quiz_disabled_response(session_id or str(uuid.uuid4())),
            {
                "primary_intent": "anti_fraud_qa",
                "workflow_mode": "knowledge_answer",
                "confidence": 1.0,
                "reason": "quiz feature disabled",
                "risk_signals": {},
                "routing_decision": {"target": "knowledge_answer", "force_high_risk": False, "prefill_slots": {}},
            },
        )
        _push_text_deltas(response["session_id"], response["answer"])
        push_to_session(response["session_id"], SSEEvent.FINAL, response)
        return
    route_decision = _route_with_knowledge_dialogue_context(
        _route_for_unified_assistant(message, session_id, history=history),
        session_id,
    )
    knowledge_turn_semantics = _knowledge_turn_semantics_for_service(message, session_id, route_decision)
    if knowledge_turn_semantics.get("is_post_completion_idle"):
        response = _build_post_knowledge_idle_response(session_id, route_decision, message)
        _push_text_deltas(session_id, response["answer"])
        push_to_session(session_id, SSEEvent.FINAL, response)
        return
    continue_knowledge_dialogue = _should_continue_knowledge_dialogue(message, session_id, route_decision)
    if _should_enter_risk_dissuasion(route_decision) and not continue_knowledge_dialogue:
        try:
            from app.modules.emergency_dissuasion.service import run_emergency_graph

            update_task_status(session_id, TASK_STATUS_PROCESSING, True)
            run_emergency_graph(
                session_id,
                message,
                True,
                route_decision.get("primary_intent") or INTENT_RISK_HELP,
                route_decision_override=route_decision,
                history_override=history,
            )
        except Exception as exc:
            logger.exception("统一反诈助手风险劝阻流式处理失败")
            push_to_session(session_id, SSEEvent.ERROR, {"error": f"风险劝阻处理失败：{exc}"})
        return

    if _should_enter_lightweight_specialty(route_decision):
        try:
            response = _annotate_specialty_unified(
                _run_unified_specialty_flow(
                    message,
                    session_id=session_id,
                    history=history,
                    route_decision=route_decision,
                    is_stream=False,
                ),
                route_decision,
            )
            _push_text_deltas(session_id, response.get("answer", ""))
            push_to_session(session_id, SSEEvent.FINAL, response)
        except Exception as exc:
            logger.exception("统一反诈助手专项流程处理失败")
            push_to_session(session_id, SSEEvent.ERROR, {"error": f"专项流程处理失败：{exc}"})
        return

    if _should_answer_as_smalltalk(route_decision) and not continue_knowledge_dialogue:
        response = _build_smalltalk_unified_response(session_id, route_decision)
        _push_text_deltas(session_id, response["answer"])
        push_to_session(session_id, SSEEvent.FINAL, response)
        return

    try:
        response = _annotate_knowledge_unified(
            _run_knowledge_dialogue_flow(
                message,
                session_id=session_id,
                history=history,
                route_decision=route_decision,
                use_llm=use_llm,
                limit=limit,
            ),
            route_decision,
        )
        _push_text_deltas(session_id, response.get("answer", ""))
        push_to_session(session_id, SSEEvent.FINAL, response)
        return
    except Exception as exc:
        logger.exception("统一反诈助手科普流式处理失败")
        push_to_session(session_id, SSEEvent.ERROR, {"error": f"科普问答处理失败：{exc}"})


def knowledge_chat(
    message: str,
    *,
    session_id: str | None = None,
    history: Optional[List[Dict[str, Any]]] = None,
    use_llm: bool = True,
    limit: int = 8,
) -> Dict[str, Any]:
    message = (message or "").strip()
    if not message:
        return {
            "message": "问题为空",
            "answer": "请先输入一个反诈科普问题。",
            "session_id": session_id or str(uuid.uuid4()),
            "intent": INTENT_GENERAL,
            "intent_label": INTENT_LABELS[INTENT_GENERAL],
            "topics": [],
            "references": [],
            "source": "none",
            "generation": "template",
        }

    session_id = session_id or str(uuid.uuid4())
    if _is_quiz_request(message):
        return _build_quiz_disabled_response(session_id)
    memory, intent, previous_topic, topics, retrieval, references = _prepare_knowledge_turn(
        message,
        session_id=session_id,
        history=history,
        limit=limit,
    )
    answer, generation = _generate_answer(message, intent, topics, references, memory, use_llm=use_llm)
    response = _build_knowledge_response(
        message=message,
        session_id=session_id,
        memory=memory,
        intent=intent,
        previous_topic=previous_topic,
        topics=topics,
        retrieval=retrieval,
        references=references,
        answer=answer,
        generation=generation,
    )
    # Keep the legacy education API free of unified-assistant routing metadata.
    # The unified entry points still expose these fields for orchestration.
    for key in ("workflow_mode", "routing_decision", "route_decision"):
        response.pop(key, None)
    return response


def unified_anti_fraud_chat(
    message: str,
    *,
    session_id: str | None = None,
    history: Optional[List[Dict[str, Any]]] = None,
    use_llm: bool = True,
    limit: int = 8,
) -> Dict[str, Any]:
    message = (message or "").strip()
    session_id = session_id or str(uuid.uuid4())
    if _is_quiz_request(message):
        return _annotate_knowledge_unified(
            _build_quiz_disabled_response(session_id),
            {
                "primary_intent": "anti_fraud_qa",
                "workflow_mode": "knowledge_answer",
                "confidence": 1.0,
                "reason": "quiz feature disabled",
                "risk_signals": {},
                "routing_decision": {"target": "knowledge_answer", "force_high_risk": False, "prefill_slots": {}},
            },
        )
    route_decision = _route_with_knowledge_dialogue_context(
        _route_for_unified_assistant(message, session_id, history=history),
        session_id,
    )
    knowledge_turn_semantics = _knowledge_turn_semantics_for_service(message, session_id, route_decision)
    if knowledge_turn_semantics.get("is_post_completion_idle"):
        return _build_post_knowledge_idle_response(session_id, route_decision, message)
    continue_knowledge_dialogue = _should_continue_knowledge_dialogue(message, session_id, route_decision)
    if _should_enter_risk_dissuasion(route_decision) and not continue_knowledge_dialogue:
        from app.modules.emergency_dissuasion.service import build_emergency_sync_result, run_emergency_graph

        update_task_status(session_id, TASK_STATUS_PROCESSING, False)
        run_emergency_graph(
            session_id,
            message,
            False,
            route_decision.get("primary_intent") or INTENT_RISK_HELP,
            route_decision_override=route_decision,
            history_override=history,
        )
        return _annotate_risk_unified(build_emergency_sync_result(session_id), route_decision)

    if _should_enter_lightweight_specialty(route_decision):
        return _annotate_specialty_unified(
            _run_unified_specialty_flow(
                message,
                session_id=session_id,
                history=history,
                route_decision=route_decision,
                is_stream=False,
            ),
            route_decision,
        )

    if _should_answer_as_smalltalk(route_decision) and not continue_knowledge_dialogue:
        return _build_smalltalk_unified_response(session_id, route_decision)

    response = _run_knowledge_dialogue_flow(
        message,
        session_id=session_id,
        history=history,
        route_decision=route_decision,
        use_llm=use_llm,
        limit=limit,
    )
    return _annotate_knowledge_unified(response, route_decision)
