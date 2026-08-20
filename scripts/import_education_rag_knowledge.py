"""Import an isolated education RAG knowledge base.

This script prepares data for the "智能反诈助手" module only. It does not write
to the realtime/emergency dissuasion collections. The Mongo collections created
here intentionally use the ``education_`` prefix, and the Milvus collection is
separate from ``anti_fraud_knowledge``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List

from dotenv import load_dotenv
from pymongo import ASCENDING, DESCENDING, ReplaceOne


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

KNOWLEDGE_DIR = PROJECT_ROOT / "data" / "knowledge"
V2_KNOWLEDGE_PATH = PROJECT_ROOT / "data" / "anti_fraud_knowledge_v2.json"

NAMESPACE = "knowledge_assistant_education"
DEFAULT_EDUCATION_MILVUS_COLLECTION = "anti_fraud_education_knowledge"

MONGO_COLLECTIONS = {
    "scam_types": "education_scam_types",
    "intent_patterns": "education_intent_patterns",
    "rag_documents": "education_rag_documents",
    "rag_chunks": "education_rag_chunks",
    "law_clauses": "education_law_clauses",
    "official_sources": "education_official_sources",
    "import_meta": "education_import_meta",
}

PROTECTED_MONGO_COLLECTIONS = [
    "anti_fraud_knowledge",
    "rag_documents",
    "rag_chunks",
    "scam_types",
    "scam_features",
    "risk_rules",
    "prevention_advice",
    "typical_cases",
    "law_clauses",
    "report_guides",
    "stage_definitions",
    "evidence_guides",
    "anti_fraud_session_state",
    "anti_fraud_case_state",
    "anti_fraud_case_event",
]

EDUCATION_V2_KNOWLEDGE_TYPES = {
    "fraud_definition",
    "fraud_process",
    "risk_signal",
    "prevention_advice",
    "fraud_case",
    "education_summary",
}


def load_json(path: Path) -> List[Dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError(f"{path} top-level JSON must be a list")
    return [item for item in data if isinstance(item, dict)]


def join_values(values: Iterable[Any], sep: str = "、") -> str:
    return sep.join(str(value) for value in values if str(value).strip())


def safe_id(prefix: str, raw: str, max_len: int = 120) -> str:
    value = "".join(ch if ch.isalnum() or ch in {"_", "-"} else "_" for ch in raw)
    value = "_".join(part for part in value.split("_") if part)
    candidate = f"{prefix}_{value}".strip("_")
    if len(candidate) <= max_len:
        return candidate
    digest = hashlib.blake2b(candidate.encode("utf-8"), digest_size=6).hexdigest()
    return f"{candidate[: max_len - len(digest) - 1]}_{digest}"


def make_doc(
    *,
    doc_id: str,
    doc_type: str,
    fraud_type: str,
    title: str,
    summary: str,
    content: str,
    keywords: List[str] | None = None,
    aliases: List[str] | None = None,
    target_users: List[str] | None = None,
    source_dataset: str,
    source_ids: List[str] | None = None,
    priority: int = 50,
) -> Dict[str, Any]:
    now = datetime.now().isoformat(timespec="seconds")
    return {
        "namespace": NAMESPACE,
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
        "assistant_module": "knowledge_assistant",
        "rag_scope": "anti_fraud_education",
        "created_at": now,
        "updated_at": now,
    }


def split_chunks(doc: Dict[str, Any], max_chars: int = 1400) -> List[Dict[str, Any]]:
    paragraphs = [line.strip() for line in doc["content"].splitlines() if line.strip()]
    if not paragraphs:
        paragraphs = [doc["summary"]]

    chunks: List[str] = []
    current: List[str] = []
    current_len = 0
    for paragraph in paragraphs:
        projected = current_len + len(paragraph) + 1
        if current and projected > max_chars:
            chunks.append("\n".join(current))
            current = [paragraph]
            current_len = len(paragraph)
        else:
            current.append(paragraph)
            current_len = projected
    if current:
        chunks.append("\n".join(current))

    now = datetime.now().isoformat(timespec="seconds")
    rows: List[Dict[str, Any]] = []
    for index, text in enumerate(chunks):
        chunk_id = safe_id("edu_chunk", f"{doc['doc_id']}_{index}")
        rows.append(
            {
                "namespace": NAMESPACE,
                "chunk_id": chunk_id,
                "doc_id": doc["doc_id"],
                "chunk_index": index,
                "chunk_text": text,
                "title": doc["title"],
                "summary": doc["summary"],
                "fraud_type": doc["fraud_type"],
                "doc_type": doc["doc_type"],
                "keywords": doc.get("keywords", []),
                "aliases": doc.get("aliases", []),
                "target_users": doc.get("target_users", []),
                "source_dataset": doc.get("source_dataset", ""),
                "priority": doc.get("priority", 50),
                "assistant_module": "knowledge_assistant",
                "rag_scope": "anti_fraud_education",
                "created_at": now,
                "updated_at": now,
            }
        )
    return rows


def build_structured_documents() -> Dict[str, List[Dict[str, Any]]]:
    scam_types = load_json(KNOWLEDGE_DIR / "scam_types.json")
    scam_features = load_json(KNOWLEDGE_DIR / "scam_features.json")
    risk_rules = load_json(KNOWLEDGE_DIR / "risk_rules.json")
    prevention_advice = load_json(KNOWLEDGE_DIR / "prevention_advice.json")
    typical_cases = load_json(KNOWLEDGE_DIR / "typical_cases.json")
    law_clauses = load_json(KNOWLEDGE_DIR / "law_clauses.json")
    report_guides = load_json(KNOWLEDGE_DIR / "report_guides.json")
    evidence_guides = load_json(KNOWLEDGE_DIR / "evidence_guides.json")

    features_by_scam: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for feature in scam_features:
        features_by_scam[str(feature.get("scam_id") or "")].append(feature)

    advice_by_type: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for advice in prevention_advice:
        advice_by_type[str(advice.get("fraud_type") or "")].append(advice)

    cases_by_type: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for case in typical_cases:
        cases_by_type[str(case.get("fraud_type") or "")].append(case)

    rules_by_type: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for rule in risk_rules:
        rules_by_type[str(rule.get("fraud_type") or "")].append(rule)

    reports_by_type: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for guide in report_guides:
        reports_by_type[str(guide.get("fraud_type") or "")].append(guide)

    evidence_by_type: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for guide in evidence_guides:
        evidence_by_type[str(guide.get("fraud_type") or "")].append(guide)

    documents: List[Dict[str, Any]] = []
    intent_patterns: List[Dict[str, Any]] = []

    for scam in scam_types:
        scam_id = str(scam.get("scam_id") or "")
        name = str(scam.get("name") or "")
        aliases = list(scam.get("aliases") or [])
        channels = list(scam.get("common_channels") or [])
        targets = list(scam.get("target_users") or [])
        stages = list(scam.get("typical_stages") or [])
        features = features_by_scam.get(scam_id, [])
        feature_keywords = sorted(
            {
                keyword
                for feature in features
                for keyword in (feature.get("keywords") or [])
                if keyword
            }
        )
        feature_names = [str(feature.get("feature_name") or "") for feature in features if feature.get("feature_name")]
        profile_terms = [
            str(scam.get("one_sentence_rule") or ""),
            str(scam.get("risk_formula") or ""),
            *[str(item) for item in (scam.get("critical_facts") or [])],
            *[str(item) for item in (scam.get("loss_signals") or [])],
        ]
        keywords = sorted({name, *aliases, *feature_keywords, *feature_names, *profile_terms})

        definition = "\n".join(
            [
                f"诈骗类型：{name}",
                f"常见叫法：{join_values(aliases) or '暂无'}",
                f"重点人群：{join_values(targets) or '泛个人用户'}",
                f"常见渠道：{join_values(channels) or '社交平台、短信、电话或陌生网页'}",
                f"核心说明：{scam.get('description') or ''}",
                f"一句话识别：{scam.get('one_sentence_rule') or ''}",
                f"风险组合：{scam.get('risk_formula') or ''}",
                f"关键确认事实：{join_values(scam.get('critical_facts') or [])}",
                f"损失/暴露信号：{join_values(scam.get('loss_signals') or [])}",
                f"典型阶段：{join_values(stages) or '接触、建立信任、提出危险要求、造成损失'}",
                "科普边界：本条用于知识讲解、识别方法和防范学习，不承载现场劝阻流程。",
            ]
        )
        documents.append(
            make_doc(
                doc_id=safe_id("edu_doc", f"{scam_id}_definition"),
                doc_type="scam_definition",
                fraud_type=name,
                title=f"什么是{name}",
                summary=str(scam.get("description") or "")[:180],
                content=definition,
                keywords=keywords,
                aliases=aliases,
                target_users=targets,
                source_dataset="data/knowledge/scam_types.json",
                source_ids=[scam_id],
                priority=95,
            )
        )

        stage_rows: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for feature in features:
            stage_rows[str(feature.get("stage") or "常见特征")].append(feature)
        process_lines = [f"{name}常见流程："]
        for stage in stages or sorted(stage_rows):
            names = [str(item.get("feature_name") or "") for item in stage_rows.get(stage, []) if item.get("feature_name")]
            process_lines.append(f"- {stage}：{join_values(names) or '通过话术或场景推进下一步'}")
        process_lines.append("学习提示：多类骗局会复用同一套推进方式，例如先建立信任，再提出转账、扫码、下载 App 或提供信息等要求。")
        documents.append(
            make_doc(
                doc_id=safe_id("edu_doc", f"{scam_id}_process"),
                doc_type="scam_process",
                fraud_type=name,
                title=f"{name}的一般套路",
                summary=f"按阶段理解{name}如何从接触推进到风险动作。",
                content="\n".join(process_lines),
                keywords=keywords,
                aliases=aliases,
                target_users=targets,
                source_dataset="data/knowledge/scam_types.json+scam_features.json",
                source_ids=[scam_id] + [str(item.get("feature_id")) for item in features if item.get("feature_id")],
                priority=90,
            )
        )

        feature_lines = [f"{name}的识别特征："]
        for feature in features:
            feature_lines.append(
                "- "
                + f"{feature.get('feature_name')}：{feature.get('explanation')} "
                + f"常见关键词：{join_values(feature.get('keywords') or [])}。"
            )
        documents.append(
            make_doc(
                doc_id=safe_id("edu_doc", f"{scam_id}_features"),
                doc_type="scam_features",
                fraud_type=name,
                title=f"{name}怎么识别",
                summary=f"整理{name}的高频关键词、话术和阶段特征。",
                content="\n".join(feature_lines),
                keywords=keywords,
                aliases=aliases,
                target_users=targets,
                source_dataset="data/knowledge/scam_features.json",
                source_ids=[str(item.get("feature_id")) for item in features if item.get("feature_id")],
                priority=92,
            )
        )

        advice_rows = advice_by_type.get(name, [])
        if advice_rows:
            advice_lines = [f"{name}防范建议："]
            source_ids = []
            for advice in advice_rows:
                source_ids.append(str(advice.get("advice_id")))
                advice_lines.extend(
                    [
                        f"- 核心建议：{advice.get('advice')}",
                        f"- 应该做：{join_values(advice.get('do') or [])}",
                        f"- 不要做：{join_values(advice.get('dont') or [])}",
                        f"- 官方核验：{join_values(advice.get('official_verification_methods') or [])}",
                        f"- 常见误区：{join_values(advice.get('common_misconceptions') or [])}",
                    ]
                )
            documents.append(
                make_doc(
                    doc_id=safe_id("edu_doc", f"{scam_id}_prevention"),
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

        case_rows = cases_by_type.get(name, [])
        if case_rows:
            case_lines = [f"{name}典型案例讲解："]
            source_ids = []
            for case in case_rows:
                source_ids.append(str(case.get("case_id")))
                case_lines.extend(
                    [
                        f"- 案例概述：{case.get('summary')}",
                        f"- 关键套路：{case.get('key_pattern')}",
                        f"- 学习提醒：{case.get('lesson')}",
                    ]
                )
            documents.append(
                make_doc(
                    doc_id=safe_id("edu_doc", f"{scam_id}_case"),
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

        rule_rows = rules_by_type.get(name, [])
        if rule_rows:
            rule_lines = [f"{name}规则化风险推理材料："]
            source_ids = []
            for rule in rule_rows:
                source_ids.append(str(rule.get("rule_id")))
                rule_lines.extend(
                    [
                        f"- 规则：{rule.get('rule_id')} / {rule.get('risk_level')} / {rule.get('risk_score')}分",
                        f"- 适用阶段：{join_values(rule.get('stages') or [])}",
                        f"- 条件：{json.dumps(rule.get('conditions') or {}, ensure_ascii=False)}",
                        f"- 结构化条件：{json.dumps(rule.get('semantic_condition_groups') or [], ensure_ascii=False)}",
                        f"- 处置目标：{rule.get('intervention_goal')}",
                        f"- 推理说明：{rule.get('explanation')}",
                    ]
                )
            documents.append(
                make_doc(
                    doc_id=safe_id("edu_doc", f"{scam_id}_risk_rules"),
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
                        f"- 必要信息：{join_values(guide.get('required_fields') or [])}",
                        f"- 摘要模板：{guide.get('suggested_summary_template')}",
                        f"- 证据清单：{join_values(guide.get('evidence_checklist') or [])}",
                        f"- 下一步：{join_values(guide.get('next_actions') or [])}",
                    ]
                )
            documents.append(
                make_doc(
                    doc_id=safe_id("edu_doc", f"{scam_id}_report_guide"),
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
                        f"- 证据项：{join_values(guide.get('evidence_items') or [])}",
                        f"- 取证提示：{join_values(guide.get('collection_tips') or [])}",
                        f"- 风险提醒：{guide.get('warning')}",
                    ]
                )
            documents.append(
                make_doc(
                    doc_id=safe_id("edu_doc", f"{scam_id}_evidence_guide"),
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

        stage_patterns = {}
        for stage, rows in stage_rows.items():
            stage_patterns[stage] = sorted(
                {
                    keyword
                    for row in rows
                    for keyword in (row.get("keywords") or [])
                    if keyword
                }
            )
        intent_patterns.append(
            {
                "namespace": NAMESPACE,
                "pattern_id": safe_id("edu_intent", scam_id),
                "scam_id": scam_id,
                "fraud_type": name,
                "aliases": aliases,
                "keywords": keywords,
                "target_users": targets,
                "common_channels": channels,
                "stage_patterns": stage_patterns,
                "assistant_module": "knowledge_assistant",
                "rag_scope": "anti_fraud_education",
                "updated_at": datetime.now().isoformat(timespec="seconds"),
            }
        )

    for law in law_clauses:
        topic = str(law.get("topic") or "")
        content = "\n".join(
            [
                f"主题：{topic}",
                f"相关行为：{join_values(law.get('related_behaviors') or [])}",
                f"相关诈骗类型：{join_values(law.get('related_scam_types') or [])}",
                f"通俗说明：{law.get('plain_summary') or ''}",
                f"一般动作：{join_values(law.get('actions') or [])}",
                f"建议保留材料：{join_values(law.get('evidence_to_preserve') or [])}",
                f"提示：{law.get('disclaimer') or '以下为一般科普，不替代专业法律意见。'}",
            ]
        )
        documents.append(
            make_doc(
                doc_id=safe_id("edu_doc", f"{law.get('law_id')}_law"),
                doc_type="law_clause",
                fraud_type="通用法律法规与处置常识",
                title=topic,
                summary=str(law.get("plain_summary") or "")[:180],
                content=content,
                keywords=list(law.get("related_behaviors") or []) + [topic],
                aliases=[],
                target_users=["学生", "泛个人用户"],
                source_dataset="data/knowledge/law_clauses.json",
                source_ids=[str(law.get("law_id"))],
                priority=75,
            )
        )

    return {
        "scam_types": scam_types,
        "intent_patterns": intent_patterns,
        "rag_documents": documents,
        "law_clauses": law_clauses,
    }


def build_v2_documents() -> List[Dict[str, Any]]:
    rows = load_json(V2_KNOWLEDGE_PATH)
    documents: List[Dict[str, Any]] = []
    for row in rows:
        knowledge_type = str(row.get("knowledge_type") or "")
        if knowledge_type not in EDUCATION_V2_KNOWLEDGE_TYPES:
            continue
        risk_tags = list(row.get("risk_tags") or [])
        fraud_type = str(row.get("fraud_type") or "")
        title = str(row.get("title") or "")
        content = "\n".join(
            [
                f"标题：{title}",
                f"诈骗类型：{fraud_type}",
                f"知识类型：{knowledge_type}",
                f"摘要：{row.get('summary') or ''}",
                f"适用学习场景：{row.get('use_when') or ''}",
                f"正文：{row.get('content') or ''}",
            ]
        )
        documents.append(
            make_doc(
                doc_id=safe_id("edu_v2", str(row.get("knowledge_id") or title)),
                doc_type=knowledge_type,
                fraud_type=fraud_type,
                title=title,
                summary=str(row.get("summary") or "")[:220],
                content=content,
                keywords=risk_tags + [fraud_type, title],
                aliases=[],
                target_users=["学生", "泛个人用户"],
                source_dataset="data/anti_fraud_knowledge_v2.json",
                source_ids=[str(row.get("knowledge_id") or "")],
                priority=int(row.get("priority") or 60),
            )
        )
    return documents


def build_source_documents(official_sources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    documents: List[Dict[str, Any]] = []
    for source in official_sources:
        source_id = str(source.get("source_id") or "")
        title = str(source.get("title") or "")
        authority = str(source.get("authority") or "")
        url = str(source.get("url") or "")
        domains = list(source.get("domains") or [])
        used_for = list(source.get("used_for") or [])
        content = "\n".join(
            [
                f"官方来源：{title}",
                f"来源机构：{authority}",
                f"来源类型：{source.get('source_type') or ''}",
                f"链接：{url}",
                f"覆盖领域：{join_values(domains)}",
                f"用于支撑：{join_values(used_for)}",
                f"覆盖说明：{source.get('coverage') or ''}",
                f"最近核验日期：{source.get('last_checked') or ''}",
            ]
        )
        documents.append(
            make_doc(
                doc_id=safe_id("edu_source", source_id or title),
                doc_type="official_source",
                fraud_type="通用法律法规与处置常识",
                title=f"官方来源：{title}",
                summary=str(source.get("coverage") or "")[:220],
                content=content,
                keywords=[title, authority, url, *domains, *used_for, "官方来源", "引用来源", "资料来源"],
                aliases=[],
                target_users=["学生", "泛个人用户"],
                source_dataset="data/knowledge/official_sources.json",
                source_ids=[source_id],
                priority=72,
            )
        )
    return documents


def build_bundle() -> Dict[str, List[Dict[str, Any]]]:
    structured = build_structured_documents()
    official_sources_path = KNOWLEDGE_DIR / "official_sources.json"
    official_sources = load_json(official_sources_path) if official_sources_path.exists() else []
    documents = structured["rag_documents"] + build_v2_documents() + build_source_documents(official_sources)
    chunks: List[Dict[str, Any]] = []
    for doc in documents:
        chunks.extend(split_chunks(doc))
    return {
        "scam_types": structured["scam_types"],
        "intent_patterns": structured["intent_patterns"],
        "rag_documents": documents,
        "rag_chunks": chunks,
        "law_clauses": structured["law_clauses"],
        "official_sources": official_sources,
    }


def load_mongo_tool():
    from app.clients.mongo_business_utils import get_business_mongo_tool

    return get_business_mongo_tool()


def protected_counts(db) -> Dict[str, int]:
    return {name: db[name].count_documents({}) for name in PROTECTED_MONGO_COLLECTIONS}


def assert_protected_unchanged(before: Dict[str, int], after: Dict[str, int]) -> None:
    changed = {
        name: {"before": before.get(name), "after": after.get(name)}
        for name in PROTECTED_MONGO_COLLECTIONS
        if before.get(name) != after.get(name)
    }
    if changed:
        raise RuntimeError(f"Protected emergency/shared collections changed unexpectedly: {changed}")


def ensure_mongo_indexes(db) -> None:
    db[MONGO_COLLECTIONS["scam_types"]].create_index([("namespace", ASCENDING), ("scam_id", ASCENDING)], unique=True)
    db[MONGO_COLLECTIONS["scam_types"]].create_index([("namespace", ASCENDING), ("name", ASCENDING)])
    db[MONGO_COLLECTIONS["intent_patterns"]].create_index([("namespace", ASCENDING), ("pattern_id", ASCENDING)], unique=True)
    db[MONGO_COLLECTIONS["intent_patterns"]].create_index([("namespace", ASCENDING), ("fraud_type", ASCENDING)])
    db[MONGO_COLLECTIONS["rag_documents"]].create_index([("namespace", ASCENDING), ("doc_id", ASCENDING)], unique=True)
    db[MONGO_COLLECTIONS["rag_documents"]].create_index([("namespace", ASCENDING), ("fraud_type", ASCENDING), ("doc_type", ASCENDING)])
    db[MONGO_COLLECTIONS["rag_documents"]].create_index([("namespace", ASCENDING), ("priority", DESCENDING)])
    db[MONGO_COLLECTIONS["rag_chunks"]].create_index([("namespace", ASCENDING), ("chunk_id", ASCENDING)], unique=True)
    db[MONGO_COLLECTIONS["rag_chunks"]].create_index([("namespace", ASCENDING), ("doc_id", ASCENDING), ("chunk_index", ASCENDING)])
    db[MONGO_COLLECTIONS["rag_chunks"]].create_index([("namespace", ASCENDING), ("fraud_type", ASCENDING), ("doc_type", ASCENDING)])
    db[MONGO_COLLECTIONS["law_clauses"]].create_index([("namespace", ASCENDING), ("law_id", ASCENDING)], unique=True)
    db[MONGO_COLLECTIONS["official_sources"]].create_index([("namespace", ASCENDING), ("source_id", ASCENDING)], unique=True)
    db[MONGO_COLLECTIONS["official_sources"]].create_index([("namespace", ASCENDING), ("url", ASCENDING)])
    db[MONGO_COLLECTIONS["official_sources"]].create_index([("namespace", ASCENDING), ("authority", ASCENDING)])
    db[MONGO_COLLECTIONS["import_meta"]].create_index([("namespace", ASCENDING), ("imported_at", DESCENDING)])


def with_namespace(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    enriched = []
    now = datetime.now().isoformat(timespec="seconds")
    for row in rows:
        doc = dict(row)
        doc["namespace"] = NAMESPACE
        doc["assistant_module"] = "knowledge_assistant"
        doc["rag_scope"] = "anti_fraud_education"
        doc["updated_at"] = now
        doc.setdefault("created_at", now)
        enriched.append(doc)
    return enriched


def replace_many(db, collection: str, rows: List[Dict[str, Any]], key_field: str) -> int:
    db[collection].delete_many({"namespace": NAMESPACE})
    if not rows:
        return 0
    operations = [
        ReplaceOne({"namespace": NAMESPACE, key_field: row[key_field]}, row, upsert=True)
        for row in rows
    ]
    result = db[collection].bulk_write(operations, ordered=False)
    return int(result.upserted_count + result.modified_count + result.matched_count)


def import_mongo(bundle: Dict[str, List[Dict[str, Any]]]) -> Dict[str, int]:
    tool = load_mongo_tool()
    db = tool.db
    before = protected_counts(db)
    ensure_mongo_indexes(db)

    counts = {
        "education_scam_types": replace_many(
            db,
            MONGO_COLLECTIONS["scam_types"],
            with_namespace(bundle["scam_types"]),
            "scam_id",
        ),
        "education_intent_patterns": replace_many(
            db,
            MONGO_COLLECTIONS["intent_patterns"],
            bundle["intent_patterns"],
            "pattern_id",
        ),
        "education_rag_documents": replace_many(
            db,
            MONGO_COLLECTIONS["rag_documents"],
            bundle["rag_documents"],
            "doc_id",
        ),
        "education_rag_chunks": replace_many(
            db,
            MONGO_COLLECTIONS["rag_chunks"],
            bundle["rag_chunks"],
            "chunk_id",
        ),
        "education_law_clauses": replace_many(
            db,
            MONGO_COLLECTIONS["law_clauses"],
            with_namespace(bundle["law_clauses"]),
            "law_id",
        ),
        "education_official_sources": replace_many(
            db,
            MONGO_COLLECTIONS["official_sources"],
            with_namespace(bundle.get("official_sources", [])),
            "source_id",
        ),
    }

    meta = {
        "namespace": NAMESPACE,
        "assistant_module": "knowledge_assistant",
        "rag_scope": "anti_fraud_education",
        "imported_at": datetime.now().isoformat(timespec="seconds"),
        "counts": counts,
        "source_files": [
            "data/knowledge/scam_types.json",
            "data/knowledge/scam_features.json",
            "data/knowledge/risk_rules.json",
            "data/knowledge/prevention_advice.json",
            "data/knowledge/typical_cases.json",
            "data/knowledge/law_clauses.json",
            "data/knowledge/report_guides.json",
            "data/knowledge/evidence_guides.json",
            "data/knowledge/official_sources.json",
            "data/anti_fraud_knowledge_v2.json",
        ],
        "protected_collections_checked": PROTECTED_MONGO_COLLECTIONS,
    }
    db[MONGO_COLLECTIONS["import_meta"]].insert_one(meta)

    after = protected_counts(db)
    assert_protected_unchanged(before, after)
    return counts


def education_milvus_collection_name() -> str:
    return os.getenv("ANTI_FRAUD_EDUCATION_COLLECTION") or DEFAULT_EDUCATION_MILVUS_COLLECTION


def assert_safe_milvus_collection(collection_name: str) -> None:
    protected = {
        "anti_fraud_knowledge",
        os.getenv("ANTI_FRAUD_COLLECTION") or "",
        os.getenv("FRAUD_KNOWLEDGE_COLLECTION") or "",
    }
    protected = {item for item in protected if item}
    if collection_name in protected:
        raise RuntimeError(
            f"Refusing to use protected Milvus collection {collection_name!r}; "
            f"set ANTI_FRAUD_EDUCATION_COLLECTION to a separate name."
        )


def import_milvus(chunks: List[Dict[str, Any]], batch_size: int, embedding_backend: str | None = None) -> Dict[str, Any]:
    if embedding_backend:
        os.environ["ANTI_FRAUD_EMBEDDING_BACKEND"] = embedding_backend

    from app.clients.milvus_utils import get_milvus_client
    from app.import_process.agent.nodes.node_import_fraud_knowledge_milvus import _create_collection, _to_milvus_rows
    from app.lm.embedding_utils import generate_embeddings

    collection_name = education_milvus_collection_name()
    assert_safe_milvus_collection(collection_name)

    client = get_milvus_client()
    if client is None:
        raise RuntimeError("Milvus client initialization failed")

    if client.has_collection(collection_name=collection_name):
        client.drop_collection(collection_name=collection_name)

    imported = 0
    created = False
    backends: set[str] = set()
    for start in range(0, len(chunks), batch_size):
        raw_batch = chunks[start : start + batch_size]
        texts = []
        records = []
        for chunk in raw_batch:
            risk_tags_text = join_values(chunk.get("keywords") or [], sep=",")
            embedding_text = "\n".join(
                [
                    f"标题：{chunk.get('title', '')}",
                    f"诈骗类型：{chunk.get('fraud_type', '')}",
                    f"知识类型：{chunk.get('doc_type', '')}",
                    f"摘要：{chunk.get('summary', '')}",
                    f"关键词：{risk_tags_text}",
                    f"内容：{chunk.get('chunk_text', '')}",
                ]
            )
            texts.append(embedding_text)
            records.append(
                {
                    "knowledge_id": chunk["chunk_id"],
                    "knowledge_type": chunk["doc_type"],
                    "fraud_type": chunk["fraud_type"],
                    "title": chunk["title"],
                    "summary": chunk["summary"],
                    "risk_tags_text": risk_tags_text,
                    "priority": int(chunk.get("priority") or 50),
                }
            )

        vectors = generate_embeddings(texts)
        backends.add(str(vectors.get("embedding_backend") or "unknown"))
        dense_vectors = vectors.get("dense") or []
        sparse_vectors = vectors.get("sparse") or []
        if len(dense_vectors) != len(records) or len(sparse_vectors) != len(records):
            raise ValueError("Embedding count does not match education RAG chunk count")

        for index, record in enumerate(records):
            record["dense_vector"] = dense_vectors[index]
            record["sparse_vector"] = sparse_vectors[index]

        if not created:
            _create_collection(client, collection_name, len(dense_vectors[0]))
            created = True

        client.insert(collection_name=collection_name, data=_to_milvus_rows(records))
        imported += len(records)
        print(f"Milvus education RAG batch imported: {imported}/{len(chunks)}")

    try:
        client.flush(collection_name=collection_name)
    except Exception:
        pass
    stats = client.get_collection_stats(collection_name) if client.has_collection(collection_name) else {}
    return {
        "collection_name": collection_name,
        "imported_count": imported,
        "row_count": stats.get("row_count"),
        "embedding_backends": sorted(backends),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Import isolated education RAG knowledge for the knowledge assistant.")
    parser.add_argument("--dry-run", action="store_true", help="Build and print counts without writing databases.")
    parser.add_argument("--skip-milvus", action="store_true", help="Only write the isolated Mongo education collections.")
    parser.add_argument("--milvus-batch-size", type=int, default=24)
    parser.add_argument(
        "--embedding-backend",
        default="",
        help="Optional embedding backend override, for example 'hash' for deterministic local vectors.",
    )
    args = parser.parse_args()

    load_dotenv(PROJECT_ROOT / ".env")
    bundle = build_bundle()
    counts = {key: len(value) for key, value in bundle.items()}
    print(f"Prepared education RAG bundle: {counts}")
    print(f"Mongo target collections: {MONGO_COLLECTIONS}")
    print(f"Milvus target collection: {education_milvus_collection_name()}")

    if args.dry_run:
        return 0

    mongo_counts = import_mongo(bundle)
    print(f"Mongo import completed: {mongo_counts}")

    if args.skip_milvus:
        print("Milvus import skipped.")
        return 0

    milvus_result = import_milvus(
        bundle["rag_chunks"],
        batch_size=max(1, int(args.milvus_batch_size or 24)),
        embedding_backend=args.embedding_backend or None,
    )
    print(f"Milvus import completed: {milvus_result}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
