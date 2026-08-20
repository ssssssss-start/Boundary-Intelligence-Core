"""Validate the structured anti-fraud knowledge base.

Run:
    uv run python scripts/validate_knowledge.py
"""

from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List


ROOT = Path(__file__).resolve().parents[1]
KNOWLEDGE_DIR = ROOT / "data" / "knowledge"

FILES = {
    "scam_types": "scam_types.json",
    "scam_features": "scam_features.json",
    "risk_rules": "risk_rules.json",
    "semantic_risk_policy": "semantic_risk_policy.json",
    "knowledge_dialogue_policy": "knowledge_dialogue_policy.json",
    "official_sources": "official_sources.json",
    "prevention_advice": "prevention_advice.json",
    "typical_cases": "typical_cases.json",
    "law_clauses": "law_clauses.json",
    "report_guides": "report_guides.json",
    "stage_definitions": "stage_definitions.json",
    "evidence_guides": "evidence_guides.json",
}

REQUIRED_FIELDS = {
    "scam_types": [
        "scam_id",
        "name",
        "aliases",
        "description",
        "common_channels",
        "target_users",
        "default_risk_level",
        "typical_stages",
        "primary_intervention_goals",
        "critical_facts",
        "loss_signals",
        "one_sentence_rule",
        "risk_formula",
    ],
    "scam_features": [
        "feature_id",
        "scam_id",
        "feature_name",
        "keywords",
        "risk_weight",
        "stage",
        "intervention_goal",
        "explanation",
        "evidence_extract_hint",
    ],
    "risk_rules": [
        "rule_id",
        "fraud_type",
        "stages",
        "conditions",
        "condition_schema_version",
        "semantic_condition_groups",
        "feature_conditions",
        "risk_score",
        "risk_level",
        "intervention_goal",
        "explanation",
        "escalation_policy",
    ],
    "semantic_risk_policy": ["policy_id", "policy_type", "title", "enabled", "priority"],
    "knowledge_dialogue_policy": ["policy_id", "policy_type", "title", "enabled", "priority"],
    "official_sources": [
        "source_id",
        "title",
        "url",
        "authority",
        "source_type",
        "domains",
        "last_checked",
        "used_for",
        "coverage",
        "source_refs",
    ],
    "prevention_advice": [
        "advice_id",
        "fraud_type",
        "risk_stage",
        "intervention_goal",
        "advice",
        "do",
        "dont",
        "official_verification_methods",
        "common_misconceptions",
    ],
    "typical_cases": [
        "case_id",
        "fraud_type",
        "risk_stage",
        "summary",
        "key_pattern",
        "lesson",
        "privacy_level",
        "use_when",
    ],
    "law_clauses": [
        "law_id",
        "topic",
        "related_behaviors",
        "related_scam_types",
        "plain_summary",
        "actions",
        "evidence_to_preserve",
        "disclaimer",
    ],
    "report_guides": [
        "guide_id",
        "input_type",
        "fraud_type",
        "required_fields",
        "suggested_summary_template",
        "evidence_checklist",
        "next_actions",
    ],
    "stage_definitions": ["stage_id", "name", "description"],
    "evidence_guides": [
        "guide_id",
        "fraud_type",
        "scenario",
        "evidence_items",
        "collection_tips",
        "warning",
    ],
}

ID_FIELDS = {
    "scam_types": "scam_id",
    "scam_features": "feature_id",
    "risk_rules": "rule_id",
    "semantic_risk_policy": "policy_id",
    "knowledge_dialogue_policy": "policy_id",
    "official_sources": "source_id",
    "prevention_advice": "advice_id",
    "typical_cases": "case_id",
    "law_clauses": "law_id",
    "report_guides": "guide_id",
    "stage_definitions": "stage_id",
    "evidence_guides": "guide_id",
}

def _load_json(name: str, file_name: str, errors: List[str]) -> List[Dict[str, Any]]:
    path = KNOWLEDGE_DIR / file_name
    if not path.exists():
        errors.append(f"缺少文件：{path}")
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{file_name} JSON 格式非法：{exc}")
        return []
    if not isinstance(data, list):
        errors.append(f"{file_name} 顶层必须是数组")
        return []
    rows = [item for item in data if isinstance(item, dict)]
    if len(rows) != len(data):
        errors.append(f"{file_name} 只能包含对象元素")
    return rows


def _missing_fields(row: Dict[str, Any], required: Iterable[str]) -> List[str]:
    missing: List[str] = []
    for field in required:
        value = row.get(field)
        if value is None or value == "" or value == [] or value == {}:
            missing.append(field)
    return missing


def _duplicates(rows: List[Dict[str, Any]], field: str) -> List[str]:
    values = [str(item.get(field)) for item in rows if item.get(field)]
    return [value for value, count in Counter(values).items() if count > 1]


def _validate_required_fields(data: Dict[str, List[Dict[str, Any]]], errors: List[str]) -> None:
    for name, rows in data.items():
        required = REQUIRED_FIELDS[name]
        id_field = ID_FIELDS[name]
        for index, row in enumerate(rows):
            missing = _missing_fields(row, required)
            if missing:
                errors.append(f"{FILES[name]} 第 {index + 1} 条 {row.get(id_field, '')} 缺少字段：{missing}")


def _validate_unique_ids(data: Dict[str, List[Dict[str, Any]]], errors: List[str]) -> None:
    for name, rows in data.items():
        id_field = ID_FIELDS[name]
        dupes = _duplicates(rows, id_field)
        if dupes:
            errors.append(f"{FILES[name]} {id_field} 重复：{dupes}")


def _validate_cross_references(data: Dict[str, List[Dict[str, Any]]], errors: List[str]) -> None:
    scam_ids = {item["scam_id"] for item in data["scam_types"] if item.get("scam_id")}
    fraud_types = {item["name"] for item in data["scam_types"] if item.get("name")}
    fraud_types.add("通用")

    for feature in data["scam_features"]:
        if feature.get("scam_id") not in scam_ids:
            errors.append(f"scam_features {feature.get('feature_id')} scam_id 不存在：{feature.get('scam_id')}")

    for collection in ["risk_rules", "prevention_advice", "typical_cases", "report_guides", "evidence_guides"]:
        for row in data[collection]:
            fraud_type = row.get("fraud_type")
            if fraud_type and fraud_type not in fraud_types:
                errors.append(f"{FILES[collection]} {row.get(ID_FIELDS[collection], '')} fraud_type 未在 scam_types 中定义：{fraud_type}")


def _validate_feature_coverage(data: Dict[str, List[Dict[str, Any]]], errors: List[str]) -> None:
    counts: Dict[str, int] = defaultdict(int)
    for feature in data["scam_features"]:
        counts[str(feature.get("scam_id"))] += 1
    for scam in data["scam_types"]:
        scam_id = scam.get("scam_id")
        if counts[scam_id] < 5:
            errors.append(f"scam_types {scam_id} 至少需要 5 个 scam_features，当前 {counts[scam_id]}")


def _validate_source_refs(data: Dict[str, List[Dict[str, Any]]], errors: List[str]) -> None:
    for name, rows in data.items():
        id_field = ID_FIELDS[name]
        for row in rows:
            if not row.get("source_refs"):
                errors.append(f"{FILES[name]} {row.get(id_field, '')} 缺少 source_refs")


def _validate_official_source_registry(data: Dict[str, List[Dict[str, Any]]], errors: List[str]) -> None:
    sources = data.get("official_sources") or []
    urls = {str(row.get("url") or "").strip() for row in sources if row.get("url")}
    source_ids = {str(row.get("source_id") or "").strip() for row in sources if row.get("source_id")}
    if len(urls) != len(sources):
        errors.append("official_sources.json url 存在重复或空值")
    if len(source_ids) != len(sources):
        errors.append("official_sources.json source_id 存在重复或空值")

    for row in sources:
        url = str(row.get("url") or "").strip()
        if not url.startswith("https://"):
            errors.append(f"official_sources {row.get('source_id')} url 必须使用 https：{url}")
        if row.get("source_refs") != [url]:
            errors.append(f"official_sources {row.get('source_id')} source_refs 应只登记自身 url")

    unregistered_refs = []
    for name, rows in data.items():
        if name == "official_sources":
            continue
        id_field = ID_FIELDS[name]
        for row in rows:
            for ref in row.get("source_refs") or []:
                ref = str(ref or "").strip()
                if ref.startswith("http") and ref not in urls:
                    unregistered_refs.append(f"{FILES[name]} {row.get(id_field, '')}: {ref}")
    if unregistered_refs:
        errors.append(f"存在未登记的官方来源 source_refs：{unregistered_refs[:20]}")


def _validate_teaching_policy_coverage(data: Dict[str, List[Dict[str, Any]]], errors: List[str]) -> None:
    scam_ids = {item["scam_id"] for item in data["scam_types"] if item.get("scam_id")}
    fraud_types = {item["name"] for item in data["scam_types"] if item.get("name")}
    policies_by_type: Dict[str, int] = defaultdict(int)
    for policy in data["knowledge_dialogue_policy"]:
        if policy.get("policy_type") != "scam_teaching_path":
            continue
        fraud_type = policy.get("fraud_type")
        scam_id = policy.get("scam_id")
        if fraud_type not in fraud_types:
            errors.append(f"knowledge_dialogue_policy {policy.get('policy_id')} fraud_type 未定义：{fraud_type}")
        if scam_id not in scam_ids:
            errors.append(f"knowledge_dialogue_policy {policy.get('policy_id')} scam_id 不存在：{scam_id}")
        if not policy.get("stage_goals") or not policy.get("one_sentence_rule"):
            errors.append(f"knowledge_dialogue_policy {policy.get('policy_id')} 缺少 stage_goals 或 one_sentence_rule")
        if fraud_type:
            policies_by_type[str(fraud_type)] += 1
    for fraud_type in fraud_types:
        if policies_by_type[fraud_type] < 1:
            errors.append(f"诈骗类型 {fraud_type} 缺少 knowledge_dialogue_policy 教学路径")


def _validate_final_coverage(data: Dict[str, List[Dict[str, Any]]], errors: List[str]) -> None:
    fraud_types = [item["name"] for item in data["scam_types"] if item.get("name")]
    coverage_requirements = {
        "prevention_advice": 3,
        "typical_cases": 3,
        "report_guides": 1,
        "evidence_guides": 1,
        "risk_rules": 1,
    }
    for collection, minimum in coverage_requirements.items():
        counts = Counter(row.get("fraud_type") for row in data[collection])
        for fraud_type in fraud_types:
            if counts[fraud_type] < minimum:
                errors.append(
                    f"{FILES[collection]} {fraud_type} 覆盖不足：至少 {minimum} 条，当前 {counts[fraud_type]}"
                )

    for scam in data["scam_types"]:
        if len(scam.get("critical_facts") or []) < 3:
            errors.append(f"scam_types {scam.get('scam_id')} critical_facts 至少需要 3 条")
        if len(scam.get("loss_signals") or []) < 3:
            errors.append(f"scam_types {scam.get('scam_id')} loss_signals 至少需要 3 条")


def _validate_rule_condition_schema(data: Dict[str, List[Dict[str, Any]]], errors: List[str]) -> None:
    feature_names = {row.get("feature_name") for row in data["scam_features"]}
    for rule in data["risk_rules"]:
        if rule.get("condition_schema_version") != "v2":
            errors.append(f"risk_rules {rule.get('rule_id')} condition_schema_version 必须为 v2")
        groups = rule.get("semantic_condition_groups")
        if not isinstance(groups, list) or not groups:
            errors.append(f"risk_rules {rule.get('rule_id')} 缺少 semantic_condition_groups")
            continue
        for group in groups:
            if group.get("operator") not in {"all", "any"}:
                errors.append(f"risk_rules {rule.get('rule_id')} 存在非法 condition operator：{group.get('operator')}")
            if not isinstance(group.get("terms"), list):
                errors.append(f"risk_rules {rule.get('rule_id')} condition terms 必须为数组")
        feature_conditions = rule.get("feature_conditions")
        if not isinstance(feature_conditions, dict):
            errors.append(f"risk_rules {rule.get('rule_id')} feature_conditions 必须为对象")
        conditions = rule.get("conditions") or {}
        semantic_terms = set(rule.get("semantic_conditions") or [])
        fact_terms = set(rule.get("fact_conditions") or [])
        action_terms = set(rule.get("action_conditions") or [])
        for term in [*(conditions.get("all") or []), *(conditions.get("any") or [])]:
            if term not in feature_names and term not in semantic_terms and term not in fact_terms and term not in action_terms:
                errors.append(f"risk_rules {rule.get('rule_id')} 引用了未注册特征：{term}")


def _validate_law_scam_coverage(data: Dict[str, List[Dict[str, Any]]], errors: List[str]) -> None:
    fraud_types = {item["name"] for item in data["scam_types"] if item.get("name")}
    covered = set()
    for law in data["law_clauses"]:
        for fraud_type in law.get("related_scam_types") or []:
            if fraud_type not in fraud_types:
                errors.append(f"law_clauses {law.get('law_id')} related_scam_types 未定义：{fraud_type}")
            else:
                covered.add(fraud_type)
    missing = sorted(fraud_types - covered)
    if missing:
        errors.append(f"law_clauses 未覆盖诈骗类型：{missing}")


def validate() -> int:
    errors: List[str] = []
    data = {name: _load_json(name, file_name, errors) for name, file_name in FILES.items()}
    if errors:
        for error in errors:
            print(f"[ERROR] {error}")
        return 1

    _validate_required_fields(data, errors)
    _validate_unique_ids(data, errors)
    _validate_cross_references(data, errors)
    _validate_feature_coverage(data, errors)
    _validate_source_refs(data, errors)
    _validate_official_source_registry(data, errors)
    _validate_teaching_policy_coverage(data, errors)
    _validate_final_coverage(data, errors)
    _validate_rule_condition_schema(data, errors)
    _validate_law_scam_coverage(data, errors)

    if errors:
        for error in errors:
            print(f"[ERROR] {error}")
        return 1

    total = sum(len(rows) for rows in data.values())
    print(f"知识库校验通过：{len(data)} 个文件，{total} 条记录。")
    return 0


if __name__ == "__main__":
    sys.exit(validate())
