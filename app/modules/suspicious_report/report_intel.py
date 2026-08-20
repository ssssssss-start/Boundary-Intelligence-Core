from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List


def report_intel_dir() -> Path:
    return Path(__file__).resolve().parents[3] / "data" / "report_intel"


@lru_cache(maxsize=32)
def load_report_intel_json(file_name: str) -> Any:
    path = report_intel_dir() / file_name
    if not path.exists():
        return [] if file_name.endswith(".json") else None
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _as_list(value: Any) -> List[Dict[str, Any]]:
    return value if isinstance(value, list) else []


def _as_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def report_scam_types() -> List[Dict[str, Any]]:
    return _as_list(load_report_intel_json("scam_types.json"))


def report_risk_phrases() -> List[Dict[str, Any]]:
    return _as_list(load_report_intel_json("risk_phrases.json"))


def report_rule_combos() -> List[Dict[str, Any]]:
    return _as_list(load_report_intel_json("rule_combos.json"))


def report_url_rules() -> List[Dict[str, Any]]:
    return _as_list(load_report_intel_json("url_rules.json"))


def report_domain_allowlist() -> List[Dict[str, Any]]:
    return _as_list(load_report_intel_json("domain_allowlist.json"))


def report_domain_watchlist() -> Dict[str, Any]:
    return _as_dict(load_report_intel_json("domain_watchlist.json"))


def report_evidence_requirements() -> List[Dict[str, Any]]:
    return _as_list(load_report_intel_json("evidence_requirements.json"))


def report_negative_samples() -> List[Dict[str, Any]]:
    return _as_list(load_report_intel_json("negative_samples.json"))


def report_display_policy() -> Dict[str, Any]:
    return _as_dict(load_report_intel_json("display_policy.json"))


def report_source_registry() -> List[Dict[str, Any]]:
    return _as_list(load_report_intel_json("source_registry.json"))


@lru_cache(maxsize=1)
def report_scam_type_names() -> Dict[str, str]:
    return {
        str(item.get("scam_id") or ""): str(item.get("name") or "")
        for item in report_scam_types()
        if item.get("scam_id") and item.get("name")
    }


@lru_cache(maxsize=1)
def report_scam_type_aliases() -> Dict[str, List[str]]:
    result: Dict[str, List[str]] = {}
    for item in report_scam_types():
        scam_id = str(item.get("scam_id") or "")
        if not scam_id:
            continue
        aliases = [str(alias) for alias in item.get("aliases") or [] if alias]
        name = str(item.get("name") or "")
        if name:
            aliases.append(name)
        result[scam_id] = aliases
    return result


def scam_type_by_id(scam_id: str) -> Dict[str, Any]:
    target = str(scam_id or "")
    for item in report_scam_types():
        if str(item.get("scam_id") or "") == target:
            return item
    return {}


def scam_name(scam_id: str) -> str:
    return report_scam_type_names().get(str(scam_id or ""), "")


def advice_for_scam_ids(scam_ids: List[str]) -> List[str]:
    result: List[str] = []
    for scam_id in scam_ids:
        item = scam_type_by_id(scam_id)
        for advice in item.get("default_advices") or []:
            text = str(advice or "").strip()
            if text and text not in result:
                result.append(text)
    return result


def evidence_for_scam_ids(scam_ids: List[str]) -> List[str]:
    result: List[str] = []
    for scam_id in scam_ids:
        item = scam_type_by_id(scam_id)
        for evidence in item.get("evidence_hint") or []:
            text = str(evidence or "").strip()
            if text and text not in result:
                result.append(text)
    return result


def evidence_requirements_for_scam_ids(scam_ids: List[str]) -> List[Dict[str, Any]]:
    ids = {str(item or "") for item in scam_ids if item}
    return [
        item
        for item in report_evidence_requirements()
        if str(item.get("scam_id") or "") in ids
    ]


def scam_ids_from_names(names: List[str]) -> List[str]:
    targets = {str(item or "").strip() for item in names if str(item or "").strip()}
    result: List[str] = []
    for item in report_scam_types():
        scam_id = str(item.get("scam_id") or "")
        name = str(item.get("name") or "")
        aliases = {str(alias or "") for alias in item.get("aliases") or [] if alias}
        if scam_id and (name in targets or aliases & targets):
            result.append(scam_id)
    return result


def source_refs_for_scam_ids(scam_ids: List[str]) -> List[Dict[str, Any]]:
    ids = {str(item or "") for item in scam_ids if item}
    source_ids: List[str] = []
    for scam_type in report_scam_types():
        if str(scam_type.get("scam_id") or "") not in ids:
            continue
        for source_id in scam_type.get("source_refs") or []:
            text = str(source_id or "").strip()
            if text and text not in source_ids:
                source_ids.append(text)

    registry = {str(item.get("source_id") or ""): item for item in report_source_registry()}
    return [registry[source_id] for source_id in source_ids if source_id in registry]


def display_empty_text(key: str, default: str = "") -> str:
    empty_text = report_display_policy().get("empty_text") or {}
    return str(empty_text.get(key) or default)


def clear_report_intel_cache() -> None:
    load_report_intel_json.cache_clear()
    report_scam_type_names.cache_clear()
    report_scam_type_aliases.cache_clear()


def validate_report_intel() -> List[str]:
    errors: List[str] = []
    required_files = [
        "scam_types.json",
        "risk_phrases.json",
        "url_rules.json",
        "rule_combos.json",
        "domain_allowlist.json",
        "domain_watchlist.json",
        "negative_samples.json",
        "evidence_requirements.json",
        "display_policy.json",
        "source_registry.json",
    ]
    for file_name in required_files:
        path = report_intel_dir() / file_name
        if not path.exists():
            errors.append(f"缺少举报研判数据文件：{file_name}")

    scam_ids = {str(item.get("scam_id") or "") for item in report_scam_types() if item.get("scam_id")}
    if not scam_ids:
        errors.append("scam_types.json 不能为空")

    for item in report_risk_phrases():
        if not item.get("feature_id"):
            errors.append("risk_phrases.json 存在缺少 feature_id 的条目")
        scam_id = str(item.get("scam_id") or "")
        if scam_id and scam_id not in scam_ids:
            errors.append(f"话术特征引用未知 scam_id：{scam_id}")
        if not item.get("feature_name"):
            errors.append(f"话术特征缺少 feature_name：{item.get('feature_id', '')}")

    feature_names = {str(item.get("feature_name") or "") for item in report_risk_phrases() if item.get("feature_name")}
    feature_names.update(str(item.get("feature_name") or "") for item in report_url_rules() if item.get("feature_name"))
    for item in report_rule_combos():
        scam_id = str(item.get("scam_id") or "")
        if scam_id and scam_id not in scam_ids:
            errors.append(f"组合规则引用未知 scam_id：{scam_id}")
        conditions = item.get("conditions") or {}
        for feature in list(conditions.get("all") or []) + list(conditions.get("any") or []):
            if str(feature or "") not in feature_names:
                errors.append(f"组合规则 {item.get('rule_id', '')} 引用未知特征：{feature}")

    return errors
