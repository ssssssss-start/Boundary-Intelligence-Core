"""Runtime rule configuration management for the anti-fraud engine.

The rule engine reads JSON Scam Packages from ``rules/scam_packages``.  This
manager provides the write-side operations used by admin APIs and tests:
validate, upsert, hot reload, list backups, and rollback.
"""

from __future__ import annotations

import json
import re
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List

from app.anti_fraud.schema import RISK_FEATURES
from app.query_process.services.scam_rule_engine import (
    normalize_intervention_goal,
    reload_rule_config,
    risk_level_from_score,
    rule_config_root,
)


HOT_RULE_PACKAGE_ID = "runtime_hot_rules"
HOT_RULE_PACKAGE_NAME = "运行时热更新规则"


def _now_token() -> str:
    return datetime.now().strftime("%Y%m%dT%H%M%S%f")


def _safe_id(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError("配置缺少 scam_id 或 package_id")
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", text)
    if safe in {".", ".."} or not safe:
        raise ValueError(f"非法配置 ID：{value}")
    return safe


def _package_dir() -> Path:
    path = rule_config_root() / "scam_packages"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _backup_root() -> Path:
    path = rule_config_root() / "rule_backups" / "scam_packages"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _package_path(package_id: str) -> Path:
    return _package_dir() / f"{_safe_id(package_id)}.json"


def _read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _backup_existing(path: Path, package_id: str) -> str:
    if not path.exists():
        return ""
    backup_dir = _backup_root() / _safe_id(package_id)
    backup_dir.mkdir(parents=True, exist_ok=True)
    backup_path = backup_dir / f"{_now_token()}__{path.name}"
    shutil.copy2(path, backup_path)
    return f"{_safe_id(package_id)}/{backup_path.name}"


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _score(rule: Dict[str, Any]) -> int:
    try:
        score = int(float(rule.get("risk_score", rule.get("score", 0)) or 0))
    except (TypeError, ValueError):
        raise ValueError(f"规则 {rule.get('rule_id', '')} 分数必须是数字")
    if score < 0 or score > 100:
        raise ValueError(f"规则 {rule.get('rule_id', '')} 分数必须在 0-100")
    return score


def _validate_keyword_groups(rule_id: str, groups: Iterable[Any]) -> None:
    for index, group in enumerate(groups, start=1):
        words = [str(word).strip() for word in _as_list(group) if str(word).strip()]
        if not words:
            raise ValueError(f"规则 {rule_id} 的 must_include_any 第 {index} 组不能为空")


def _validate_rule(rule: Dict[str, Any], package_features: set[str]) -> None:
    if not isinstance(rule, dict):
        raise ValueError("规则必须是对象")
    rule_id = str(rule.get("rule_id") or "").strip()
    if not rule_id:
        raise ValueError("规则缺少 rule_id")
    if not str(rule.get("fraud_type") or rule.get("risk_scene") or "").strip():
        raise ValueError(f"规则 {rule_id} 缺少 fraud_type/risk_scene")
    _score(rule)

    conditions = rule.get("conditions") or {}
    if not isinstance(conditions, dict):
        raise ValueError(f"规则 {rule_id} conditions 必须是对象")
    if not any(conditions.get(key) for key in ["all", "any", "must_include_any", "must_include_all", "include_any"]):
        raise ValueError(f"规则 {rule_id} 至少需要一个条件组")

    allowed_features = set(RISK_FEATURES) | package_features
    for key in ["all", "any"]:
        for feature in conditions.get(key) or []:
            if feature not in allowed_features:
                raise ValueError(f"规则 {rule_id} 使用未知风险特征：{feature}")
    _validate_keyword_groups(rule_id, conditions.get("must_include_any") or [])


def _normalize_rule(rule: Dict[str, Any], default_fraud_type: str) -> Dict[str, Any]:
    doc = dict(rule)
    score = _score(doc)
    fraud_type = str(doc.get("fraud_type") or doc.get("risk_scene") or default_fraud_type).strip()
    doc["fraud_type"] = fraud_type
    doc.setdefault("rule_name", f"{fraud_type}配置化规则")
    doc["risk_score"] = score
    doc["score"] = score
    doc["risk_level"] = str(doc.get("risk_level") or doc.get("min_level") or risk_level_from_score(score))
    doc["intervention_goal"] = normalize_intervention_goal(doc.get("intervention_goal") or doc.get("intervention_action") or "ask_clarification")
    doc["suggested_action"] = str(
        doc.get("suggested_action")
        or doc.get("dissuasion_text")
        or doc.get("intervention_text")
        or doc.get("reply_template")
        or ""
    )
    doc.setdefault("explanation", "")
    doc.setdefault("enabled", True)
    return doc


def normalize_scam_package(package: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(package, dict):
        raise ValueError("规则配置包必须是对象")
    scam_id = _safe_id(package.get("scam_id") or package.get("package_id"))
    name = str(package.get("name") or package.get("risk_scene") or "").strip()
    if not name:
        raise ValueError("配置包缺少 name/risk_scene")

    features = []
    for item in package.get("features") or []:
        if not isinstance(item, dict) or not str(item.get("feature_name") or "").strip():
            raise ValueError("features 中每项都必须包含 feature_name")
        feature = dict(item)
        feature["keywords"] = [str(word).strip() for word in _as_list(feature.get("keywords")) if str(word).strip()]
        feature["weight"] = int(feature.get("weight", 20) or 20)
        features.append(feature)

    package_features = {str(item.get("feature_name")) for item in features}
    rules = []
    for rule in package.get("rules") or []:
        _validate_rule(rule, package_features)
        rules.append(_normalize_rule(rule, name))
    if not rules:
        raise ValueError("配置包至少需要一条规则")

    aliases = [str(item).strip() for item in _as_list(package.get("aliases")) if str(item).strip()]
    if name not in aliases:
        aliases.insert(0, name)

    return {
        **package,
        "scam_id": scam_id,
        "name": name,
        "version": str(package.get("version") or _now_token()),
        "aliases": aliases,
        "features": features,
        "rules": rules,
        "updated_at": datetime.now().isoformat(timespec="seconds"),
    }


def list_scam_package_configs() -> Dict[str, Any]:
    items: List[Dict[str, Any]] = []
    for path in sorted(_package_dir().glob("*.json")):
        try:
            data = _read_json(path)
        except Exception as exc:
            items.append({"path": str(path), "load_error": str(exc)})
            continue
        items.append(
            {
                "scam_id": data.get("scam_id", path.stem),
                "name": data.get("name", ""),
                "version": data.get("version", ""),
                "rule_count": len(data.get("rules") or []),
                "feature_count": len(data.get("features") or []),
                "path": str(path),
            }
        )
    return {"items": items, "total": len(items), "rules_dir": str(rule_config_root())}


def upsert_scam_package_config(package: Dict[str, Any], *, hot_reload: bool = True) -> Dict[str, Any]:
    normalized = normalize_scam_package(package)
    package_id = normalized["scam_id"]
    path = _package_path(package_id)
    backup_id = _backup_existing(path, package_id)
    _write_json(path, normalized)
    reload_result = reload_rule_config() if hot_reload else {}
    return {
        "message": "规则配置包已保存",
        "package_id": package_id,
        "path": str(path),
        "backup_id": backup_id,
        "rule_count": len(normalized.get("rules") or []),
        "hot_reloaded": bool(hot_reload),
        "reload": reload_result,
    }


def upsert_hot_rule_config(rule: Dict[str, Any], *, hot_reload: bool = True) -> Dict[str, Any]:
    package_id = HOT_RULE_PACKAGE_ID
    path = _package_path(package_id)
    if path.exists():
        package = _read_json(path)
    else:
        package = {
            "scam_id": package_id,
            "name": HOT_RULE_PACKAGE_NAME,
            "version": "1.0",
            "aliases": [],
            "features": [],
            "rules": [],
        }

    rule_id = str(rule.get("rule_id") or "").strip()
    if not rule_id:
        raise ValueError("热更新规则缺少 rule_id")
    existing = [item for item in package.get("rules") or [] if item.get("rule_id") != rule_id]
    existing.append(rule)
    package["rules"] = existing
    package["version"] = _now_token()
    return upsert_scam_package_config(package, hot_reload=hot_reload)


def list_rule_config_backups(package_id: str | None = None) -> Dict[str, Any]:
    root = _backup_root()
    items: List[Dict[str, Any]] = []
    package_dirs = [root / _safe_id(package_id)] if package_id else [path for path in sorted(root.iterdir()) if path.is_dir()]
    for package_dir in package_dirs:
        if not package_dir.exists():
            continue
        for path in sorted(package_dir.glob("*.json"), reverse=True):
            items.append(
                {
                    "backup_id": f"{package_dir.name}/{path.name}",
                    "package_id": package_dir.name,
                    "path": str(path),
                    "created_at": datetime.fromtimestamp(path.stat().st_mtime).isoformat(timespec="seconds"),
                }
            )
    return {"items": items, "total": len(items)}


def rollback_rule_config(backup_id: str, *, hot_reload: bool = True) -> Dict[str, Any]:
    parts = [part for part in str(backup_id or "").replace("\\", "/").split("/") if part]
    if len(parts) != 2:
        raise ValueError("backup_id 必须形如 package_id/file.json")
    package_id = _safe_id(parts[0])
    filename = _safe_id(parts[1])
    backup_path = _backup_root() / package_id / filename
    if not backup_path.exists():
        raise FileNotFoundError(f"备份不存在：{backup_id}")

    target = _package_path(package_id)
    current_backup_id = _backup_existing(target, package_id)
    shutil.copy2(backup_path, target)
    reload_result = reload_rule_config() if hot_reload else {}
    return {
        "message": "规则配置已回滚",
        "package_id": package_id,
        "restored_from": backup_id,
        "current_backup_id": current_backup_id,
        "path": str(target),
        "hot_reloaded": bool(hot_reload),
        "reload": reload_result,
    }
