"""Curated official video-link cards for the anti-fraud chat.

This module is deliberately additive: it never generates or edits the answer
text.  A response can be decorated with ``video_cards`` after the existing
knowledge or risk workflow has completed.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlparse

from pymongo import DESCENDING, ReturnDocument

from app.anti_fraud.taxonomy import fraud_type_id_for, standard_name_for
from app.clients.mongo_business_utils import get_business_mongo_tool, write_audit_log
from app.clients.mongo_history_utils import get_history_mongo_tool


logger = logging.getLogger(__name__)

VIDEO_STATUSES = {"draft", "pending_review", "published", "disabled", "expired"}
VIDEO_SCENES = {"knowledge", "risk"}
PUBLIC_VIDEO_FIELDS = (
    "video_id",
    "scam_id",
    "scam_name",
    "title",
    "cover_url",
    "source_url",
    "platform",
    "publisher",
    "official_account",
    "duration_seconds",
    "orientation",
    "label",
    "source_published_at",
)


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _text(value: Any) -> str:
    return str(value or "").strip()


def _dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _valid_http_url(value: Any) -> bool:
    parsed = urlparse(_text(value))
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return default


def _route_decision(response: Dict[str, Any]) -> Dict[str, Any]:
    summary = _dict(response.get("summary"))
    return _dict(response.get("route_decision")) or _dict(summary.get("route_decision"))


def _response_mode(response: Dict[str, Any]) -> str:
    summary = _dict(response.get("summary"))
    route = _route_decision(response)
    assistant_mode = _text(response.get("assistant_mode") or summary.get("assistant_mode"))
    workflow_mode = _text(
        response.get("workflow_mode")
        or summary.get("workflow_mode")
        or route.get("workflow_mode")
    )
    if assistant_mode == "risk_dissuasion" or workflow_mode == "risk_case_flow":
        return "risk"
    if workflow_mode in {"knowledge_answer", "knowledge_dialogue_flow"} or assistant_mode in {
        "knowledge_education",
        "knowledge_assistant",
    }:
        return "knowledge"
    return ""


def _candidate_values(response: Dict[str, Any]) -> Iterable[Any]:
    summary = _dict(response.get("summary"))
    route = _route_decision(response)
    engine = _dict(response.get("anti_fraud_engine")) or _dict(summary.get("anti_fraud_engine"))
    scam_understanding = _dict(summary.get("scam_understanding"))
    risk = _dict(summary.get("risk"))
    topics = response.get("topics") or summary.get("topics") or []

    yield response.get("scam_id")
    yield response.get("fraud_type_id")
    yield response.get("fraud_type")
    yield response.get("scam_type")
    yield summary.get("scam_id")
    yield summary.get("fraud_type_id")
    yield summary.get("fraud_type")
    yield summary.get("scam_type")
    yield route.get("fraud_type_id")
    yield route.get("normalized_topic")
    yield scam_understanding.get("scam_id")
    yield scam_understanding.get("primary_scam_type")
    yield scam_understanding.get("primary_scam_type_name")
    yield risk.get("scam_id")
    yield risk.get("fraud_type_id")
    yield risk.get("fraud_type")
    yield engine.get("scam_id")
    yield engine.get("fraud_type_id")
    yield engine.get("fraud_type")
    yield engine.get("risk_scene_name")

    for topic in topics if isinstance(topics, list) else []:
        if isinstance(topic, dict):
            yield topic.get("scam_id")
            yield topic.get("fraud_type_id")
            yield topic.get("fraud_type")
            yield topic.get("name")
        else:
            yield topic


def resolve_response_scam_id(response: Dict[str, Any]) -> str:
    for value in _candidate_values(response):
        if isinstance(value, dict):
            for nested in ("scam_id", "fraud_type_id", "fraud_type", "scam_type", "name", "label"):
                resolved = fraud_type_id_for(value.get(nested))
                if resolved:
                    return resolved
            continue
        resolved = fraud_type_id_for(value)
        if resolved:
            return resolved
    return ""


def _public_card(document: Dict[str, Any]) -> Dict[str, Any]:
    return {
        key: document.get(key)
        for key in PUBLIC_VIDEO_FIELDS
        if document.get(key) not in (None, "")
    }


def _normalise_card(payload: Dict[str, Any], *, existing: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    base = dict(existing or {})
    base.update({key: value for key, value in _dict(payload).items() if value is not None})
    video_id = _text(base.get("video_id"))
    if not video_id:
        raise ValueError("video_id is required")

    raw_scam_id = _text(base.get("scam_id") or base.get("fraud_type_id") or base.get("scam_name"))
    scam_id = fraud_type_id_for(raw_scam_id)
    if not scam_id:
        raise ValueError("scam_id must match the anti-fraud taxonomy")

    status = _text(base.get("status") or "draft")
    if status not in VIDEO_STATUSES:
        raise ValueError(f"unsupported video status: {status}")

    source_url = _text(base.get("source_url"))
    cover_url = _text(base.get("cover_url"))
    if source_url and not _valid_http_url(source_url):
        raise ValueError("source_url must be an absolute http(s) URL")
    if cover_url and not _valid_http_url(cover_url):
        raise ValueError("cover_url must be an absolute http(s) URL")

    usage_policy = {
        "direct_link_allowed": False,
        "embed_allowed": False,
        "download_allowed": False,
        **_dict(base.get("usage_policy")),
    }
    display_policy = {
        "knowledge_auto": True,
        "risk_auto": True,
        **_dict(base.get("display_policy")),
    }
    now = _now()
    document = {
        **base,
        "video_id": video_id,
        "scam_id": scam_id,
        "scam_name": standard_name_for(scam_id),
        "title": _text(base.get("title")),
        "cover_url": cover_url,
        "source_url": source_url,
        "platform": _text(base.get("platform")),
        "publisher": _text(base.get("publisher")),
        "official_account": _text(base.get("official_account")),
        "duration_seconds": _as_int(base.get("duration_seconds")),
        "orientation": _text(base.get("orientation") or "vertical"),
        "label": _text(base.get("label") or "官方反诈视频"),
        "usage_policy": usage_policy,
        "display_policy": display_policy,
        "status": status,
        "source_check_status": _text(base.get("source_check_status") or "unchecked"),
        "rights_status": _text(base.get("rights_status") or "unknown"),
        "priority": _as_int(base.get("priority")),
        "updated_at": now,
    }
    document.setdefault("created_at", now)

    if status == "published":
        if not document["title"] or not source_url or not cover_url:
            raise ValueError("published videos require title, source_url and cover_url")
        if document["source_check_status"] != "passed":
            raise ValueError("published videos require source_check_status=passed")
        if not bool(usage_policy.get("direct_link_allowed")):
            raise ValueError("published videos require direct_link_allowed=true")
    return document


def upsert_video_card(payload: Dict[str, Any], actor: str = "admin") -> Dict[str, Any]:
    tool = get_business_mongo_tool()
    existing = tool.db["risk_video_cards"].find_one({"video_id": _text(payload.get("video_id"))})
    document = _normalise_card(payload, existing=existing)
    document["updated_by"] = actor or "admin"
    document.pop("_id", None)
    tool.db["risk_video_cards"].update_one(
        {"video_id": document["video_id"]},
        {"$set": document},
        upsert=True,
    )
    write_audit_log(
        "risk_video_card_upsert",
        {"video_id": document["video_id"], "status": document["status"], "actor": actor or "admin"},
    )
    return get_video_card(document["video_id"], public=False) or document


def get_video_card(video_id: str, *, public: bool = True) -> Optional[Dict[str, Any]]:
    tool = get_business_mongo_tool()
    projection = {"_id": 0}
    document = tool.db["risk_video_cards"].find_one({"video_id": _text(video_id)}, projection)
    if not document:
        return None
    if public:
        if not _is_public_document(document):
            return None
        return _public_card(document)
    return document


def _is_public_document(document: Dict[str, Any], scene: str = "") -> bool:
    if _text(document.get("status")) != "published":
        return False
    if _text(document.get("source_check_status")) != "passed":
        return False
    if not bool(_dict(document.get("usage_policy")).get("direct_link_allowed")):
        return False
    if not _valid_http_url(document.get("source_url")) or not _valid_http_url(document.get("cover_url")):
        return False
    if scene and not bool(_dict(document.get("display_policy")).get(f"{scene}_auto")):
        return False
    return True


def list_video_cards(
    *,
    scam_id: str = "",
    status: str = "",
    scene: str = "",
    limit: int = 50,
    public: bool = False,
) -> List[Dict[str, Any]]:
    tool = get_business_mongo_tool()
    query: Dict[str, Any] = {}
    if scam_id:
        resolved = fraud_type_id_for(scam_id)
        if not resolved:
            return []
        query["scam_id"] = resolved
    if status:
        query["status"] = status
    if public:
        query.update(
            {
                "status": "published",
                "source_check_status": "passed",
                "usage_policy.direct_link_allowed": True,
                "cover_url": {"$exists": True, "$nin": [None, ""]},
                "source_url": {"$exists": True, "$nin": [None, ""]},
            }
        )
        if scene:
            query[f"display_policy.{scene}_auto"] = True
    limit = max(1, min(int(limit or 50), 100))
    documents = list(
        tool.db["risk_video_cards"]
        .find(query, {"_id": 0})
        .sort([("priority", DESCENDING), ("updated_at", DESCENDING)])
        .limit(limit)
    )
    if public:
        return [_public_card(item) for item in documents if _is_public_document(item, scene)]
    return documents


def update_video_card_status(video_id: str, status: str, actor: str = "admin") -> Dict[str, Any]:
    if status not in VIDEO_STATUSES:
        raise ValueError(f"unsupported video status: {status}")
    current = get_video_card(video_id, public=False)
    if not current:
        raise ValueError("video card not found")
    payload = dict(current)
    payload["status"] = status
    payload.pop("_id", None)
    result = upsert_video_card(payload, actor=actor)
    write_audit_log(
        "risk_video_card_status",
        {"video_id": video_id, "status": status, "actor": actor or "admin"},
    )
    return result


def _claim_delivery(session_id: str, scene: str, scam_id: str, video_id: str) -> bool:
    if not session_id:
        return False
    tool = get_history_mongo_tool()
    if tool is None:
        return False
    key = f"{scene}:{scam_id}"
    record = {
        "key": key,
        "scene": scene,
        "scam_id": scam_id,
        "video_id": video_id,
        "shown_at": _now(),
    }
    try:
        result = tool.session_state.find_one_and_update(
            {"session_id": session_id, "video_delivery_keys": {"$ne": key}},
            {
                "$addToSet": {"video_delivery_keys": key},
                "$push": {"video_delivery_records": record},
                "$set": {"updated_at": _now()},
            },
            upsert=True,
            return_document=ReturnDocument.AFTER,
        )
        return bool(result and key in (result.get("video_delivery_keys") or []))
    except Exception as exc:
        logger.warning("video delivery claim failed: %s", exc)
        return False


def attach_video_cards(
    response: Dict[str, Any],
    session_id: str = "",
    *,
    scene: str = "",
    force: bool = False,
) -> Dict[str, Any]:
    """Return the original response with an optional ``video_cards`` field.

    All failures are contained so a MongoDB or source-data problem cannot
    change the existing answer path.
    """
    original = dict(response or {})
    try:
        existing_cards = original.get("video_cards")
        if isinstance(existing_cards, list) and existing_cards:
            return original
        summary_cards = _dict(original.get("summary")).get("video_cards")
        if isinstance(summary_cards, list) and summary_cards:
            original["video_cards"] = summary_cards
            return original
        resolved_scene = scene or _response_mode(original)
        if resolved_scene not in VIDEO_SCENES:
            return original
        scam_id = resolve_response_scam_id(original)
        if not scam_id:
            return original
        cards = list_video_cards(scam_id=scam_id, scene=resolved_scene, limit=1, public=True)
        if not cards:
            return original
        selected = cards[0]
        if not force and not _claim_delivery(session_id, resolved_scene, scam_id, selected.get("video_id", "")):
            return original
        original["video_cards"] = cards
        return original
    except Exception as exc:
        logger.warning("attach video cards skipped: %s", exc)
        return original


def public_video_cards(scam_id: str, scene: str = "", limit: int = 3) -> List[Dict[str, Any]]:
    if scene and scene not in VIDEO_SCENES:
        raise ValueError("scene must be knowledge or risk")
    return list_video_cards(scam_id=scam_id, scene=scene, limit=limit, public=True)
