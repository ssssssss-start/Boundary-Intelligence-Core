from __future__ import annotations

import hashlib
import re
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List

from app.clients.mongo_business_utils import (
    count_report_tickets_for_day,
    create_report_analysis_draft,
    create_report_ticket,
    get_report_analysis_draft,
    update_report_analysis_draft,
    write_audit_log,
)
from app.modules.suspicious_report.report_intel import (
    advice_for_scam_ids,
    report_display_policy,
    scam_ids_from_names,
    source_refs_for_scam_ids,
)
from app.modules.suspicious_report.rules import (
    analyze_keyword_blacklist,
    analyze_url_features,
    build_report_advice,
    build_report_evidence,
    classify_suspicious_type,
    sanitize_content_urls,
    score_suspicious_item,
)
from app.modules.report_intel_tool.llm_judge import UNKNOWN_SCAM_TYPE, analyze_report_semantics
from app.report_process.services.desensitize_service import desensitize_text
from app.query_process.services.scam_rule_engine import risk_level_from_score


_MEMORY_DRAFTS: Dict[str, Dict[str, Any]] = {}
_DRAFT_TTL_HOURS = 24


def _now() -> datetime:
    return datetime.now()


def _iso(value: datetime) -> str:
    return value.isoformat(timespec="seconds")


def _sha256_text(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


def _analysis_id() -> str:
    return f"RA-{_now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:10].upper()}"


def _next_report_id() -> str:
    day_text = _now().strftime("%Y%m%d")
    try:
        seq = count_report_tickets_for_day(day_text) + 1
        return f"FS-{day_text}-{seq:05d}"
    except Exception:
        return f"FS-{day_text}-{uuid.uuid4().hex[:6].upper()}"


def _extract_phones(text: str) -> List[str]:
    values = re.findall(r"(?<!\d)1[3-9]\d{9}(?!\d)", text or "")
    return list(dict.fromkeys(desensitize_text(item) for item in values))


def _extract_accounts(text: str) -> List[str]:
    patterns = [
        r"(?:QQ|qq|QQ号|qq号)\s*[:：]?\s*\d{5,12}",
        r"(?:微信|微信号|WeChat|wechat)\s*[:：]?\s*[A-Za-z][A-Za-z0-9_-]{5,19}",
        r"(?:账号|账户)\s*[:：]?\s*[A-Za-z0-9_-]{5,24}",
    ]
    accounts: List[str] = []
    for pattern in patterns:
        accounts.extend(re.findall(pattern, text or ""))
    return list(dict.fromkeys(accounts))


def _type_parts(value: str) -> List[str]:
    return [item.strip() for item in re.split(r"[、,/，]+", str(value or "")) if item.strip()]


def _rule_labels(url_result: Dict[str, Any], keyword_result: Dict[str, Any], risk: Dict[str, Any]) -> List[str]:
    labels: List[str] = []
    for item in (
        (url_result.get("matched_rules") or [])
        + (keyword_result.get("matched_rules") or [])
        + [hit.get("label", "") for hit in risk.get("knowledge_rule_hits") or []]
    ):
        text = str(item or "").strip()
        if text and text not in labels:
            labels.append(text)
    return labels


def _hit_items(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    result: List[Dict[str, Any]] = []
    for item in items or []:
        result.append(
            {
                "id": item.get("rule_id") or item.get("feature_id") or "",
                "label": item.get("label") or item.get("display_label") or item.get("feature_name") or "",
                "feature_name": item.get("feature_name") or "",
                "evidence": item.get("evidence") or "",
                "score": int(item.get("score", 0) or 0),
                "scam_type": item.get("scam_type") or item.get("fraud_type") or "",
                "source": item.get("source") or "",
            }
        )
    return result


def _risk_copy(risk_level: str, risk_score: int) -> str:
    policy = report_display_policy().get("risk_copy") or {}
    if risk_score >= 80:
        return str(policy.get("critical") or "发现极高风险诈骗组合，请立即停止操作。")
    if risk_score >= 60:
        return str(policy.get("high") or "发现高危诈骗组合，建议停止操作并保存证据。")
    if risk_score >= 30:
        return str(policy.get("medium") or "发现多个可疑信号，继续操作前需要谨慎核实。")
    if risk_score > 0:
        return str(policy.get("low") or "发现少量可疑信号，建议先通过官方渠道核实。")
    return str(policy.get("risk_unknown") or "暂未发现足够的诈骗风险证据，不代表链接或内容一定安全。")


def _dedupe_text(items: List[Any], limit: int = 12) -> List[str]:
    result: List[str] = []
    for item in items or []:
        text = str(item or "").strip()
        if text and text not in result:
            result.append(text)
        if len(result) >= limit:
            break
    return result


def _clean_sentence(text: str) -> str:
    value = str(text or "").strip()
    if not value:
        return ""
    return value if value[-1] in "。！？!?" else f"{value}。"


def _merge_suspected_type(rule_type: str, llm_analysis: Dict[str, Any], final_score: int, rule_score: int) -> str:
    rule_type = str(rule_type or "").strip()
    llm_type = str(llm_analysis.get("suspected_type") or "").strip()
    llm_score = int(llm_analysis.get("risk_score", 0) or 0)
    if final_score < 30:
        return UNKNOWN_SCAM_TYPE
    values: List[str] = []
    for text in _type_parts(rule_type):
        if text and text != UNKNOWN_SCAM_TYPE and text not in values:
            values.append(text)
    if llm_score >= 30 or not values:
        for text in _type_parts(llm_type):
            if text and text != UNKNOWN_SCAM_TYPE and text not in values:
                values.append(text)
    if not values and rule_score >= 30 and rule_type != UNKNOWN_SCAM_TYPE:
        values.append(rule_type)
    return "、".join(values[:3]) if values else UNKNOWN_SCAM_TYPE


def _llm_scam_ids(llm_analysis: Dict[str, Any]) -> List[str]:
    values = llm_analysis.get("suspected_scam_ids") or []
    return _dedupe_text(values, limit=6)


def _display_summary(
    risk_level: str,
    risk_score: int,
    suspected_type: str,
    matched_rules: List[str],
    semantic_summary: str = "",
) -> str:
    if risk_score <= 0 or suspected_type == UNKNOWN_SCAM_TYPE:
        return "这段内容暂未发现足够的诈骗风险证据。若涉及转账、验证码、下载 App 或填写身份银行卡信息，建议再通过官方渠道核实。"
    lead = f"这段内容风险很高，疑似{suspected_type}。" if risk_score >= 80 else f"这段内容存在{suspected_type}相关风险。"
    if semantic_summary:
        return f"{lead}{_clean_sentence(semantic_summary)}"
    if matched_rules:
        return f"{lead}重点风险是：{'、'.join(matched_rules[:3])}。"
    return lead


def _source_refs(suspected_type: str) -> List[Dict[str, Any]]:
    refs: List[Dict[str, Any]] = []
    scam_ids = scam_ids_from_names(_type_parts(suspected_type))
    for item in source_refs_for_scam_ids(scam_ids):
        refs.append(
            {
                "id": item.get("source_id", ""),
                "title": item.get("name", ""),
                "summary": item.get("usage", ""),
                "url": item.get("url", ""),
                "source_type": item.get("source_type", ""),
            }
        )
    return refs


def _build_analysis_payload(
    *,
    analysis_id: str,
    raw_content: str,
    tool_session_id: str,
    created_at: datetime,
    expires_at: datetime,
) -> Dict[str, Any]:
    url_result = analyze_url_features(raw_content)
    keyword_result = analyze_keyword_blacklist(raw_content)
    risk = score_suspicious_item(url_result, keyword_result)
    rule_score = int(risk.get("risk_score", 0) or 0)
    rule_suspected_type = classify_suspicious_type(url_result, keyword_result)
    llm_analysis = analyze_report_semantics(raw_content, url_result, keyword_result, risk)
    llm_score = int(llm_analysis.get("risk_score", 0) or 0) if llm_analysis.get("status") == "completed" else 0
    risk_score = max(rule_score, llm_score)
    risk_level = risk_level_from_score(risk_score)
    suspected_type = _merge_suspected_type(rule_suspected_type, llm_analysis, risk_score, rule_score)
    semantic_hits = _hit_items(llm_analysis.get("semantic_features") or [])
    matched_rules = _dedupe_text(
        _rule_labels(url_result, keyword_result, risk)
        + [f"语义研判：{item.get('label')}" for item in semantic_hits if item.get("label")],
        limit=12,
    )
    llm_scam_ids = _llm_scam_ids(llm_analysis)
    advice = _dedupe_text(
        build_report_advice(url_result, keyword_result, risk_score)
        + (llm_analysis.get("recommended_actions") or [])
        + advice_for_scam_ids(llm_scam_ids),
        limit=6,
    )
    evidence_requirements = build_report_evidence(
        url_result,
        keyword_result,
        extra_scam_ids=_dedupe_text(scam_ids_from_names(_type_parts(suspected_type)) + llm_scam_ids, limit=8),
    )
    sanitized_content = sanitize_content_urls(desensitize_text(raw_content))
    urls = url_result.get("urls", [])
    phones = _extract_phones(raw_content)
    accounts = _extract_accounts(raw_content)

    phrase_hits = _hit_items(keyword_result.get("rule_hits") or [])
    combo_hits = _hit_items(risk.get("knowledge_rule_hits") or [])
    url_hits = _hit_items(url_result.get("rule_hits") or [])
    display_summary = _display_summary(
        risk_level,
        risk_score,
        suspected_type,
        matched_rules,
        semantic_summary=str(llm_analysis.get("reasoning_summary") or "") if llm_analysis.get("status") == "completed" else "",
    )

    report_intel = {
        "version": "report-intel-v1",
        "analysis_mode": "single_turn_content_judgement",
        "analysis_id": analysis_id,
        "status": "analyzed",
        "tool_session_id": tool_session_id,
        "report_type": "可疑链接/内容",
        "created_at": _iso(created_at),
        "expires_at": _iso(expires_at),
        "risk_level": risk_level,
        "risk_score": risk_score,
        "suspected_type": suspected_type,
        "display_summary": display_summary,
        "risk_copy": _risk_copy(risk_level, risk_score),
        "url_analysis": {
            "urls": urls,
            "rule_hits": url_hits,
            "allowlist_hits": url_result.get("allowlist_hits") or [],
            "empty_text": url_result.get("empty_text") or "",
        },
        "phrase_hits": phrase_hits,
        "semantic_hits": semantic_hits,
        "llm_analysis": llm_analysis,
        "semantic_analysis": llm_analysis,
        "combo_hits": combo_hits,
        "evidence_requirements": evidence_requirements,
        "recommended_actions": advice,
        "sources": _source_refs(suspected_type),
    }

    return {
        "analysis_id": analysis_id,
        "created_at": _iso(created_at),
        "expires_at": _iso(expires_at),
        "status": "analyzed",
        "analysis_mode": "single_turn_content_judgement",
        "tool_session_id": tool_session_id,
        "report_type": "可疑链接/内容",
        "raw_content_hash": _sha256_text(raw_content),
        "content": sanitized_content,
        "raw_user_content": sanitized_content,
        "urls": urls,
        "phones": phones,
        "accounts": accounts,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "suspected_type": suspected_type,
        "fraud_type": suspected_type,
        "scam_type": suspected_type,
        "matched_rules": matched_rules,
        "url_features": url_result,
        "keyword_blacklist": keyword_result,
        "knowledge_rules": risk.get("knowledge_rule_hits", []),
        "llm_analysis": llm_analysis,
        "semantic_analysis": llm_analysis,
        "advice": advice,
        "evidence_requirements": evidence_requirements,
        "display_summary": display_summary,
        "message": "已完成初步研判",
        "answer": display_summary,
        "report_intel": report_intel,
        "knowledge_refs": report_intel["sources"],
        "knowledge_source": "report_intel",
    }


def _store_draft(draft: Dict[str, Any]) -> tuple[str, List[str]]:
    warnings: List[str] = []
    analysis_id = str(draft.get("analysis_id") or "")
    _MEMORY_DRAFTS[analysis_id] = dict(draft)
    try:
        create_report_analysis_draft(draft)
        return "draft_saved", warnings
    except Exception as exc:
        warnings.append(f"研判草稿写入失败：{exc}")
        return "draft_memory_only", warnings


def analyze_report_content(content: str, tool_session_id: str = "") -> Dict[str, Any]:
    raw_content = str(content or "").strip()
    if not raw_content:
        raise ValueError("研判内容不能为空")

    created_at = _now()
    expires_at = created_at + timedelta(hours=_DRAFT_TTL_HOURS)
    analysis_id = _analysis_id()
    tool_id = str(tool_session_id or f"report-tool-{uuid.uuid4().hex[:10]}").strip()
    payload = _build_analysis_payload(
        analysis_id=analysis_id,
        raw_content=raw_content,
        tool_session_id=tool_id,
        created_at=created_at,
        expires_at=expires_at,
    )
    draft = {
        **payload,
        "status": "draft",
        "source": "report_intel_modal",
        "tool_source": "plus_modal",
        "expires_at_ts": expires_at,
        "confirmed": False,
    }
    status, warnings = _store_draft(draft)
    payload["status"] = status
    payload["report_intel"]["status"] = status
    if warnings:
        payload["warnings"] = warnings
    return payload


def _load_draft(analysis_id: str) -> Dict[str, Any]:
    draft = _MEMORY_DRAFTS.get(analysis_id)
    if draft:
        return dict(draft)
    try:
        stored = get_report_analysis_draft(analysis_id)
        if stored:
            _MEMORY_DRAFTS[analysis_id] = dict(stored)
            return dict(stored)
    except Exception:
        pass
    return {}


def confirm_report_analysis(analysis_id: str, tool_session_id: str = "", reporter_note: str = "") -> Dict[str, Any]:
    target_id = str(analysis_id or "").strip()
    if not target_id:
        raise ValueError("analysis_id 不能为空")

    draft = _load_draft(target_id)
    if not draft:
        raise LookupError("研判草稿不存在或已过期，请重新研判后再确认举报")

    existing_report_id = str(draft.get("report_id") or "")
    if existing_report_id and draft.get("confirmed"):
        return {
            "status": "confirmed",
            "message": "举报已确认",
            "analysis_id": target_id,
            "report_id": existing_report_id,
            "risk_level": draft.get("risk_level", ""),
            "risk_score": draft.get("risk_score", 0),
            "fraud_type": draft.get("fraud_type", ""),
            "suspected_type": draft.get("suspected_type", ""),
            "evidence_requirements": draft.get("evidence_requirements", []),
            "advice": draft.get("advice", []),
        }

    report_id = _next_report_id()
    confirmed_at = _iso(_now())
    report = {
        "report_id": report_id,
        "analysis_id": target_id,
        "created_at": confirmed_at,
        "confirmed_at": confirmed_at,
        "source": "report_intel_modal",
        "tool_source": "plus_modal",
        "tool_session_id": str(tool_session_id or draft.get("tool_session_id") or ""),
        "session_id": "",
        "report_type": draft.get("report_type") or "可疑链接/内容",
        "raw_content_hash": draft.get("raw_content_hash", ""),
        "content": draft.get("content", ""),
        "raw_user_content": draft.get("raw_user_content", ""),
        "urls": draft.get("urls", []),
        "phones": draft.get("phones", []),
        "accounts": draft.get("accounts", []),
        "risk_score": draft.get("risk_score", 0),
        "risk_level": draft.get("risk_level", ""),
        "suspected_type": draft.get("suspected_type", ""),
        "fraud_type": draft.get("fraud_type", ""),
        "scam_type": draft.get("scam_type", ""),
        "matched_rules": draft.get("matched_rules", []),
        "url_features": draft.get("url_features", {}),
        "keyword_blacklist": draft.get("keyword_blacklist", {}),
        "knowledge_rules": draft.get("knowledge_rules", []),
        "llm_analysis": draft.get("llm_analysis", {}),
        "semantic_analysis": draft.get("semantic_analysis", {}),
        "advice": draft.get("advice", []),
        "evidence_requirements": draft.get("evidence_requirements", []),
        "report_intel": draft.get("report_intel", {}),
        "knowledge_refs": draft.get("knowledge_refs", []),
        "knowledge_source": "report_intel",
        "reporter_note": str(reporter_note or "").strip(),
        "status": "confirmed",
    }

    warnings: List[str] = []
    try:
        create_report_ticket(report)
    except Exception as exc:
        warnings.append(f"正式举报记录写入失败：{exc}")
        report["status"] = "confirm_generated_not_persisted"

    update_doc = {
        "confirmed": True,
        "status": report["status"],
        "report_id": report_id,
        "confirmed_at": confirmed_at,
        "reporter_note": report["reporter_note"],
    }
    draft.update(update_doc)
    _MEMORY_DRAFTS[target_id] = draft
    try:
        update_report_analysis_draft(target_id, update_doc)
    except Exception as exc:
        warnings.append(f"研判草稿状态更新失败：{exc}")

    try:
        write_audit_log(
            "report_intel_confirm",
            {
                "analysis_id": target_id,
                "report_id": report_id,
                "tool_session_id": report["tool_session_id"],
                "risk_level": report["risk_level"],
                "risk_score": report["risk_score"],
                "fraud_type": report["fraud_type"],
            },
        )
    except Exception as exc:
        warnings.append(f"审计日志写入失败：{exc}")

    response = {
        "status": "confirmed" if report["status"] == "confirmed" else report["status"],
        "message": "举报已确认" if report["status"] == "confirmed" else "举报已确认，但正式记录暂未写入数据库",
        "analysis_id": target_id,
        "report_id": report_id,
        "confirmed_at": confirmed_at,
        "risk_level": report["risk_level"],
        "risk_score": report["risk_score"],
        "fraud_type": report["fraud_type"],
        "suspected_type": report["suspected_type"],
        "evidence_requirements": report["evidence_requirements"],
        "advice": report["advice"],
        "report_intel": {
            **(draft.get("report_intel") or {}),
            "status": report["status"],
            "report_id": report_id,
            "confirmed_at": confirmed_at,
        },
    }
    if warnings:
        response["warnings"] = warnings
    return response
