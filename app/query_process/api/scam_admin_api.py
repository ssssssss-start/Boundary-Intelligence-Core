from datetime import datetime
from typing import Any, Dict

from fastapi import APIRouter, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field

from app.clients.mongo_business_utils import get_business_mongo_tool
from app.query_process.services.admin_auth_service import (
    SESSION_COOKIE,
    SESSION_HOURS,
    authenticate_admin,
    create_admin_session,
    destroy_admin_session,
    require_admin_user,
)
from app.core.security import env_bool
from app.query_process.services.scam_intake_review_service import (
    apply_review_ai_enrichment,
    decide_review,
    generate_review_ai_enrichment,
    get_review_detail,
    list_publish_packages,
    list_review_tasks,
    list_versions,
    publish_package,
    rollback_version,
    run_pre_publish_checks,
    save_review_draft,
)


router = APIRouter(tags=["scam_admin"])


class AdminLoginRequest(BaseModel):
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)


class ReviewDraftSaveRequest(BaseModel):
    draft: Dict[str, Any] = Field(default_factory=dict)


class ReviewAiEnrichRequest(BaseModel):
    use_llm: bool = True
    force: bool = False


class ReviewAiEnrichApplyRequest(BaseModel):
    enrichment_id: str = ""


class ReviewDecisionRequest(BaseModel):
    action: str = Field(..., description="approve / reject / need_more_info / duplicate")
    comment: str = ""


class PublishRequest(BaseModel):
    activate_rules: bool = False


class RollbackRequest(BaseModel):
    reason: str = ""


class ReportStatusRequest(BaseModel):
    status: str = Field(..., description="confirmed / handled / invalid")
    note: str = ""


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",", 1)[0].strip()
    return request.client.host if request.client else ""


def _set_session_cookie(response: Response, token: str, request: Request) -> None:
    forwarded_proto = request.headers.get("x-forwarded-proto", "").split(",", 1)[0].strip().lower()
    secure_cookie = env_bool(
        "ANTI_FRAUD_COOKIE_SECURE",
        request.url.scheme == "https" or forwarded_proto == "https",
    )
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        max_age=SESSION_HOURS * 3600,
        httponly=True,
        samesite="lax",
        secure=secure_cookie,
        path="/",
    )


def _admin(request: Request) -> Dict[str, Any]:
    return require_admin_user(request)


def _can_review_reports(request: Request) -> Dict[str, Any]:
    user = _admin(request)
    roles = set(user.get("roles") or [])
    if not ({"admin", "report_reviewer"} & roles):
        raise HTTPException(status_code=403, detail="需要举报审核权限")
    return user


def _compact_report_ticket(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "report_id": item.get("report_id", ""),
        "analysis_id": item.get("analysis_id", ""),
        "status": item.get("status", ""),
        "report_type": item.get("report_type", ""),
        "content": item.get("content", ""),
        "urls": item.get("urls", []),
        "risk_score": item.get("risk_score", 0),
        "risk_level": item.get("risk_level", ""),
        "suspected_type": item.get("suspected_type", "") or item.get("fraud_type", "") or item.get("scam_type", ""),
        "matched_rules": item.get("matched_rules", []),
        "created_at": item.get("created_at", ""),
        "confirmed_at": item.get("confirmed_at", ""),
        "handled_at": item.get("handled_at", ""),
        "handled_by": item.get("handled_by", {}),
        "handler_note": item.get("handler_note", ""),
    }


@router.post("/admin/auth/login")
async def admin_login(payload: AdminLoginRequest, request: Request, response: Response):
    user = authenticate_admin(payload.username.strip(), payload.password, ip=_client_ip(request))
    session = create_admin_session(
        user,
        ip=_client_ip(request),
        user_agent=request.headers.get("user-agent", ""),
    )
    _set_session_cookie(response, session["token"], request)
    return {
        "message": "登录成功",
        "user": session["user"],
        "expires_at": session["expires_at"],
        "must_change_password": payload.username.strip() == "admin" and payload.password == "Admin@123456",
    }


@router.post("/admin/auth/logout")
async def admin_logout(request: Request, response: Response):
    destroy_admin_session(request.cookies.get(SESSION_COOKIE, ""))
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"message": "已退出登录"}


@router.get("/admin/auth/me")
async def admin_me(request: Request):
    return {"user": _admin(request)}


@router.get("/admin/intake/stats")
async def admin_intake_stats(request: Request):
    _admin(request)
    tool = get_business_mongo_tool()
    review_statuses = ["pending_review", "need_more_info", "rejected", "approved", "published"]
    publish_statuses = ["approved", "ready_to_publish", "pre_publish_blocked", "published", "rolled_back"]
    review_counts = {
        status: int(tool.db["scam_review_tasks"].count_documents({"status": status}))
        for status in review_statuses
    }
    publish_counts = {
        status: int(tool.db["scam_publish_packages"].count_documents({"status": status}))
        for status in publish_statuses
    }
    return {
        "review": review_counts,
        "publish": publish_counts,
        "reports": {
            "confirmed": int(tool.db["report_tickets"].count_documents({"status": "confirmed"})),
            "handled": int(tool.db["report_tickets"].count_documents({"status": "handled"})),
            "invalid": int(tool.db["report_tickets"].count_documents({"status": "invalid"})),
            "total": int(tool.db["report_tickets"].count_documents({})),
        },
        "versions": int(tool.db["scam_publish_versions"].count_documents({})),
        "formal_knowledge": int(tool.db["anti_fraud_knowledge"].count_documents({})),
        "rule_candidates": int(tool.db["risk_rule_candidates"].count_documents({})),
        "audit_logs": int(tool.db["audit_logs"].count_documents({})),
    }


@router.get("/admin/reports/tickets")
async def admin_list_report_tickets(
    request: Request,
    status: str = Query("confirmed", description="举报处理状态"),
    limit: int = Query(80, ge=1, le=200),
):
    _can_review_reports(request)
    tool = get_business_mongo_tool()
    query: Dict[str, Any] = {}
    if status:
        query["status"] = status
    items = list(
        tool.db["report_tickets"]
        .find(query, {"_id": 0})
        .sort("created_at", -1)
        .limit(max(1, min(int(limit or 80), 200)))
    )
    return {
        "items": [_compact_report_ticket(item) for item in items],
        "total": int(tool.db["report_tickets"].count_documents(query)),
    }


@router.get("/admin/reports/tickets/{report_id}")
async def admin_get_report_ticket(report_id: str, request: Request):
    _can_review_reports(request)
    tool = get_business_mongo_tool()
    item = tool.db["report_tickets"].find_one({"report_id": report_id}, {"_id": 0})
    if not item:
        raise HTTPException(status_code=404, detail="举报记录不存在")
    return {"ticket": item}


@router.post("/admin/reports/tickets/{report_id}/status")
async def admin_update_report_ticket_status(report_id: str, payload: ReportStatusRequest, request: Request):
    user = _can_review_reports(request)
    status = payload.status.strip()
    if status not in {"confirmed", "handled", "invalid"}:
        raise HTTPException(status_code=400, detail="不支持的举报状态")
    tool = get_business_mongo_tool()
    update = {
        "status": status,
        "handler_note": payload.note.strip(),
        "handled_by": {
            "user_id": user.get("user_id", ""),
            "username": user.get("username", ""),
            "display_name": user.get("display_name", ""),
        },
        "handled_at": datetime.now().isoformat(timespec="seconds"),
    }
    if status == "confirmed":
        update["handler_note"] = payload.note.strip() or "重新打开"
    update_result = tool.db["report_tickets"].update_one({"report_id": report_id}, {"$set": update})
    result = tool.db["report_tickets"].find_one({"report_id": report_id}, {"_id": 0})
    if not update_result.matched_count or not result:
        raise HTTPException(status_code=404, detail="举报记录不存在")
    try:
        from app.clients.mongo_business_utils import write_audit_log

        write_audit_log(
            "report_ticket_status_update",
            {"report_id": report_id, "status": status, "username": user.get("username", "")},
        )
    except Exception:
        pass
    return {"message": "举报状态已更新", "ticket": result}


@router.get("/admin/intake/reviews")
async def admin_list_reviews(
    request: Request,
    status: str = Query("", description="审核状态"),
    limit: int = Query(50, ge=1, le=100),
):
    _admin(request)
    return list_review_tasks(status=status, limit=limit)


@router.get("/admin/intake/reviews/{review_id}")
async def admin_get_review(review_id: str, request: Request):
    _admin(request)
    return get_review_detail(review_id)


@router.put("/admin/intake/reviews/{review_id}/draft")
async def admin_save_review_draft(review_id: str, payload: ReviewDraftSaveRequest, request: Request):
    user = _admin(request)
    return save_review_draft(review_id, payload.draft, user)


@router.post("/admin/intake/reviews/{review_id}/ai-enrich")
async def admin_generate_review_ai_enrichment(review_id: str, payload: ReviewAiEnrichRequest, request: Request):
    user = _admin(request)
    return generate_review_ai_enrichment(review_id, user, use_llm=payload.use_llm, force=payload.force)


@router.post("/admin/intake/reviews/{review_id}/ai-enrich/apply")
async def admin_apply_review_ai_enrichment(review_id: str, payload: ReviewAiEnrichApplyRequest, request: Request):
    user = _admin(request)
    return apply_review_ai_enrichment(review_id, user, enrichment_id=payload.enrichment_id)


@router.post("/admin/intake/reviews/{review_id}/decision")
async def admin_review_decision(review_id: str, payload: ReviewDecisionRequest, request: Request):
    user = _admin(request)
    return decide_review(review_id, payload.action, payload.comment, user)


@router.get("/admin/intake/publish")
async def admin_list_publish_packages(
    request: Request,
    status: str = Query("", description="发布包状态"),
    limit: int = Query(50, ge=1, le=100),
):
    _admin(request)
    return list_publish_packages(status=status, limit=limit)


@router.post("/admin/intake/publish/{publish_id}/check")
async def admin_check_publish_package(publish_id: str, request: Request):
    _admin(request)
    return run_pre_publish_checks(publish_id)


@router.post("/admin/intake/publish/{publish_id}/publish")
async def admin_publish_package(publish_id: str, payload: PublishRequest, request: Request):
    user = _admin(request)
    try:
        return publish_package(publish_id, user, activate_rules=payload.activate_rules)
    except Exception as exc:
        if isinstance(exc, HTTPException):
            raise
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/admin/intake/versions")
async def admin_list_versions(request: Request, limit: int = Query(50, ge=1, le=100)):
    _admin(request)
    return list_versions(limit=limit)


@router.post("/admin/intake/versions/{version_id}/rollback")
async def admin_rollback_version(version_id: str, payload: RollbackRequest, request: Request):
    user = _admin(request)
    try:
        return rollback_version(version_id, user, reason=payload.reason)
    except Exception as exc:
        if isinstance(exc, HTTPException):
            raise
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/admin/intake/audit")
async def admin_audit_logs(request: Request, limit: int = Query(50, ge=1, le=100)):
    _admin(request)
    tool = get_business_mongo_tool()
    items = list(
        tool.db["audit_logs"]
        .find({}, {"_id": 0})
        .sort("created_at", -1)
        .limit(max(1, min(int(limit or 50), 100)))
    )
    return {"items": items, "total": len(items)}
