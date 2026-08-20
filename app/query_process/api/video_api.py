from typing import Any, Dict

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

from app.query_process.services.admin_auth_service import require_admin_user
from app.query_process.services.risk_video_card_service import (
    VIDEO_SCENES,
    VIDEO_STATUSES,
    get_video_card,
    public_video_cards,
    list_video_cards,
    update_video_card_status,
    upsert_video_card,
)


router = APIRouter(tags=["risk-video-cards"])


class VideoCardUpsertRequest(BaseModel):
    item: Dict[str, Any] = Field(default_factory=dict, description="视频链接预览卡片")


class VideoCardStatusRequest(BaseModel):
    status: str = Field(..., description="draft/pending_review/published/disabled/expired")


def _admin(request: Request) -> Dict[str, Any]:
    return require_admin_user(request)


@router.get("/risk/video-cards")
async def risk_video_cards(
    scam_id: str = Query(..., min_length=1, description="诈骗类型 scam_id"),
    scene: str = Query("", description="knowledge 或 risk"),
    limit: int = Query(3, ge=1, le=20),
):
    if scene and scene not in VIDEO_SCENES:
        raise HTTPException(status_code=400, detail="scene must be knowledge or risk")
    try:
        items = public_video_cards(scam_id, scene=scene, limit=limit)
        return {"scam_id": scam_id, "scene": scene, "items": items, "total": len(items)}
    except Exception as exc:
        raise HTTPException(status_code=503, detail="video cards temporarily unavailable") from exc


@router.get("/admin/risk-video-cards")
async def admin_list_risk_video_cards(
    request: Request,
    scam_id: str = Query(""),
    status: str = Query(""),
    scene: str = Query(""),
    limit: int = Query(50, ge=1, le=100),
):
    _admin(request)
    if status and status not in VIDEO_STATUSES:
        raise HTTPException(status_code=400, detail="unsupported video status")
    if scene and scene not in VIDEO_SCENES:
        raise HTTPException(status_code=400, detail="scene must be knowledge or risk")
    try:
        items = list_video_cards(scam_id=scam_id, status=status, scene=scene, limit=limit, public=False)
        return {"items": items, "total": len(items)}
    except Exception as exc:
        raise HTTPException(status_code=503, detail="video cards temporarily unavailable") from exc


@router.post("/admin/risk-video-cards")
async def admin_create_risk_video_card(payload: VideoCardUpsertRequest, request: Request):
    user = _admin(request)
    try:
        actor = str(user.get("username") or user.get("user_id") or "admin")
        item = upsert_video_card(payload.item, actor=actor)
        return {"message": "video card saved", "item": item}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=503, detail="video card storage unavailable") from exc


@router.put("/admin/risk-video-cards/{video_id}")
async def admin_update_risk_video_card(video_id: str, payload: VideoCardUpsertRequest, request: Request):
    user = _admin(request)
    item = dict(payload.item or {})
    item["video_id"] = video_id
    try:
        actor = str(user.get("username") or user.get("user_id") or "admin")
        saved = upsert_video_card(item, actor=actor)
        return {"message": "video card saved", "item": saved}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=503, detail="video card storage unavailable") from exc


@router.get("/admin/risk-video-cards/{video_id}")
async def admin_get_risk_video_card(video_id: str, request: Request):
    _admin(request)
    try:
        item = get_video_card(video_id, public=False)
        if not item:
            raise HTTPException(status_code=404, detail="video card not found")
        return {"item": item}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=503, detail="video card storage unavailable") from exc


@router.post("/admin/risk-video-cards/{video_id}/status")
async def admin_update_risk_video_card_status(
    video_id: str,
    payload: VideoCardStatusRequest,
    request: Request,
):
    user = _admin(request)
    if payload.status not in VIDEO_STATUSES:
        raise HTTPException(status_code=400, detail="unsupported video status")
    try:
        actor = str(user.get("username") or user.get("user_id") or "admin")
        item = update_video_card_status(video_id, payload.status, actor=actor)
        return {"message": "video card status updated", "item": item}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=503, detail="video card storage unavailable") from exc

