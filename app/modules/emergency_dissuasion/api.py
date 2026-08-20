from fastapi import APIRouter, BackgroundTasks, HTTPException, Request
from fastapi.responses import StreamingResponse

from app.clients.mongo_history_utils import clear_history, get_recent_messages
from app.modules.emergency_dissuasion.schemas import EmergencyChatRequest
from app.modules.emergency_dissuasion.service import handle_emergency_chat
from app.query_process.services.admin_auth_service import require_admin_user
from app.utils.sse_utils import sse_generator


router = APIRouter(tags=["module:emergency-dissuasion"])


@router.post("/emergency/chat")
async def emergency_chat(background_tasks: BackgroundTasks, request: EmergencyChatRequest):
    return await handle_emergency_chat(background_tasks, request)


@router.post("/chat")
async def chat_alias(background_tasks: BackgroundTasks, request: EmergencyChatRequest):
    return await handle_emergency_chat(background_tasks, request)


@router.post("/query")
async def query_alias(background_tasks: BackgroundTasks, request: EmergencyChatRequest):
    return await handle_emergency_chat(background_tasks, request)


@router.get("/stream/{session_id}")
async def stream(session_id: str, request: Request):
    return StreamingResponse(
        sse_generator(session_id, request),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/history/{session_id}")
async def history(session_id: str, limit: int = 50):
    try:
        records = get_recent_messages(session_id, limit=limit)
        items = []
        for item in records:
            items.append(
                {
                    "_id": str(item.get("_id")) if item.get("_id") is not None else "",
                    "session_id": item.get("session_id", ""),
                    "role": item.get("role", ""),
                    "text": item.get("text", ""),
                    "rewritten_query": item.get("rewritten_query", ""),
                    "fraud_types": item.get("fraud_types", []),
                    "risk_summary": item.get("risk_summary", {}),
                    "video_cards": item.get("video_cards", []),
                    "ts": item.get("ts"),
                }
            )
        return {"session_id": session_id, "items": items}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"history error: {e}") from e


@router.delete("/history/{session_id}")
async def clear_chat_history(session_id: str, request: Request):
    require_admin_user(request)
    count = clear_history(session_id)
    return {"message": "History cleared", "deleted_count": count}
