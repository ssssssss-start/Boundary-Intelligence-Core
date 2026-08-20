import os
from typing import Any, Dict, List, Optional
import uuid

from fastapi import APIRouter, BackgroundTasks, File, Form, HTTPException, Query, UploadFile
from pydantic import BaseModel, Field

from app.modules.knowledge_assistant.service import (
    run_unified_anti_fraud_chat_stream,
    search_knowledge,
    unified_anti_fraud_chat,
)
from app.modules.knowledge_assistant.emotion import with_emotion_context
from app.modules.vision_ocr.service import analyze_image_fraud_risk
from app.utils.sse_utils import create_sse_queue


router = APIRouter(tags=["module:knowledge-assistant"])
MAX_IMAGE_UPLOAD_BYTES = int(os.getenv("VISION_IMAGE_MAX_BYTES", str(8 * 1024 * 1024)) or str(8 * 1024 * 1024))
ALLOWED_IMAGE_TYPES = {"image/png", "image/jpeg", "image/webp"}
ALLOWED_IMAGE_EXTENSIONS = (".png", ".jpg", ".jpeg", ".webp")


class KnowledgeChatRequest(BaseModel):
    message: str = Field(..., description="用户的反诈咨询内容，可自动分流到科普问答或风险劝阻")
    session_id: Optional[str] = Field(default=None, description="智能反诈助手会话 ID")
    history: List[Dict[str, Any]] = Field(default_factory=list, description="可选的前端对话历史")
    use_llm: bool = Field(default=True, description="是否调用大模型生成回答")
    limit: int = Field(default=8, ge=1, le=20, description="检索材料数量")
    is_stream: bool = Field(default=False, description="是否使用流式返回")
    input_mode: str = Field(default="text", description="输入方式：text 或 voice")
    emotion: Optional[Dict[str, Any]] = Field(default=None, description="前端根据输入内容估计的情绪提示")
    voice_emotion: Optional[Dict[str, Any]] = Field(default=None, description="兼容旧版客户端的语音情绪提示")




def _message_with_emotion_context(
    message: str,
    input_mode: str,
    emotion: Optional[Dict[str, Any]],
) -> tuple[str, Dict[str, Any]]:
    return with_emotion_context(message, input_mode, emotion)


def _message_with_voice_emotion_context(
    message: str,
    input_mode: str,
    voice_emotion: Optional[Dict[str, Any]],
) -> str:
    """Backward-compatible helper retained for older integrations."""

    enriched, _ = _message_with_emotion_context(message, input_mode, voice_emotion)
    return enriched

@router.get("/knowledge/search")
async def knowledge_search(
    query: str = Query(..., description="检索关键词"),
    limit: int = Query(5, ge=1, le=20, description="返回数量"),
):
    return search_knowledge(query, limit=limit)


@router.post("/knowledge/chat")
async def knowledge_chat_api(background_tasks: BackgroundTasks, payload: KnowledgeChatRequest):
    provided_emotion = payload.emotion if isinstance(payload.emotion, dict) else payload.voice_emotion
    message, emotion = _message_with_emotion_context(payload.message, payload.input_mode, provided_emotion)
    if payload.is_stream:
        session_id = payload.session_id or str(uuid.uuid4())
        create_sse_queue(session_id)
        background_tasks.add_task(
            run_unified_anti_fraud_chat_stream,
            message,
            session_id=session_id,
            history=payload.history,
            use_llm=payload.use_llm,
            limit=payload.limit,
        )
        return {"message": "结果正在处理中...", "session_id": session_id, "emotion": emotion}

    result = unified_anti_fraud_chat(
        message,
        session_id=payload.session_id,
        history=payload.history,
        use_llm=payload.use_llm,
        limit=payload.limit,
    )
    result["emotion"] = emotion
    return result


@router.post("/knowledge/image/analyze")
async def knowledge_image_analyze_api(
    file: UploadFile = File(..., description="待识别的聊天截图或可疑图片"),
    session_id: Optional[str] = Form(default=None, description="当前聊天会话 ID，用于前端关联"),
):
    filename = file.filename or "upload-image"
    content_type = (file.content_type or "").lower()
    filename_lower = filename.lower()
    has_allowed_type = content_type in ALLOWED_IMAGE_TYPES
    has_allowed_extension = filename_lower.endswith(ALLOWED_IMAGE_EXTENSIONS)
    if not has_allowed_type and not has_allowed_extension:
        raise HTTPException(status_code=400, detail="仅支持 PNG、JPG/JPEG、WEBP 图片")

    image_bytes = await file.read()
    if not image_bytes:
        raise HTTPException(status_code=400, detail="图片文件为空")
    if len(image_bytes) > MAX_IMAGE_UPLOAD_BYTES:
        max_mb = MAX_IMAGE_UPLOAD_BYTES / 1024 / 1024
        raise HTTPException(status_code=413, detail=f"图片过大，请上传 {max_mb:.0f}MB 以内的图片")

    result = await analyze_image_fraud_risk(
        image_bytes,
        filename=filename,
        content_type=content_type if has_allowed_type else "",
    )
    result["filename"] = filename
    result["content_type"] = content_type or ""
    result["size_bytes"] = len(image_bytes)
    result["session_id"] = session_id or ""
    return result
