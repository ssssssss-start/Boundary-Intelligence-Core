from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class EmergencyChatRequest(BaseModel):
    query: str = Field(..., description="用户正在经历的风险场景描述")
    session_id: str | None = Field(None, description="紧急劝阻会话ID")
    is_stream: bool = Field(False, description="是否流式返回")
    intent_hint: str | None = Field("emergency_help", description="入口意图提示")
    input_mode: str = Field("text", description="输入方式：text、voice 或 image")
    emotion: Optional[Dict[str, Any]] = Field(default=None, description="根据输入内容估计的情绪提示")
    voice_emotion: Optional[Dict[str, Any]] = Field(default=None, description="兼容旧版客户端的语音情绪提示")
