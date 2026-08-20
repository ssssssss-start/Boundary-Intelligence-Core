from typing import Any, Dict

from pydantic import BaseModel, Field

from app.modules.training_camp.service import DEFAULT_USER_ID


class GameSubmitRequest(BaseModel):
    user_id: str = Field(DEFAULT_USER_ID, description="用户ID")
    level_id: int = Field(..., ge=1, description="关卡ID")
    answer: str = Field("", description="用户选择的答案；语音作答时可为空")
    interaction_mode: str = Field("choice", description="交互模式：choice 或 voice")
    voice_text: str | None = Field(None, description="浏览器语音识别后的转写文本")
    audio_meta: Dict[str, Any] | None = Field(None, description="语音输入元信息")


class ScamSimulationStartRequest(BaseModel):
    user_id: str = Field(DEFAULT_USER_ID, description="用户ID")
    fraud_type: str | None = Field(None, description="可选，指定骗局类型；为空时随机")
    difficulty: str = Field("medium", description="模拟难度：easy、medium、hard")
    use_llm: bool = Field(False, description="是否优先使用 LLM 生成骗子话术")


class ScamSimulationTurnRequest(BaseModel):
    session_id: str = Field(..., description="模拟会话ID")
    user_message: str = Field("", description="用户自由回复文本")
    voice_text: str | None = Field(None, description="语音识别转写文本")
    use_llm: bool = Field(False, description="是否优先使用 LLM 生成骗子下一轮话术")


class ScamSimulationFinishRequest(BaseModel):
    session_id: str = Field(..., description="模拟会话ID")
    user_message: str | None = Field(None, description="可选，结束前最后一句用户回复")
