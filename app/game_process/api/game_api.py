from typing import Any, Dict

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

from app.game_process.services.game_service import (
    DEFAULT_USER_ID,
    build_game_report,
    continue_scam_simulation,
    finish_scam_simulation,
    get_next_level,
    start_scam_simulation,
    submit_level,
)


router = APIRouter(tags=["game"])


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
    use_llm: bool = Field(True, description="是否优先使用 LLM 生成骗子话术")


class ScamSimulationTurnRequest(BaseModel):
    session_id: str = Field(..., description="模拟会话ID")
    user_message: str = Field("", description="用户自由回复文本")
    voice_text: str | None = Field(None, description="语音识别转写文本")
    use_llm: bool = Field(True, description="是否优先使用 LLM 生成骗子下一轮话术")


class ScamSimulationFinishRequest(BaseModel):
    session_id: str = Field(..., description="模拟会话ID")
    user_message: str | None = Field(None, description="可选，结束前最后一句用户回复")


@router.get("/game/next")
async def game_next(
    user_id: str = Query(DEFAULT_USER_ID, description="用户ID"),
    level_id: int | None = Query(None, ge=1, description="指定关卡；为空时返回下一关"),
):
    return get_next_level(user_id=user_id, level_id=level_id)


@router.post("/game/submit")
async def game_submit(request: GameSubmitRequest):
    return submit_level(
        user_id=request.user_id,
        level_id=request.level_id,
        answer=request.answer,
        interaction_mode=request.interaction_mode,
        voice_text=request.voice_text or "",
        audio_meta=request.audio_meta,
    )


@router.get("/game/report")
async def game_report(user_id: str = Query(DEFAULT_USER_ID, description="用户ID")):
    return build_game_report(user_id=user_id)


@router.post("/game/simulation/start")
async def simulation_start(request: ScamSimulationStartRequest):
    return start_scam_simulation(
        user_id=request.user_id,
        fraud_type=request.fraud_type,
        difficulty=request.difficulty,
        use_llm=request.use_llm,
    )


@router.post("/game/simulation/turn")
async def simulation_turn(request: ScamSimulationTurnRequest):
    return continue_scam_simulation(
        session_id=request.session_id,
        user_message=request.user_message,
        voice_text=request.voice_text or "",
        use_llm=request.use_llm,
    )


@router.post("/game/simulation/finish")
async def simulation_finish(request: ScamSimulationFinishRequest):
    return finish_scam_simulation(session_id=request.session_id, user_message=request.user_message)
