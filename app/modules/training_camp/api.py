from fastapi import APIRouter, HTTPException, Query

from app.modules.training_camp.schemas import (
    GameSubmitRequest,
    ScamSimulationFinishRequest,
    ScamSimulationStartRequest,
    ScamSimulationTurnRequest,
)
from app.modules.training_camp.service import (
    DEFAULT_USER_ID,
    build_game_report,
    continue_scam_simulation,
    finish_scam_simulation,
    get_next_level,
    start_scam_simulation,
    submit_level,
)


router = APIRouter(tags=["module:training-camp"])


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
    try:
        return start_scam_simulation(
            user_id=request.user_id,
            fraud_type=request.fraud_type,
            difficulty=request.difficulty,
            use_llm=request.use_llm,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"模拟启动失败：{exc}") from exc


@router.post("/game/simulation/turn")
async def simulation_turn(request: ScamSimulationTurnRequest):
    try:
        return continue_scam_simulation(
            session_id=request.session_id,
            user_message=request.user_message,
            voice_text=request.voice_text or "",
            use_llm=request.use_llm,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"模拟回应失败：{exc}") from exc


@router.post("/game/simulation/finish")
async def simulation_finish(request: ScamSimulationFinishRequest):
    try:
        return finish_scam_simulation(session_id=request.session_id, user_message=request.user_message)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"模拟评分失败：{exc}") from exc
