from __future__ import annotations

import asyncio
import base64
import os
import uuid
from dataclasses import dataclass
from typing import Any, Dict

from dotenv import load_dotenv
from fastapi import WebSocket
from pydantic import ValidationError
from starlette.websockets import WebSocketDisconnect

from app.modules.training_camp.service import (
    DEFAULT_USER_ID,
    continue_scam_simulation,
    finish_scam_simulation,
    start_scam_simulation,
)
from app.modules.voice.asr_service import get_asr_provider
from app.modules.voice.providers.base import ASRProvider, TTSProvider
from app.modules.voice.schemas import VoiceClientEvent, VoiceConfig, VoiceServerEvent
from app.modules.voice.tts_service import get_tts_provider


load_dotenv()


@dataclass
class RealtimeVoiceSession:
    voice_session_id: str
    simulation_session_id: str
    user_id: str
    difficulty: str
    scenario_type: str
    status: str = "listening"
    interrupted: bool = False


def load_voice_config() -> VoiceConfig:
    return VoiceConfig(
        mode=os.getenv("VOICE_MODE", "realtime_voice"),
        asr_provider=os.getenv("VOICE_ASR_PROVIDER", "mock_realtime"),
        tts_provider=os.getenv("VOICE_TTS_PROVIDER", "browser_fallback"),
        enable_realtime_dialogue=os.getenv("VOICE_ENABLE_REALTIME_DIALOGUE", "1") in {"1", "true", "True"},
        enable_interruption=os.getenv("VOICE_ENABLE_INTERRUPTION", "1") in {"1", "true", "True"},
        min_confidence=float(os.getenv("VOICE_MIN_CONFIDENCE", "0.75")),
        save_audio=os.getenv("VOICE_SAVE_AUDIO", "0") in {"1", "true", "True"},
        save_transcript=os.getenv("VOICE_SAVE_TRANSCRIPT", "1") in {"1", "true", "True"},
        default_audio_format=os.getenv("VOICE_DEFAULT_AUDIO_FORMAT", "webm_opus"),
    )


async def send_event(websocket: WebSocket, event_type: str, payload: Dict[str, Any] | None = None) -> None:
    await websocket.send_json(VoiceServerEvent(type=event_type, payload=payload or {}).model_dump())


async def handle_voice_user_turn(session_id: str, transcript: str) -> Dict[str, Any]:
    return await asyncio.to_thread(
        continue_scam_simulation,
        session_id,
        "",
        transcript,
        True,
    )


async def _start_voice_session(payload: Dict[str, Any]) -> tuple[RealtimeVoiceSession, Dict[str, Any]]:
    user_id = str(payload.get("user_id") or DEFAULT_USER_ID)
    scenario_type = str(payload.get("scenario_type") or payload.get("fraud_type") or "")
    difficulty = str(payload.get("difficulty") or "medium")
    simulation = await asyncio.to_thread(
        start_scam_simulation,
        user_id,
        scenario_type or None,
        difficulty,
        True,
    )
    sim = simulation.get("simulation") or {}
    voice_session = RealtimeVoiceSession(
        voice_session_id=f"voice-{uuid.uuid4().hex[:12]}",
        simulation_session_id=str(sim.get("session_id") or ""),
        user_id=user_id,
        difficulty=str(sim.get("difficulty") or difficulty),
        scenario_type=str(sim.get("fraud_type") or scenario_type),
    )
    return voice_session, simulation


def _turn_payload(result: Dict[str, Any]) -> Dict[str, Any]:
    simulation = result.get("simulation") or {}
    evaluation = result.get("result") or {}
    interim_score = result.get("interim_score")
    score = evaluation.get("score", interim_score if interim_score is not None else 100)
    safe_actions = evaluation.get("safe_signals") or []
    risk_events = evaluation.get("loss_signals") or []
    return {
        "risk_score": max(0, min(100, 100 - int(score or 0))),
        "safe_actions": safe_actions,
        "risk_events": risk_events,
        "assistant_text": result.get("scammer_message") or evaluation.get("debrief", ""),
        "simulation": simulation,
        "simulation_status": simulation.get("status", "running"),
        "turn_count": simulation.get("turn_count", 0),
    }


async def _send_assistant_text(websocket: WebSocket, text: str, tts_provider: TTSProvider) -> None:
    tts = await tts_provider.synthesize(text)
    await send_event(
        websocket,
        "assistant.text.final",
        {
            "text": text,
            "tts": {
                "provider": tts.provider,
                "speak_with_browser": tts.speak_with_browser,
                "audio_format": tts.audio_format,
                "audio_base64": tts.audio_base64,
                "meta": tts.meta,
            },
        },
    )


async def _finish_voice_session(
    websocket: WebSocket,
    session: RealtimeVoiceSession,
    asr_provider: ASRProvider,
) -> None:
    result = await asyncio.to_thread(finish_scam_simulation, session.simulation_session_id)
    await send_event(
        websocket,
        "session.ended",
        {
            "summary": (result.get("result") or {}).get("debrief", ""),
            "final_score": result.get("score", 0),
            "outcome": result.get("outcome", ""),
            "simulation": result.get("simulation") or {},
            "result": result.get("result") or {},
        },
    )
    session.status = "ended"
    await asr_provider.reset(session.voice_session_id)


async def handle_realtime_voice_websocket(websocket: WebSocket) -> None:
    await websocket.accept()
    config = load_voice_config()
    asr_provider = get_asr_provider(config.asr_provider)
    tts_provider = get_tts_provider(config.tts_provider)
    session: RealtimeVoiceSession | None = None

    if not config.enable_realtime_dialogue:
        await send_event(websocket, "error", {"message": "实时语音对话未启用"})
        await websocket.close(code=1008)
        return

    try:
        while True:
            raw = await websocket.receive_json()
            try:
                event = VoiceClientEvent.model_validate(raw)
            except ValidationError as exc:
                await send_event(websocket, "error", {"message": f"事件格式错误：{exc.errors()[0]['msg']}"})
                continue

            if event.type == "session.start":
                session, simulation = await _start_voice_session(event.payload)
                await send_event(
                    websocket,
                    "session.started",
                    {
                        "session_id": session.voice_session_id,
                        "simulation_session_id": session.simulation_session_id,
                        "asr_provider": config.asr_provider,
                        "tts_provider": config.tts_provider,
                        "audio_format": config.default_audio_format,
                        "simulation": simulation.get("simulation") or {},
                    },
                )
                opening = simulation.get("scammer_message") or ((simulation.get("simulation") or {}).get("messages") or [{}])[-1].get("content", "")
                if opening:
                    await _send_assistant_text(websocket, str(opening), tts_provider)
                continue

            if not session:
                await send_event(websocket, "error", {"message": "请先发送 session.start"})
                continue

            if event.type == "audio.input.append":
                audio_base64 = str(event.payload.get("audio_base64") or "")
                if audio_base64:
                    await asr_provider.accept_audio_chunk(session.voice_session_id, base64.b64decode(audio_base64))
                continue

            if event.type == "audio.input.commit":
                session.status = "recognizing"
                result = await asr_provider.commit_audio(session.voice_session_id)
                if result.text:
                    await send_event(websocket, "transcript.partial", {"text": result.text, "confidence": result.confidence})
                if not result.text or result.confidence < config.min_confidence:
                    await send_event(
                        websocket,
                        "error",
                        {"message": "没有识别到足够清晰的语音，请再说一次。", "confidence": result.confidence},
                    )
                    session.status = "listening"
                    continue
                await send_event(websocket, "transcript.final", {"text": result.text, "confidence": result.confidence, "meta": result.meta})
                session.status = "thinking"
                turn = await handle_voice_user_turn(session.simulation_session_id, result.text)
                assistant_text = turn.get("scammer_message") or (turn.get("result") or {}).get("debrief", "")
                if assistant_text:
                    session.status = "speaking"
                    await _send_assistant_text(websocket, str(assistant_text), tts_provider)
                await send_event(websocket, "turn.completed", _turn_payload(turn))
                if turn.get("result"):
                    await send_event(
                        websocket,
                        "session.ended",
                        {
                            "summary": (turn.get("result") or {}).get("debrief", ""),
                            "final_score": turn.get("score", 0),
                            "outcome": turn.get("outcome", ""),
                            "simulation": turn.get("simulation") or {},
                            "result": turn.get("result") or {},
                        },
                    )
                    session.status = "ended"
                else:
                    session.status = "listening"
                continue

            if event.type == "assistant.interrupt":
                if config.enable_interruption:
                    session.interrupted = True
                    session.status = "listening"
                    await send_event(websocket, "assistant.interrupted", {"session_id": session.voice_session_id})
                continue

            if event.type == "session.end":
                await _finish_voice_session(websocket, session, asr_provider)
                await websocket.close(code=1000)
                return

    except WebSocketDisconnect:
        if session:
            await asr_provider.reset(session.voice_session_id)
    except Exception as exc:
        await send_event(websocket, "error", {"message": str(exc)})
        await websocket.close(code=1011)
