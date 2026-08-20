from __future__ import annotations

from typing import Any, Dict, Literal

from pydantic import BaseModel, Field


VoiceClientEventType = Literal[
    "session.start",
    "audio.input.append",
    "audio.input.commit",
    "assistant.interrupt",
    "session.end",
]


class VoiceClientEvent(BaseModel):
    type: VoiceClientEventType
    payload: Dict[str, Any] = Field(default_factory=dict)


class VoiceServerEvent(BaseModel):
    type: str
    payload: Dict[str, Any] = Field(default_factory=dict)


class VoiceConfig(BaseModel):
    mode: str = "realtime_voice"
    asr_provider: str = "mock_realtime"
    tts_provider: str = "browser_fallback"
    enable_realtime_dialogue: bool = True
    enable_interruption: bool = True
    min_confidence: float = 0.75
    save_audio: bool = False
    save_transcript: bool = True
    default_audio_format: str = "webm_opus"

