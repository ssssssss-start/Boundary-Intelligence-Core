from __future__ import annotations

from collections import defaultdict
from typing import Dict, List

from app.modules.voice.providers.base import ASRProvider, ASRResult, TTSProvider, TTSResult


class BrowserFallbackASRProvider(ASRProvider):
    """Fallback ASR provider placeholder.

    Browser SpeechRecognition can be used by clients that choose to send a
    transcript in the commit payload. When only audio bytes are sent, this
    provider returns an empty transcript with low confidence instead of calling
    a third-party cloud API.
    """

    def __init__(self) -> None:
        self._chunks: Dict[str, List[bytes]] = defaultdict(list)

    async def accept_audio_chunk(self, session_id: str, audio: bytes) -> None:
        if audio:
            self._chunks[session_id].append(audio)

    async def commit_audio(self, session_id: str) -> ASRResult:
        byte_count = sum(len(item) for item in self._chunks.get(session_id, []))
        self._chunks[session_id] = []
        return ASRResult(
            text="",
            confidence=0.0,
            meta={"provider": "browser_fallback", "audio_bytes": byte_count},
        )

    async def reset(self, session_id: str) -> None:
        self._chunks.pop(session_id, None)


class BrowserFallbackTTSProvider(TTSProvider):
    async def synthesize(self, text: str, voice: str | None = None) -> TTSResult:
        return TTSResult(
            text=text,
            provider="browser_fallback",
            speak_with_browser=True,
            meta={"voice": voice or "zh-CN"},
        )

