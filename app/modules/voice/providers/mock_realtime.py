from __future__ import annotations

from collections import defaultdict
from typing import Dict, List

from app.modules.voice.providers.base import ASRProvider, ASRResult, TTSProvider, TTSResult


class MockRealtimeASRProvider(ASRProvider):
    """Deterministic local ASR provider for end-to-end WebSocket testing.

    It buffers real audio bytes so the transport path is exercised, then emits
    a rotating safe-training transcript when the browser commits an utterance.
    """

    def __init__(self) -> None:
        self._chunks: Dict[str, List[bytes]] = defaultdict(list)
        self._turns: Dict[str, int] = defaultdict(int)
        self._samples = [
            "我先不转账，也不会给验证码，我要去官方渠道核实。",
            "这个要求有点可疑，我不会共享屏幕，也不会下载陌生应用。",
            "我会保存聊天记录和付款要求，必要时联系官方客服或报警。",
        ]

    async def accept_audio_chunk(self, session_id: str, audio: bytes) -> None:
        if audio:
            self._chunks[session_id].append(audio)

    async def commit_audio(self, session_id: str) -> ASRResult:
        turn_index = self._turns[session_id]
        self._turns[session_id] += 1
        byte_count = sum(len(item) for item in self._chunks.get(session_id, []))
        self._chunks[session_id] = []
        text = self._samples[turn_index % len(self._samples)]
        return ASRResult(
            text=text,
            confidence=0.99,
            meta={"provider": "mock_realtime", "audio_bytes": byte_count},
        )

    async def reset(self, session_id: str) -> None:
        self._chunks.pop(session_id, None)
        self._turns.pop(session_id, None)


class MockRealtimeTTSProvider(TTSProvider):
    async def synthesize(self, text: str, voice: str | None = None) -> TTSResult:
        return TTSResult(
            text=text,
            provider="mock_realtime",
            speak_with_browser=True,
            meta={"voice": voice or "default"},
        )

