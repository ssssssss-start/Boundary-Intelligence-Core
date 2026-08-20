from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict


@dataclass
class ASRResult:
    text: str
    confidence: float = 1.0
    is_final: bool = True
    meta: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TTSResult:
    text: str
    audio_base64: str | None = None
    audio_format: str | None = None
    provider: str = "browser_fallback"
    speak_with_browser: bool = True
    meta: Dict[str, Any] = field(default_factory=dict)


class ASRProvider(ABC):
    @abstractmethod
    async def accept_audio_chunk(self, session_id: str, audio: bytes) -> None:
        """Accept one browser audio chunk for a realtime voice session."""

    @abstractmethod
    async def commit_audio(self, session_id: str) -> ASRResult:
        """Finalize buffered audio and return one user utterance transcript."""

    async def reset(self, session_id: str) -> None:
        """Clear provider-side buffered state for a session."""


class TTSProvider(ABC):
    @abstractmethod
    async def synthesize(self, text: str, voice: str | None = None) -> TTSResult:
        """Synthesize assistant text or return browser-synthesis instructions."""

