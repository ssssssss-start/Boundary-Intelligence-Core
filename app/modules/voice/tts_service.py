from __future__ import annotations

from app.modules.voice.providers.base import TTSProvider
from app.modules.voice.providers.browser_fallback import BrowserFallbackTTSProvider
from app.modules.voice.providers.mock_realtime import MockRealtimeTTSProvider


_TTS_PROVIDERS: dict[str, TTSProvider] = {}


def get_tts_provider(name: str | None) -> TTSProvider:
    provider_name = (name or "browser_fallback").strip().lower()
    if provider_name not in _TTS_PROVIDERS:
        if provider_name == "mock_realtime":
            _TTS_PROVIDERS[provider_name] = MockRealtimeTTSProvider()
        else:
            _TTS_PROVIDERS[provider_name] = BrowserFallbackTTSProvider()
    return _TTS_PROVIDERS[provider_name]

