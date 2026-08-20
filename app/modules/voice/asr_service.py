from __future__ import annotations

from app.modules.voice.providers.base import ASRProvider
from app.modules.voice.providers.browser_fallback import BrowserFallbackASRProvider
from app.modules.voice.providers.mock_realtime import MockRealtimeASRProvider


_ASR_PROVIDERS: dict[str, ASRProvider] = {}


def get_asr_provider(name: str | None) -> ASRProvider:
    provider_name = (name or "mock_realtime").strip().lower()
    if provider_name not in _ASR_PROVIDERS:
        if provider_name == "browser_fallback":
            _ASR_PROVIDERS[provider_name] = BrowserFallbackASRProvider()
        else:
            _ASR_PROVIDERS[provider_name] = MockRealtimeASRProvider()
    return _ASR_PROVIDERS[provider_name]

