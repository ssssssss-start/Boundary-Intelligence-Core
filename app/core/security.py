"""Central security configuration helpers.

Defaults are safe for a local demo and can be tightened for deployment through
environment variables without changing application code.
"""

from __future__ import annotations

import os
from typing import Iterable, List


LOCAL_CORS_ORIGINS = [
    "http://127.0.0.1:8000",
    "http://127.0.0.1:8001",
    "http://127.0.0.1:5173",
    "http://localhost:8000",
    "http://localhost:8001",
    "http://localhost:5173",
]


def env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def csv_values(value: str | None, default: Iterable[str] = ()) -> List[str]:
    values = [item.strip() for item in str(value or "").split(",") if item.strip()]
    return values or list(default)


def cors_origins() -> List[str]:
    origins = csv_values(os.getenv("ANTI_FRAUD_CORS_ORIGINS"), LOCAL_CORS_ORIGINS)
    if "*" in origins and not env_bool("ANTI_FRAUD_ALLOW_INSECURE_CORS", False):
        raise RuntimeError(
            "Wildcard CORS is disabled. Set explicit ANTI_FRAUD_CORS_ORIGINS, "
            "or deliberately set ANTI_FRAUD_ALLOW_INSECURE_CORS=1 for a disposable demo."
        )
    return origins


def is_weak_password(password: str) -> bool:
    normalized = str(password or "").strip().lower()
    weak = {
        "123456",
        "admin",
        "admin123",
        "admin@123456",
        "password",
        "password123",
        "qwerty",
    }
    return len(password or "") < 10 or normalized in weak

