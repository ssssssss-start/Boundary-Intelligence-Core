"""Small dependency-free HTTP security middleware for the public API."""

from __future__ import annotations

import os
import time
from collections import defaultdict, deque
from typing import Deque, Dict, Tuple

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response


RATE_LIMITED_PATHS = {
    "/knowledge/chat": 30,
    "/emergency/chat": 30,
    "/chat": 30,
    "/query": 30,
    "/knowledge/image/analyze": 10,
    "/game/simulation/asr": 20,
    "/game/simulation/tts": 30,
    "/report-intel/analyze": 20,
    "/report-intel/confirm": 20,
    "/admin/auth/login": 10,
    "/intake/submit": 20,
    "/import/default": 5,
    "/upload": 5,
}


class SecurityMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self.window_seconds = int(os.getenv("ANTI_FRAUD_RATE_LIMIT_WINDOW_SECONDS", "60") or 60)
        self.max_body_bytes = int(os.getenv("ANTI_FRAUD_MAX_REQUEST_BODY_BYTES", str(12 * 1024 * 1024)) or 12 * 1024 * 1024)
        self._requests: Dict[Tuple[str, str], Deque[float]] = defaultdict(deque)

    def _client_key(self, request: Request) -> str:
        return request.client.host if request.client else "unknown"

    def _rate_limited(self, request: Request) -> bool:
        limit = RATE_LIMITED_PATHS.get(request.url.path)
        if not limit or request.method == "OPTIONS":
            return False
        now = time.monotonic()
        queue = self._requests[(self._client_key(request), request.url.path)]
        while queue and now - queue[0] >= self.window_seconds:
            queue.popleft()
        if len(queue) >= limit:
            return True
        queue.append(now)
        return False

    async def dispatch(self, request: Request, call_next) -> Response:
        content_length = request.headers.get("content-length", "")
        if content_length.isdigit() and int(content_length) > self.max_body_bytes:
            return JSONResponse({"detail": "请求体过大"}, status_code=413)
        if self._rate_limited(request):
            return JSONResponse(
                {"detail": "请求过于频繁，请稍后再试"},
                status_code=429,
                headers={"Retry-After": str(self.window_seconds)},
            )
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "camera=(), geolocation=(), payment=()")
        response.headers.setdefault("Cache-Control", "no-store")
        return response
