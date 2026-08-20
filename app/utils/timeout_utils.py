"""Small synchronous timeout helpers for latency-sensitive fallbacks."""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from typing import Any, Callable, TypeVar


T = TypeVar("T")


def env_timeout(name: str, default: float) -> float:
    try:
        value = float(os.getenv(name, str(default)) or default)
    except (TypeError, ValueError):
        value = default
    return max(0.05, value)


def call_with_timeout(fn: Callable[[], T], timeout_seconds: float) -> T:
    """Run a blocking provider call with a bounded wait.

    The executor is deliberately not awaited after a timeout.  The provider
    call may continue in the background, but the request path immediately
    switches to its deterministic result instead of holding the user request.
    """
    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="anti-fraud-timeout")
    future = executor.submit(fn)
    try:
        return future.result(timeout=max(0.05, float(timeout_seconds)))
    except FutureTimeoutError as exc:
        future.cancel()
        raise TimeoutError(f"provider call timed out after {timeout_seconds:.2f}s") from exc
    finally:
        executor.shutdown(wait=False, cancel_futures=True)


__all__ = ["call_with_timeout", "env_timeout"]
