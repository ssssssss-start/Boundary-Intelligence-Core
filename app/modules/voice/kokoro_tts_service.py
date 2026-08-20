from __future__ import annotations

import atexit
import base64
import json
import os
import subprocess
import threading
from pathlib import Path
from typing import Any, Dict

from app.modules.voice.chinese_text_normalizer import normalize_numbers_for_chinese_tts


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_KOKORO_MODEL_DIR = PROJECT_ROOT / "tts" / "kokoro" / "kokoro-int8-multi-lang-v1_1"
DEFAULT_KOKORO_PYTHON = PROJECT_ROOT / "tts" / "kokoro" / ".venv" / "bin" / "python"
DEFAULT_KOKORO_WORKER = PROJECT_ROOT / "tts" / "kokoro" / "kokoro_worker.py"


def _resolve_path(value: str | None, default: Path) -> Path:
    if not value:
        return default
    path = Path(value)
    return path if path.is_absolute() else PROJECT_ROOT / path


class KokoroTtsWorker:
    def __init__(self) -> None:
        self._process: subprocess.Popen[str] | None = None
        self._lock = threading.Lock()
        self._warmed_speakers: set[int] = set()

    def _config(self) -> Dict[str, Path]:
        return {
            "python": _resolve_path(os.getenv("KOKORO_TTS_PYTHON"), DEFAULT_KOKORO_PYTHON),
            "worker": _resolve_path(os.getenv("KOKORO_TTS_WORKER"), DEFAULT_KOKORO_WORKER),
            "model_dir": _resolve_path(os.getenv("KOKORO_TTS_MODEL_DIR"), DEFAULT_KOKORO_MODEL_DIR),
        }

    def _ensure_process(self) -> subprocess.Popen[str]:
        if self._process and self._process.poll() is None:
            return self._process

        config = self._config()
        for key, path in config.items():
            if not path.exists():
                raise FileNotFoundError(f"Kokoro TTS {key} not found: {path}")

        self._process = subprocess.Popen(
            [
                str(config["python"]),
                str(config["worker"]),
                "--model-dir",
                str(config["model_dir"]),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
            cwd=str(PROJECT_ROOT),
        )
        return self._process

    def synthesize(self, text: str, sid: int = 3, speed: float = 1.0) -> Dict[str, Any]:
        normalized = str(text or "").strip()
        if not normalized:
            raise ValueError("text is required")
        normalized = normalized[:500]
        normalized = normalize_numbers_for_chinese_tts(normalized)
        sid = max(0, min(int(sid), 200))
        speed = max(0.5, min(float(speed), 1.5))

        with self._lock:
            process = self._ensure_process()
            if not process.stdin or not process.stdout:
                raise RuntimeError("Kokoro TTS worker pipes are unavailable")
            payload = json.dumps({"text": normalized, "sid": sid, "speed": speed}, ensure_ascii=False)
            try:
                process.stdin.write(payload + "\n")
                process.stdin.flush()
                line = process.stdout.readline()
            except BrokenPipeError:
                self._process = None
                process = self._ensure_process()
                if not process.stdin or not process.stdout:
                    raise RuntimeError("Kokoro TTS worker restart failed")
                process.stdin.write(payload + "\n")
                process.stdin.flush()
                line = process.stdout.readline()

        if not line:
            self._process = None
            raise RuntimeError("Kokoro TTS worker returned no data")
        result = json.loads(line)
        if not result.get("ok"):
            raise RuntimeError(str(result.get("error") or "Kokoro TTS synthesis failed"))
        audio_base64 = str(result.get("audio_base64") or "")
        return {
            "audio": base64.b64decode(audio_base64),
            "sample_rate": int(result.get("sample_rate") or 0),
            "sid": sid,
            "speed": speed,
        }

    def warmup(self, sid: int = 3) -> Dict[str, Any]:
        sid = max(0, min(int(sid), 200))
        if sid in self._warmed_speakers and self._process and self._process.poll() is None:
            return {"ok": True, "warmed": True, "sid": sid, "cached": True}
        self.synthesize(text="你好。", sid=sid, speed=1.0)
        self._warmed_speakers.add(sid)
        return {"ok": True, "warmed": True, "sid": sid, "cached": False}

    def close(self) -> None:
        if self._process and self._process.poll() is None:
            self._process.terminate()
        self._process = None


_worker = KokoroTtsWorker()
atexit.register(_worker.close)


def synthesize_kokoro_wav(text: str, sid: int = 3, speed: float = 1.0) -> Dict[str, Any]:
    return _worker.synthesize(text=text, sid=sid, speed=speed)


def warmup_kokoro_tts(sid: int = 3) -> Dict[str, Any]:
    return _worker.warmup(sid=sid)
