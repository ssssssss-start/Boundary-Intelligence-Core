from __future__ import annotations

import asyncio
import json
import os
import ssl
from dataclasses import dataclass, field
from typing import Any

import websockets


@dataclass
class FunAsrTranscript:
    text: str
    confidence: float = 1.0
    meta: dict[str, Any] = field(default_factory=dict)


def _funasr_uri() -> tuple[str, ssl.SSLContext | None]:
    host = os.getenv("FUNASR_ASR_HOST", "127.0.0.1")
    port = int(os.getenv("FUNASR_ASR_PORT", "10096"))
    use_ssl = os.getenv("FUNASR_ASR_SSL", "0") in {"1", "true", "True"}
    if not use_ssl:
        return f"ws://{host}:{port}", None
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return f"wss://{host}:{port}", context


async def transcribe_funasr_pcm(audio: bytes, sample_rate: int = 16000) -> FunAsrTranscript:
    if not audio:
        raise ValueError("audio is required")
    mode = os.getenv("FUNASR_ASR_MODE", "2pass")
    chunk_size = [int(item.strip()) for item in os.getenv("FUNASR_ASR_CHUNK_SIZE", "5,10,5").split(",")]
    chunk_interval = int(os.getenv("FUNASR_ASR_CHUNK_INTERVAL", "10"))
    timeout = float(os.getenv("FUNASR_ASR_TIMEOUT", "15"))
    use_itn = os.getenv("FUNASR_ASR_USE_ITN", "1") in {"1", "true", "True"}
    uri, ssl_context = _funasr_uri()

    stride = int(60 * chunk_size[1] / chunk_interval / 1000 * sample_rate * 2)
    stride = max(640, stride)
    chunk_num = (len(audio) - 1) // stride + 1
    offline_parts: list[str] = []
    online_parts: list[str] = []
    messages: list[dict[str, Any]] = []

    async with websockets.connect(uri, subprotocols=["binary"], ping_interval=None, ssl=ssl_context) as websocket:
        await websocket.send(
            json.dumps(
                {
                    "mode": mode,
                    "chunk_size": chunk_size,
                    "chunk_interval": chunk_interval,
                    "encoder_chunk_look_back": int(os.getenv("FUNASR_ASR_ENCODER_LOOK_BACK", "4")),
                    "decoder_chunk_look_back": int(os.getenv("FUNASR_ASR_DECODER_LOOK_BACK", "0")),
                    "audio_fs": int(sample_rate),
                    "wav_name": "simulation-utterance",
                    "wav_format": "pcm",
                    "is_speaking": True,
                    "hotwords": os.getenv("FUNASR_ASR_HOTWORDS", ""),
                    "itn": use_itn,
                },
                ensure_ascii=False,
            )
        )

        async def receive_messages() -> None:
            while True:
                raw = await websocket.recv()
                message = json.loads(raw)
                messages.append(message)
                text = str(message.get("text") or "")
                msg_mode = str(message.get("mode") or "")
                if text:
                    if msg_mode in {"offline", "2pass-offline"}:
                        offline_parts.append(text)
                    elif msg_mode in {"online", "2pass-online"}:
                        online_parts.append(text)
                if message.get("is_final") or msg_mode in {"offline", "2pass-offline"}:
                    break

        receive_task = asyncio.create_task(receive_messages())
        try:
            for index in range(chunk_num):
                begin = index * stride
                await websocket.send(audio[begin : begin + stride])
                await asyncio.sleep(0.001)
            await websocket.send(json.dumps({"is_speaking": False}, ensure_ascii=False))
            await asyncio.wait_for(receive_task, timeout=timeout)
        finally:
            if not receive_task.done():
                receive_task.cancel()
            await websocket.close()

    final_text = "".join(offline_parts).strip() or "".join(online_parts).strip()
    return FunAsrTranscript(
        text=final_text,
        confidence=1.0 if final_text else 0.0,
        meta={
            "provider": "funasr",
            "mode": mode,
            "sample_rate": sample_rate,
            "audio_bytes": len(audio),
            "message_count": len(messages),
        },
    )
