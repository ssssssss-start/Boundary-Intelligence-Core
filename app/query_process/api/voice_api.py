import asyncio
import base64
import io
import wave
import audioop

from fastapi import APIRouter, HTTPException, Response, WebSocket
from pydantic import BaseModel, Field

from app.modules.voice.funasr_asr_service import transcribe_funasr_pcm
from app.modules.voice.kokoro_tts_service import synthesize_kokoro_wav, warmup_kokoro_tts
from app.modules.voice.realtime_voice_service import handle_realtime_voice_websocket


router = APIRouter(tags=["module:voice"])


class KokoroTtsRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=500)
    sid: int = Field(3, ge=0, le=200)
    speed: float = Field(1.0, ge=0.5, le=1.5)


class FunAsrRequest(BaseModel):
    audio_base64: str = Field(..., min_length=1)
    sample_rate: int = Field(16000, ge=8000, le=48000)
    audio_format: str = Field("pcm_s16le")


@router.websocket("/game/simulation/realtime-voice/ws")
async def realtime_voice_ws(websocket: WebSocket):
    await handle_realtime_voice_websocket(websocket)


@router.post("/game/simulation/tts")
async def simulation_tts(request: KokoroTtsRequest):
    try:
        result = await asyncio.to_thread(
            synthesize_kokoro_wav,
            text=request.text,
            sid=request.sid,
            speed=request.speed,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return Response(
        content=result["audio"],
        media_type="audio/wav",
        headers={
            "X-TTS-Provider": "kokoro",
            "X-TTS-Sample-Rate": str(result.get("sample_rate") or ""),
            "X-TTS-Speaker": str(result.get("sid") or request.sid),
        },
    )


@router.post("/game/simulation/tts/warmup")
async def simulation_tts_warmup(request: KokoroTtsRequest):
    try:
        result = await asyncio.to_thread(warmup_kokoro_tts, sid=request.sid)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return result


def _wav_to_pcm_s16le(audio: bytes, target_sample_rate: int = 16000) -> tuple[bytes, int]:
    if not audio.startswith(b"RIFF"):
        return audio, target_sample_rate

    with wave.open(io.BytesIO(audio), "rb") as wav:
        channels = wav.getnchannels()
        sample_width = wav.getsampwidth()
        source_sample_rate = wav.getframerate()
        frames = wav.readframes(wav.getnframes())

    if sample_width == 1:
        frames = audioop.bias(frames, 1, -128)

    if channels > 1:
        frames = audioop.tomono(frames, sample_width, 0.5, 0.5)
        channels = 1

    if sample_width != 2:
        frames = audioop.lin2lin(frames, sample_width, 2)
        sample_width = 2

    if source_sample_rate != target_sample_rate:
        frames, _ = audioop.ratecv(frames, sample_width, channels, source_sample_rate, target_sample_rate, None)
        source_sample_rate = target_sample_rate

    return frames, source_sample_rate


@router.post("/game/simulation/asr")
async def simulation_asr(request: FunAsrRequest):
    audio_format = request.audio_format.strip().lower()
    if audio_format not in {"pcm_s16le", "wav"}:
        raise HTTPException(status_code=400, detail="audio_format must be pcm_s16le or wav")
    try:
        audio = base64.b64decode(request.audio_base64)
        sample_rate = request.sample_rate
        if audio_format == "wav":
            audio, sample_rate = _wav_to_pcm_s16le(audio, target_sample_rate=request.sample_rate)
        result = await transcribe_funasr_pcm(audio=audio, sample_rate=sample_rate)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return {
        "text": result.text,
        "confidence": result.confidence,
        "provider": "funasr",
        "meta": result.meta,
    }
