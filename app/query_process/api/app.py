import asyncio
import logging
import os
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, RedirectResponse
from starlette.middleware.cors import CORSMiddleware
from starlette.staticfiles import StaticFiles

from app.clients.mongo_business_utils import (
    delete_report_tickets_for_session,
    delete_user_game_progress,
    init_business_collections,
)
from app.clients.mongo_history_utils import clear_history
from app.modules.emergency_dissuasion.api import router as emergency_dissuasion_router
from app.modules.knowledge_assistant.api import router as knowledge_assistant_router
from app.modules.knowledge_assistant.service import clear_education_session_memory
from app.modules.profile.api import router as profile_router
from app.modules.report_intel_tool.api import router as report_intel_tool_router
from app.modules.training_camp.api import router as training_camp_router
from app.query_process.api.admin_api import router as admin_router
from app.query_process.api.report_api import router as report_router
from app.query_process.api.risk_api import router as risk_router
from app.query_process.api.scam_admin_api import router as scam_admin_router
from app.query_process.api.url_api import router as url_router
from app.query_process.api.voice_api import router as voice_router
from app.query_process.api.video_api import router as video_router
from app.modules.voice.kokoro_tts_service import warmup_kokoro_tts
from app.core.security import cors_origins
from app.core.security_middleware import SecurityMiddleware
from app.query_process.services.admin_auth_service import require_admin_user


PAGE_DIR = Path(__file__).absolute().parent.parent / "page"
PAGE_ASSETS_DIR = PAGE_DIR / "assets"
GAME_IMAGES_DIR = Path(__file__).absolute().parents[2] / "game_process" / "data" / "images"

app = FastAPI(title="anti fraud query service", description="金融反诈 RAG 风险识别服务")
app.add_middleware(SecurityMiddleware)
app.mount("/assets", StaticFiles(directory=PAGE_ASSETS_DIR), name="query_page_assets")
if GAME_IMAGES_DIR.exists():
    app.mount("/game-images", StaticFiles(directory=GAME_IMAGES_DIR), name="game_images")

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins(),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Requested-With"],
)

app.include_router(knowledge_assistant_router)
app.include_router(emergency_dissuasion_router)
app.include_router(report_intel_tool_router)
app.include_router(training_camp_router)
app.include_router(voice_router)
app.include_router(profile_router)
app.include_router(risk_router)
app.include_router(url_router)
app.include_router(report_router)
app.include_router(admin_router)
app.include_router(scam_admin_router)
app.include_router(video_router)


logger = logging.getLogger(__name__)


@app.on_event("startup")
async def warmup_local_tts() -> None:
    if os.getenv("KOKORO_TTS_STARTUP_WARMUP", "1").lower() in {"0", "false", "no"}:
        return

    async def _warmup() -> None:
        try:
            sid = int(os.getenv("KOKORO_TTS_WARMUP_SID", "3") or "3")
            await asyncio.to_thread(warmup_kokoro_tts, sid=sid)
            logger.info("Kokoro TTS warmup completed")
        except Exception as exc:
            logger.warning("Kokoro TTS warmup failed: %s", exc)

    asyncio.create_task(_warmup())


@app.get("/health")
async def health():
    return {"ok": True}


@app.post("/db/init")
async def db_init(request: Request):
    require_admin_user(request)
    collections = init_business_collections()
    return {"message": "业务集合初始化完成", "collections": collections}


@app.delete("/sessions/{module}/{session_id}")
async def delete_workspace_session(module: str, session_id: str, request: Request):
    # Session deletion touches server-side conversation memory and must not be
    # callable by an anonymous browser with a guessed session ID.
    require_admin_user(request)
    deleted = {"history": 0, "knowledge_memory": 0, "report_tickets": 0, "training_progress": 0}
    normalized = (module or "").strip().lower()
    deleted["history"] = clear_history(session_id)
    if normalized in {"knowledge", "knowledge_assistant", "assistant", "all"}:
        deleted["knowledge_memory"] = 1 if clear_education_session_memory(session_id) else 0
    if normalized in {"report", "suspicious_report", "suspicious", "all"}:
        try:
            deleted["report_tickets"] = delete_report_tickets_for_session(session_id)
        except Exception:
            deleted["report_tickets"] = 0
    if normalized in {"training", "training_camp", "game", "all"}:
        try:
            deleted["training_progress"] = delete_user_game_progress(session_id)
        except Exception:
            deleted["training_progress"] = 0
    return {"message": "Session memory deleted", "module": module, "session_id": session_id, "deleted": deleted}


def _page_response(filename: str) -> FileResponse:
    page_path = PAGE_DIR / filename
    if not page_path.exists():
        raise HTTPException(status_code=404, detail=f"没有查询到页面，地址为：{page_path}！")
    return FileResponse(page_path)


@app.get("/")
async def index_page():
    return RedirectResponse(url="/chat.html")


@app.get("/chat.html")
async def chat_page():
    return _page_response("chat.html")


@app.get("/emergency.html")
async def emergency_page():
    return RedirectResponse(url="/chat.html?module=emergency")


@app.get("/training.html")
async def training_page():
    return RedirectResponse(url="/chat.html?module=training")


@app.get("/profile.html")
async def profile_page():
    return _page_response("profile.html")


@app.get("/admin/review.html")
async def admin_review_page():
    return _page_response("admin_review.html")


@app.get("/admin/publish.html")
async def admin_publish_page():
    return RedirectResponse(url="/admin/review.html#publish")


@app.get("/admin/versions.html")
async def admin_versions_page():
    return RedirectResponse(url="/admin/review.html#versions")
