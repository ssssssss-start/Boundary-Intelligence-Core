import hmac
import os
import shutil
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import uvicorn
from fastapi import BackgroundTasks, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from starlette.staticfiles import StaticFiles

from app.core.logger import logger
from app.core.security import cors_origins
from app.core.security_middleware import SecurityMiddleware
from app.import_process.agent.main_graph import kb_import_app
from app.import_process.agent.state import create_default_state
from app.query_process.services.admin_auth_service import require_admin_user
from app.query_process.services.scam_intake_review_service import (
    create_intake_submission,
    get_submission_status,
)
from app.utils.path_util import PROJECT_ROOT
from app.utils.task_utils import (
    TASK_STATUS_COMPLETED,
    TASK_STATUS_FAILED,
    TASK_STATUS_PROCESSING,
    add_done_task,
    add_running_task,
    get_done_task_list,
    get_running_task_list,
    get_task_result,
    get_task_status,
    set_task_result,
    update_task_status,
)


app = FastAPI(
    title="Anti Fraud Knowledge Import Service",
    description="Submit new scam materials for Agent drafting, manual review and controlled publishing.",
)
app.add_middleware(SecurityMiddleware)
PAGE_ASSETS_DIR = PROJECT_ROOT / "app/query_process/page/assets"
if PAGE_ASSETS_DIR.exists():
    app.mount("/assets", StaticFiles(directory=PAGE_ASSETS_DIR), name="import_page_assets")

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins(),
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "X-Admin-Token", "X-Import-Admin-Token", "X-Requested-With"],
)


class ImportRequest(BaseModel):
    knowledge_file_path: Optional[str] = Field(
        None,
        description="反诈知识 JSON 文件路径；为空时使用 data/anti_fraud_knowledge_v2.json",
    )
    collection_name: str = Field("anti_fraud_knowledge", description="Milvus 目标集合名")


REQUIRED_INTAKE_FIELDS = ["fraud_name", "scam_scene", "target_users"]
MATERIAL_FIELDS = ["raw_dialogue", "incident_process", "keywords"]
MAX_FIELD_LENGTH = 12000


def _default_knowledge_path() -> str:
    return str((PROJECT_ROOT / "data" / "anti_fraud_knowledge_v2.json").resolve())


def _clean_text(value: Any) -> Any:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, list):
        return [_clean_text(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _clean_text(item) for key, item in value.items()}
    return value


def _normalize_intake_payload(payload: Dict[str, Any]) -> tuple[Dict[str, Any], Dict[str, Any]]:
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="提交内容必须是 JSON 对象")
    materials = payload.get("materials") if isinstance(payload.get("materials"), dict) else payload
    submitter = payload.get("submitter") if isinstance(payload.get("submitter"), dict) else {}
    materials = _clean_text(dict(materials or {}))
    submitter = _clean_text(dict(submitter or {}))
    if not submitter:
        submitter = {
            "name": materials.get("submitter_name", ""),
            "contact": materials.get("submitter_contact", ""),
            "team": materials.get("submitter_team", ""),
        }
    return materials, submitter


def _validate_intake_materials(materials: Dict[str, Any]) -> None:
    missing = [field for field in REQUIRED_INTAKE_FIELDS if not str(materials.get(field) or "").strip()]
    if missing:
        raise HTTPException(status_code=400, detail="缺少必填字段：" + "、".join(missing))
    if not any(str(materials.get(field) or "").strip() for field in MATERIAL_FIELDS):
        raise HTTPException(status_code=400, detail="请至少填写骗局流程描述或典型话术与关键词")
    for key, value in materials.items():
        if isinstance(value, str) and len(value) > MAX_FIELD_LENGTH:
            raise HTTPException(status_code=400, detail=f"字段过长：{key}，请压缩到 {MAX_FIELD_LENGTH} 字以内")


def _legacy_import_token_ok(request: Request) -> bool:
    secret = os.getenv("ANTI_FRAUD_IMPORT_ADMIN_TOKEN", "")
    supplied = request.headers.get("x-admin-token", "") or request.headers.get("x-import-admin-token", "")
    return bool(secret and supplied and hmac.compare_digest(secret, supplied))


def _assert_legacy_import_authorized(request: Request) -> None:
    if _legacy_import_token_ok(request):
        return
    try:
        require_admin_user(request)
        return
    except HTTPException as exc:
        raise HTTPException(
            status_code=403,
            detail="旧版 JSON 直导接口已关闭公开访问，请先登录管理员后台或配置 ANTI_FRAUD_IMPORT_ADMIN_TOKEN。",
        ) from exc


@app.get("/import.html", response_class=FileResponse)
async def get_import_page():
    """新增骗局材料提交页；不会直接写入正式知识库。"""
    html_abs_path = PROJECT_ROOT / "app/import_process/page/import.html"
    if not os.path.exists(html_abs_path):
        raise HTTPException(status_code=404, detail="import.html page not found")
    return FileResponse(path=html_abs_path, media_type="text/html")


@app.get("/health")
async def health():
    return {"ok": True, "service": "anti_fraud_import"}


@app.post("/intake/submit", summary="提交新增骗局材料进入人工审核")
async def submit_scam_intake(request: Request):
    try:
        payload = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail="请求体必须是 JSON") from exc
    materials, submitter = _normalize_intake_payload(payload)
    _validate_intake_materials(materials)
    result = create_intake_submission(materials, submitter=submitter)
    return {
        "code": 200,
        "message": "已提交人工审核。审核通过并发布前，不会进入正式知识库或向量库。",
        **result,
    }


@app.get("/intake/status/{submission_id}", summary="查询新增骗局材料审核状态")
async def intake_status(submission_id: str):
    return {"code": 200, **get_submission_status(submission_id)}


def run_graph_task(task_id: str, knowledge_file_path: Optional[str] = None, collection_name: str = "anti_fraud_knowledge"):
    """
    执行反诈知识结构化导入：
    JSON 读取 → 字段校验 → MongoDB 主库写入 → embedding_text → BGE-M3 向量化 → Milvus 全量重建。
    """
    try:
        update_task_status(task_id, TASK_STATUS_PROCESSING)
        init_state = create_default_state(
            task_id=task_id,
            knowledge_file_path=knowledge_file_path or _default_knowledge_path(),
            collection_name=collection_name,
        )

        final_state: Dict[str, Any] = {}
        for event in kb_import_app.stream(init_state):
            for node_name, node_result in event.items():
                logger.info(f"[{task_id}] 反诈导入节点完成：{node_name}")
                add_done_task(task_id, node_name)
                if isinstance(node_result, dict):
                    final_state.update(node_result)

        update_task_status(task_id, TASK_STATUS_COMPLETED)
        set_task_result(task_id, "collection_name", final_state.get("collection_name", collection_name))
        set_task_result(task_id, "total_count", str(final_state.get("total_count", 0)))
        set_task_result(task_id, "mongo_imported_count", str(final_state.get("mongo_imported_count", 0)))
        set_task_result(task_id, "imported_count", str(final_state.get("imported_count", 0)))
        logger.info(f"[{task_id}] 反诈知识导入完成：{final_state}")
    except Exception as e:
        update_task_status(task_id, TASK_STATUS_FAILED)
        set_task_result(task_id, "error", str(e))
        logger.error(f"[{task_id}] 反诈知识导入失败：{e}", exc_info=True)


@app.post("/import/default", summary="受控导入默认反诈知识库")
async def import_default(http_request: Request, background_tasks: BackgroundTasks, request: ImportRequest = ImportRequest()):
    _assert_legacy_import_authorized(http_request)
    task_id = str(uuid.uuid4())
    add_running_task(task_id, "upload_file")
    add_done_task(task_id, "upload_file")
    update_task_status(task_id, TASK_STATUS_PROCESSING)
    background_tasks.add_task(
        run_graph_task,
        task_id,
        request.knowledge_file_path or _default_knowledge_path(),
        request.collection_name,
    )
    return {
        "code": 200,
        "message": "Anti-fraud knowledge import started.",
        "task_id": task_id,
        "knowledge_file_path": request.knowledge_file_path or _default_knowledge_path(),
        "collection_name": request.collection_name,
    }


@app.post("/upload", summary="受控上传反诈知识 JSON 并导入")
async def upload_files(http_request: Request, background_tasks: BackgroundTasks, files: List[UploadFile] = File(...)):
    _assert_legacy_import_authorized(http_request)
    """
    兼容原上传接口，但现在只接受结构化反诈知识 JSON 文件。
    每个上传文件会触发一次独立导入任务。
    """
    date_dir = PROJECT_ROOT / "output" / datetime.now().strftime("%Y%m%d")
    task_ids: List[str] = []

    for file in files:
        if not file.filename.lower().endswith(".json"):
            raise HTTPException(status_code=400, detail=f"仅支持 JSON 反诈知识文件：{file.filename}")

        task_id = str(uuid.uuid4())
        task_ids.append(task_id)
        add_running_task(task_id, "upload_file")

        task_dir = date_dir / task_id
        task_dir.mkdir(parents=True, exist_ok=True)
        local_file_path = task_dir / file.filename

        with local_file_path.open("wb") as file_buffer:
            shutil.copyfileobj(file.file, file_buffer)

        add_done_task(task_id, "upload_file")
        update_task_status(task_id, TASK_STATUS_PROCESSING)
        background_tasks.add_task(run_graph_task, task_id, str(local_file_path), "anti_fraud_knowledge")
        logger.info(f"[{task_id}] 已上传反诈知识 JSON 并启动导入：{local_file_path}")

    return {
        "code": 200,
        "message": f"Anti-fraud knowledge files uploaded, total: {len(files)}",
        "task_ids": task_ids,
    }


@app.get("/status/{task_id}", summary="任务状态查询")
async def get_task_progress(task_id: str):
    return {
        "code": 200,
        "task_id": task_id,
        "status": get_task_status(task_id),
        "done_list": get_done_task_list(task_id),
        "running_list": get_running_task_list(task_id),
        "collection_name": get_task_result(task_id, "collection_name", ""),
        "total_count": get_task_result(task_id, "total_count", "0"),
        "mongo_imported_count": get_task_result(task_id, "mongo_imported_count", "0"),
        "imported_count": get_task_result(task_id, "imported_count", "0"),
        "error": get_task_result(task_id, "error", ""),
    }


if __name__ == "__main__":
    logger.info("Anti Fraud Knowledge Import Service starting...")
    uvicorn.run(app=app, host="127.0.0.1", port=8000)
