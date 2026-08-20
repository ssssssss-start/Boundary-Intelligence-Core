from fastapi import APIRouter

from app.clients.mongo_business_utils import write_audit_log
from app.query_process.api.schemas import UrlCheckRequest
from app.query_process.services.risk_service import check_url_content
from app.report_process.services.desensitize_service import desensitize_text


router = APIRouter(tags=["url"])


@router.post("/url/check")
async def url_check(request: UrlCheckRequest):
    result = check_url_content(request.content)
    write_audit_log(
        "url_check",
        {
            "input": desensitize_text(request.content),
            "risk_level": result["risk_level"],
            "risk_rules": result["risk_rules"],
        },
    )
    return {"message": "URL/内容检测完成", **result}
