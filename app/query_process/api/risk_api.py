from fastapi import APIRouter

from app.clients.mongo_business_utils import write_audit_log
from app.query_process.api.schemas import RiskCheckRequest
from app.query_process.services.risk_service import evaluate_risk_text
from app.report_process.services.desensitize_service import desensitize_text


router = APIRouter(tags=["risk"])


@router.post("/risk/check")
async def risk_check(request: RiskCheckRequest):
    result = evaluate_risk_text(request.user_text)
    write_audit_log(
        "risk_check",
        {
            "input": desensitize_text(request.user_text),
            "risk_level": result["risk_level"],
            "scam_type": result["scam_type"],
        },
    )
    return {"message": "风险研判完成", **result}
