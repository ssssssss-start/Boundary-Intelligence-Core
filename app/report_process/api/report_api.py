from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.report_process.services.report_service import create_report


router = APIRouter(tags=["report"])


class ReportCreateRequest(BaseModel):
    report_type: str = Field(..., description="举报类型：链接、聊天内容、账号、电话、App、二维码等")
    content: str = Field(..., description="举报内容")
    platform: str = Field("", description="发生平台")
    has_paid: bool = Field(False, description="是否已转账")
    amount: str = Field("", description="涉及金额，可选")
    contact: str = Field("", description="联系方式，可选")
    note: str = Field("", description="补充说明")


@router.post("/report/create")
async def report_create(request: ReportCreateRequest):
    report = create_report(request.model_dump())
    return {"message": "举报工单已生成", "report": report, **report}
