from fastapi import APIRouter, HTTPException

from app.modules.report_intel_tool.schemas import ReportIntelAnalyzeRequest, ReportIntelConfirmRequest
from app.modules.report_intel_tool.service import analyze_report_content, confirm_report_analysis


router = APIRouter(prefix="/report-intel", tags=["module:report-intel-tool"])


@router.post("/analyze")
async def report_intel_analyze(request: ReportIntelAnalyzeRequest):
    try:
        return analyze_report_content(
            content=request.content,
            tool_session_id=request.tool_session_id or "",
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/confirm")
async def report_intel_confirm(request: ReportIntelConfirmRequest):
    try:
        return confirm_report_analysis(
            analysis_id=request.analysis_id,
            tool_session_id=request.tool_session_id or "",
            reporter_note=request.reporter_note or "",
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
