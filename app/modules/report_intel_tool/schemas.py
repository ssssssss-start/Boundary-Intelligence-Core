from pydantic import BaseModel, Field


class ReportIntelAnalyzeRequest(BaseModel):
    content: str = Field(..., description="待研判的可疑链接、短信、聊天内容、账号或 App 信息")
    tool_session_id: str | None = Field(None, description="举报工具临时会话 ID，不等同于聊天会话")


class ReportIntelConfirmRequest(BaseModel):
    analysis_id: str = Field(..., description="研判草稿 ID")
    tool_session_id: str | None = Field(None, description="举报工具临时会话 ID，不等同于聊天会话")
    reporter_note: str | None = Field(None, description="用户确认举报时补充的说明")
