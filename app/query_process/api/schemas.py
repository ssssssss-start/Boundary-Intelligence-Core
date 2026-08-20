from typing import Any, Dict

from pydantic import BaseModel, Field


class QueryRequest(BaseModel):
    query: str = Field(..., description="查询内容")
    session_id: str | None = Field(None, description="会话ID")
    is_stream: bool = Field(False, description="是否流式返回")
    intent_hint: str | None = Field(None, description="前端快捷入口给出的意图提示，不作为最终路由结论")


class RiskCheckRequest(BaseModel):
    user_text: str = Field(..., description="用户描述的风险场景")
    user_profile: Dict[str, Any] = Field(default_factory=dict, description="用户画像，可选")


class UrlCheckRequest(BaseModel):
    content: str = Field(..., description="待检测 URL、短信或聊天文本")


class RuleUpsertRequest(BaseModel):
    rule: Dict[str, Any] | None = Field(None, description="单条规则")
    rules: list[Dict[str, Any]] | None = Field(None, description="批量规则")


class RulePackageUpsertRequest(BaseModel):
    package: Dict[str, Any] = Field(..., description="Scam Package JSON 配置包")
    hot_reload: bool = Field(True, description="保存后是否立即热更新")


class HotRuleUpsertRequest(BaseModel):
    rule: Dict[str, Any] = Field(..., description="单条可热更新规则，支持 must_include_any 关键词组")
    hot_reload: bool = Field(True, description="保存后是否立即热更新")


class RuleConfigRollbackRequest(BaseModel):
    backup_id: str = Field(..., description="回滚备份 ID，形如 package_id/file.json")
    hot_reload: bool = Field(True, description="回滚后是否立即热更新")


class KnowledgeUpsertRequest(BaseModel):
    item: Dict[str, Any] | None = Field(None, description="单条知识")
    items: list[Dict[str, Any]] | None = Field(None, description="批量知识")
