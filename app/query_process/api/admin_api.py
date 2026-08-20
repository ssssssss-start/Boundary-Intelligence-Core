from fastapi import APIRouter, HTTPException, Query, Request

from app.clients.mongo_business_utils import (
    list_risk_rules,
    search_anti_fraud_knowledge,
    upsert_anti_fraud_knowledge,
    upsert_risk_rules,
)
from app.query_process.agent.nodes.node_rule_engine import _load_rules
from app.query_process.api.schemas import (
    HotRuleUpsertRequest,
    KnowledgeUpsertRequest,
    RuleConfigRollbackRequest,
    RulePackageUpsertRequest,
    RuleUpsertRequest,
)
from app.query_process.services.rule_config_manager import (
    list_rule_config_backups,
    list_scam_package_configs,
    rollback_rule_config,
    upsert_hot_rule_config,
    upsert_scam_package_config,
)
from app.query_process.services.scam_rule_engine import reload_rule_config
from app.query_process.services.admin_auth_service import require_admin_user


router = APIRouter(tags=["admin"])


def _admin(request: Request):
    return require_admin_user(request)


@router.get("/admin/rules")
async def admin_list_rules(request: Request, enabled_only: bool = Query(False, description="是否只返回启用规则")):
    _admin(request)
    rules = list_risk_rules(enabled_only=enabled_only)
    return {"message": "规则列表查询完成", "items": rules, "total": len(rules)}


@router.post("/admin/rules")
async def admin_upsert_rules(payload: RuleUpsertRequest, request: Request):
    _admin(request)
    records = []
    if payload.rule:
        records.append(payload.rule)
    if payload.rules:
        records.extend(payload.rules)
    count = upsert_risk_rules(records, source="admin_api")
    _load_rules.cache_clear()
    return {"message": "规则已保存", "count": count}


@router.get("/admin/rule-config/packages")
async def admin_list_rule_packages(request: Request):
    _admin(request)
    return {"message": "规则配置包列表查询完成", **list_scam_package_configs()}


@router.post("/admin/rule-config/packages")
async def admin_upsert_rule_package(payload: RulePackageUpsertRequest, request: Request):
    _admin(request)
    try:
        return upsert_scam_package_config(payload.package, hot_reload=payload.hot_reload)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/admin/rule-config/hot-rule")
async def admin_upsert_hot_rule(payload: HotRuleUpsertRequest, request: Request):
    _admin(request)
    try:
        return upsert_hot_rule_config(payload.rule, hot_reload=payload.hot_reload)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/admin/rule-config/reload")
async def admin_reload_rule_config(request: Request):
    _admin(request)
    return reload_rule_config()


@router.get("/admin/rule-config/backups")
async def admin_list_rule_config_backups(request: Request, package_id: str = Query("", description="可选配置包 ID")):
    _admin(request)
    return {"message": "规则配置备份列表查询完成", **list_rule_config_backups(package_id or None)}


@router.post("/admin/rule-config/rollback")
async def admin_rollback_rule_config(payload: RuleConfigRollbackRequest, request: Request):
    _admin(request)
    try:
        return rollback_rule_config(payload.backup_id, hot_reload=payload.hot_reload)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/admin/knowledge")
async def admin_list_knowledge(
    request: Request,
    query: str = Query("", description="关键词"),
    limit: int = Query(20, ge=1, le=50, description="返回数量"),
):
    _admin(request)
    items = search_anti_fraud_knowledge(query, limit=limit)
    return {"message": "知识列表查询完成", "items": items, "total": len(items)}


@router.post("/admin/knowledge")
async def admin_upsert_knowledge(payload: KnowledgeUpsertRequest, request: Request):
    _admin(request)
    records = []
    if payload.item:
        records.append(payload.item)
    if payload.items:
        records.extend(payload.items)
    count = upsert_anti_fraud_knowledge(records, source_file="admin_api")
    return {"message": "知识已保存", "count": count}
