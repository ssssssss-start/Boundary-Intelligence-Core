"""Runtime regression checks for the expanded anti-fraud knowledge base.

This script intentionally avoids pytest so it can run in the current project
environment with only the bundled virtualenv.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

PACKAGE_DIR = ROOT / "app" / "query_process" / "rules" / "scam_packages"
KNOWLEDGE_DIR = ROOT / "data" / "knowledge"
CHAT_HTML = ROOT / "app" / "query_process" / "page" / "chat.html"

EXPECTED_CLOSED_SCENE_TEXT = (
    "我是您的反诈骗小卫士 🛡️\n"
    "专门帮您识破冒充客服、刷单返利、虚假贷款这些骗局。\n"
    "您只要记住：陌生链接别乱点，可疑电话多核实，转账汇款先问我。\n"
    "有什么拿不准的情况，直接发给我，我帮您把关。\n\n"
    "请问您想咨询什么，或者有遇到可疑的事情吗？"
)

EXPECTED_PACKAGES = {
    "scam_cross_border_high_salary": "跨境高薪招工诱骗诈骗",
    "scam_elderly_health_product": "养老保健品诈骗",
    "scam_national_asset_project": "民族资产解冻/虚假国家项目诈骗",
    "scam_medical_insurance_fund": "医保骗保/医保卡倒卖诈骗",
    "scam_virtual_currency_laundering": "虚拟货币洗钱跑分诈骗",
    "scam_live_commerce_private_trade": "直播带货/私域交易诈骗",
}

RUNTIME_CASES = [
    {
        "text": "有人说出国做客服月薪三万 包签证 让我先交路费和护照照片",
        "fraud_type": "跨境高薪招工诱骗诈骗",
        "min_score": 90,
        "required_features": ["境外高薪诱导", "出境前收费", "索要证件材料"],
        "required_rule": "PKG_CROSS_BORDER_HIGH_SALARY_001",
    },
    {
        "text": "免费体检后专家让我买保健品套餐",
        "fraud_type": "养老保健品诈骗",
        "min_score": 70,
        "required_features": ["免费讲座义诊", "高价预存套餐"],
        "required_rule": "PKG_ELDERLY_HEALTH_PRODUCT_002",
    },
    {
        "text": "群里说国家项目交激活费就能领几十万补贴",
        "fraud_type": "民族资产解冻/虚假国家项目诈骗",
        "min_score": 90,
        "required_features": ["国家项目包装", "缴费领取补贴", "巨额分红承诺"],
        "required_rule": "PKG_NATIONAL_ASSET_PROJECT_001",
    },
    {
        "text": "有人让我把医保码给他刷药返钱",
        "fraud_type": "医保骗保/医保卡倒卖诈骗",
        "min_score": 80,
        "required_features": ["外借医保凭证", "刷医保返钱"],
        "required_rule": "PKG_MEDICAL_INSURANCE_FUND_001",
    },
    {
        "text": "有人让我刷流水收款后买USDT",
        "fraud_type": "虚拟货币洗钱跑分诈骗",
        "min_score": 90,
        "required_features": ["高佣金跑分", "虚拟币转移资金"],
        "required_rule": "PKG_VIRTUAL_CURRENCY_LAUNDERING_001",
    },
    {
        "text": "直播间客服让我加微信私下扫码付款买低价手机",
        "fraud_type": "直播带货/私域交易诈骗",
        "min_score": 80,
        "required_features": ["明显低价诱导", "私下扫码付款", "引导私域下单"],
        "required_rule": "PKG_LIVE_PRIVATE_TRADE_001",
    },
]


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _fail(errors: List[str], message: str) -> None:
    errors.append(message)


def validate_package_loading(errors: List[str]) -> Dict[str, Any]:
    from app.query_process.services.scam_rule_engine import load_scam_packages

    load_scam_packages.cache_clear()
    packages = load_scam_packages()
    by_id = {str(package.get("scam_id") or ""): package for package in packages}
    for scam_id, name in EXPECTED_PACKAGES.items():
        package = by_id.get(scam_id)
        if not package:
            _fail(errors, f"缺少 Scam Package：{scam_id}")
            continue
        if package.get("name") != name:
            _fail(errors, f"{scam_id} name 不匹配：{package.get('name')} != {name}")
        if len(package.get("features") or []) < 5:
            _fail(errors, f"{scam_id} 至少需要 5 个实时识别特征")
        if not package.get("rules"):
            _fail(errors, f"{scam_id} 缺少实时规则")
        if not package.get("source_refs"):
            _fail(errors, f"{scam_id} 缺少 source_refs")

    return {
        "package_count": len(packages),
        "expected_package_count": len(EXPECTED_PACKAGES),
        "package_files": len(list(PACKAGE_DIR.glob("*.json"))),
    }


def validate_runtime_cases(errors: List[str]) -> List[Dict[str, Any]]:
    from app.query_process.services.scam_rule_engine import evaluate_rule_text, load_scam_packages

    load_scam_packages.cache_clear()
    results: List[Dict[str, Any]] = []
    for case in RUNTIME_CASES:
        result = evaluate_rule_text(str(case["text"]))
        matched_rule_ids = [str(rule.get("rule_id") or "") for rule in result.get("matched_rules") or []]
        features = [str(item) for item in result.get("risk_features") or []]
        fraud_type = str(result.get("fraud_type") or "")
        score = int(result.get("risk_score") or 0)

        if fraud_type != case["fraud_type"]:
            _fail(errors, f"场景误判：{case['text']} => {fraud_type}，期望 {case['fraud_type']}")
        if score < int(case["min_score"]):
            _fail(errors, f"风险分不足：{case['text']} => {score}，期望 >= {case['min_score']}")
        missing_features = [item for item in case["required_features"] if item not in features]
        if missing_features:
            _fail(errors, f"场景缺少特征：{case['text']} => {missing_features}")
        if case["required_rule"] not in matched_rule_ids:
            _fail(errors, f"场景未命中新规则：{case['text']} => {case['required_rule']}")

        results.append(
            {
                "text": case["text"],
                "fraud_type": fraud_type,
                "risk_score": score,
                "top_rules": matched_rule_ids[:3],
                "features": features,
            }
        )
    return results


def validate_sources_and_bundle(errors: List[str]) -> Dict[str, Any]:
    from scripts.import_education_rag_knowledge import build_bundle

    sources = _load_json(KNOWLEDGE_DIR / "official_sources.json")
    source_urls = {str(item.get("url") or "") for item in sources}
    for path in KNOWLEDGE_DIR.glob("*.json"):
        data = _load_json(path)
        if not isinstance(data, list):
            continue
        for row in data:
            if not isinstance(row, dict):
                continue
            for ref in row.get("source_refs") or []:
                ref = str(ref or "")
                if ref.startswith("http") and ref not in source_urls:
                    _fail(errors, f"{path.name} 存在未登记来源：{ref}")

    bundle = build_bundle()
    official_source_docs = [
        doc for doc in bundle.get("rag_documents", []) if doc.get("doc_type") == "official_source"
    ]
    if len(official_source_docs) != len(sources):
        _fail(errors, f"official_source RAG 文档数不匹配：{len(official_source_docs)} != {len(sources)}")
    if not bundle.get("official_sources"):
        _fail(errors, "导入 bundle 缺少 official_sources")

    return {
        "official_sources": len(sources),
        "bundle_scam_types": len(bundle.get("scam_types", [])),
        "bundle_intent_patterns": len(bundle.get("intent_patterns", [])),
        "bundle_rag_documents": len(bundle.get("rag_documents", [])),
        "bundle_rag_chunks": len(bundle.get("rag_chunks", [])),
        "bundle_law_clauses": len(bundle.get("law_clauses", [])),
        "bundle_official_sources": len(bundle.get("official_sources", [])),
        "official_source_rag_documents": len(official_source_docs),
    }


def validate_fixed_copy(errors: List[str]) -> Dict[str, Any]:
    from app.query_process.services.semantic_risk_agent import ASSISTANT_CLOSED_SCENE_TEXT

    if ASSISTANT_CLOSED_SCENE_TEXT != EXPECTED_CLOSED_SCENE_TEXT:
        _fail(errors, "闭环收尾文案被改动")

    chat_html = CHAT_HTML.read_text(encoding="utf-8")
    removed_intro = "我是智能反诈助手，会先判断你是在了解反诈知识，还是正在遇到疑似诈骗"
    if removed_intro in chat_html:
        _fail(errors, "chat.html 仍包含用户要求移除的初始开场白")
    if 'intro: ""' not in chat_html:
        _fail(errors, "知识助手首页 intro 不是空字符串")

    return {
        "closed_scene_text_locked": ASSISTANT_CLOSED_SCENE_TEXT == EXPECTED_CLOSED_SCENE_TEXT,
        "knowledge_intro_empty": 'intro: ""' in chat_html and removed_intro not in chat_html,
    }


def validate_topic_and_route_guards(errors: List[str]) -> Dict[str, Any]:
    from app.modules.knowledge_assistant.knowledge_dialogue_agent import _scam_catalog, match_dialogue_topic
    from app.modules.knowledge_assistant.service import _wall_cross_border_job_risk_route

    _scam_catalog.cache_clear()
    topic = match_dialogue_topic("什么是直播带货私域交易诈骗")
    topic_name = str(((topic or {}).get("scam") or {}).get("name") or "")
    if topic_name != "直播带货/私域交易诈骗":
        _fail(errors, f"直播带货私域交易教学主题匹配失败：{topic_name}")

    route = _wall_cross_border_job_risk_route("墙壁上贴着出国高工资 是真的吗")
    workflow = str((route or {}).get("workflow_mode") or "")
    if workflow != "risk_case_flow":
        _fail(errors, f"墙壁出国高工资未进入风险流程：{workflow}")

    return {
        "live_private_trade_topic": topic_name,
        "wall_cross_border_route": workflow,
    }


def main() -> int:
    errors: List[str] = []
    package_stats = validate_package_loading(errors)
    runtime_results = validate_runtime_cases(errors)
    bundle_stats = validate_sources_and_bundle(errors)
    copy_stats = validate_fixed_copy(errors)
    guard_stats = validate_topic_and_route_guards(errors)

    if errors:
        for error in errors:
            print(f"[ERROR] {error}")
        return 1

    print("扩展知识库运行时校验通过。")
    print("Scam Package 统计：" + json.dumps(package_stats, ensure_ascii=False, sort_keys=True))
    print("导入 Bundle 统计：" + json.dumps(bundle_stats, ensure_ascii=False, sort_keys=True))
    print("固定话术校验：" + json.dumps(copy_stats, ensure_ascii=False, sort_keys=True))
    print("话题/路由护栏校验：" + json.dumps(guard_stats, ensure_ascii=False, sort_keys=True))
    print("运行时场景结果：")
    for item in runtime_results:
        print(json.dumps(item, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
