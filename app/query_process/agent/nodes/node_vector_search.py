"""反诈知识库向量检索节点。

Milvus 只作为语义检索索引，MongoDB 才是知识业务主库。
检索流程：
1. 用 retrieval_query 生成 BGE-M3 dense/sparse 混合向量。
2. 在 Milvus 中召回 knowledge_id 和摘要字段。
3. 用 knowledge_id 回查 MongoDB，拿完整知识内容。
4. 根据路由、干预目标、诈骗类型、风险标签进行重排和多样化。
"""

import os
from typing import Any, Dict, List

from app.anti_fraud.schema import KNOWLEDGE_TYPES
from app.clients.mongo_business_utils import get_anti_fraud_knowledge_by_ids
from app.clients.milvus_utils import create_hybrid_search_requests, get_milvus_client, hybrid_search
from app.conf.milvus_config import milvus_config
from app.core.logger import logger
from app.lm.embedding_utils import generate_embeddings
from app.query_process.agent.nodes.common import append_warning, mark_node_done, mark_node_start


NODE_NAME = "node_vector_search"
TOP_K = 5
RAW_TOP_K = 30

ROUTE_TYPE_ORDER = {
    "prevention_consult": [
        "risk_signal",
        "prevention_advice",
        "persuasion_script",
        "fraud_process",
        "fraud_case",
    ],
    "loss_response": [
        "intervention_action",
        "evidence_guide",
        "police_report_guide",
        "bank_stop_guide",
        "persuasion_script",
    ],
    "education": [
        "fraud_definition",
        "fraud_process",
        "fraud_case",
        "risk_signal",
        "prevention_advice",
    ],
}


def _knowledge_disabled() -> bool:
    """聊天主链路默认关闭本地知识库。

    需要重新启用 RAG 时，显式设置 ANTI_FRAUD_ENABLE_LOCAL_KNOWLEDGE=true。
    """
    return os.getenv("ANTI_FRAUD_ENABLE_LOCAL_KNOWLEDGE", "").strip().lower() not in {"1", "true", "yes", "on"}


def _collection_name() -> str:
    """读取反诈知识 Milvus 集合名，支持环境变量覆盖。"""
    return (
        os.getenv("ANTI_FRAUD_COLLECTION")
        or os.getenv("FRAUD_KNOWLEDGE_COLLECTION")
        or milvus_config.anti_fraud_collection
        or "anti_fraud_knowledge"
    )


def _hit_to_doc(hit: Any) -> Dict[str, Any]:
    """把 Milvus 命中结果转换成统一的文档字典。"""
    if isinstance(hit, dict):
        entity = hit.get("entity") or hit
        score = hit.get("distance", hit.get("score", hit.get("similarity", 0)))
    else:
        entity = getattr(hit, "entity", {}) or {}
        score = getattr(hit, "distance", getattr(hit, "score", 0))

    if hasattr(entity, "to_dict"):
        entity = entity.to_dict()
    if not isinstance(entity, dict):
        entity = {}

    title = entity.get("title") or ""
    content = entity.get("content") or ""
    doc_id = entity.get("knowledge_id") or entity.get("id") or entity.get("doc_id") or ""
    fraud_type = entity.get("fraud_type") or ""
    risk_tags = entity.get("risk_tags") or []
    risk_tags_text = entity.get("risk_tags_text", "")
    if not risk_tags and risk_tags_text:
        risk_tags = [tag.strip() for tag in risk_tags_text.split(",") if tag.strip()]
    applicable_routes = [item.strip() for item in entity.get("applicable_routes_text", "").split(",") if item.strip()]
    case_types = [item.strip() for item in entity.get("case_types_text", "").split(",") if item.strip()]
    intervention_goals = [
        item.strip() for item in entity.get("intervention_goals_text", "").split(",") if item.strip()
    ]

    return {
        "id": str(doc_id),
        "knowledge_type": entity.get("knowledge_type", "knowledge"),
        "fraud_type": fraud_type,
        "fraud_stage": entity.get("fraud_stage", ""),
        "title": title,
        "summary": entity.get("summary", ""),
        "content": content,
        "risk_tags": risk_tags,
        "applicable_routes": applicable_routes,
        "applicable_case_types": case_types,
        "intervention_goals": intervention_goals,
        "user_stage": entity.get("user_stage", ""),
        "use_when": entity.get("use_when", ""),
        "do_not_use_when": entity.get("do_not_use_when", ""),
        "answer_role": entity.get("answer_role", ""),
        "priority": int(entity.get("priority") or 0),
        "risk_level": entity.get("risk_level", ""),
        "source": entity.get("source", ""),
        "score": float(score or 0),
    }


def _hydrate_docs_from_mongo(hit_docs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """根据 Milvus 返回的 knowledge_id 从 MongoDB 回查完整知识。"""
    ids = [doc.get("id", "") for doc in hit_docs if doc.get("id")]
    if not ids:
        return hit_docs

    try:
        mongo_docs = get_anti_fraud_knowledge_by_ids(ids)
    except Exception as e:
        logger.warning(f"MongoDB 回查反诈知识失败，使用 Milvus 摘要字段降级：{e}")
        return hit_docs

    by_id = {doc.get("knowledge_id"): doc for doc in mongo_docs}
    hydrated: List[Dict[str, Any]] = []
    for hit_doc in hit_docs:
        knowledge_id = hit_doc.get("id", "")
        source_doc = by_id.get(knowledge_id)
        if not source_doc:
            hydrated.append(hit_doc)
            continue

        merged = dict(source_doc)
        merged["id"] = knowledge_id
        merged["score"] = hit_doc.get("score", 0)
        merged["risk_tags"] = merged.get("risk_tags") or hit_doc.get("risk_tags", [])
        merged["applicable_routes"] = merged.get("applicable_routes") or hit_doc.get("applicable_routes", [])
        merged["applicable_case_types"] = [
            str(value) for value in (merged.get("applicable_case_types") or hit_doc.get("applicable_case_types", []))
        ]
        hydrated.append(merged)
    return hydrated


def _rerank_docs(docs: List[Dict[str, Any]], state: Dict[str, Any]) -> List[Dict[str, Any]]:
    """根据当前案件状态对召回知识做业务重排。"""
    route_name = state.get("route_name", "")
    intervention_goal = state.get("intervention_goal", "")
    fraud_type = state.get("fraud_type", "")
    fraud_stage = state.get("fraud_stage", "")
    risk_features = set(state.get("normalized_risk_features") or state.get("risk_features") or [])
    case_type = str(state.get("case_context_type") or "")

    reranked: List[Dict[str, Any]] = []
    for doc in docs:
        final_score = float(doc.get("score") or 0)
        # 路由、案件类型、干预目标、诈骗类型越匹配，越适合放进 prompt。
        if route_name and route_name in doc.get("applicable_routes", []):
            final_score += 0.20
        if case_type and case_type in doc.get("applicable_case_types", []):
            final_score += 0.10
        if intervention_goal and intervention_goal in doc.get("intervention_goals", []):
            final_score += 0.25
        if fraud_type and fraud_type == doc.get("fraud_type"):
            final_score += 0.15
        if fraud_stage and fraud_stage == doc.get("fraud_stage"):
            final_score += 0.10
        overlap = risk_features.intersection(set(doc.get("risk_tags") or []))
        final_score += min(len(overlap) * 0.05, 0.20)
        final_score += min(int(doc.get("priority") or 0), 100) / 1000
        doc_copy = dict(doc)
        doc_copy["final_score"] = round(final_score, 6)
        doc_copy["matched_risk_tags"] = [tag for tag in doc.get("risk_tags", []) if tag in overlap]
        reranked.append(doc_copy)

    return sorted(reranked, key=lambda item: item.get("final_score", 0), reverse=True)


def _diversify_docs(docs: List[Dict[str, Any]], route_name: str = "", limit: int = TOP_K) -> List[Dict[str, Any]]:
    """按知识类型做多样化，避免返回 5 条全是同一种知识。"""
    if not docs:
        return []

    selected: List[Dict[str, Any]] = []
    selected_ids = set()
    type_order = ROUTE_TYPE_ORDER.get(route_name) or KNOWLEDGE_TYPES

    for knowledge_type in type_order:
        typed_docs = [doc for doc in docs if doc.get("knowledge_type") == knowledge_type]
        if not typed_docs:
            continue
        doc = typed_docs[0]
        doc_id = doc.get("id") or f"{doc.get('knowledge_type')}:{doc.get('title')}"
        if doc_id not in selected_ids:
            selected.append(doc)
            selected_ids.add(doc_id)
        if len(selected) >= limit:
            return selected

    for doc in docs:
        doc_id = doc.get("id") or f"{doc.get('knowledge_type')}:{doc.get('title')}"
        if doc_id in selected_ids:
            continue
        selected.append(doc)
        selected_ids.add(doc_id)
        if len(selected) >= limit:
            break

    return selected


def node_vector_search(state: Dict[str, Any]) -> Dict[str, Any]:
    """执行 Milvus 检索、Mongo 回查、重排和多样化选择。"""
    mark_node_start(state, NODE_NAME)
    logger.info("开始执行反诈知识库向量检索节点")

    if _knowledge_disabled():
        state["retrieved_docs"] = []
        append_warning(state, "聊天主链路已关闭本地知识库检索，跳过 Milvus/Mongo RAG")
        mark_node_done(state, NODE_NAME)
        return state

    query = (
        state.get("retrieval_query")
        or state.get("rewritten_query")
        or state.get("original_query")
        or ""
    ).strip()
    if not query:
        state["retrieved_docs"] = []
        append_warning(state, "向量检索 query 为空，跳过检索")
        mark_node_done(state, NODE_NAME)
        return state

    collection_name = _collection_name()
    if not collection_name:
        state["retrieved_docs"] = []
        append_warning(state, "未配置反诈知识库 Milvus 集合名，跳过检索")
        mark_node_done(state, NODE_NAME)
        return state

    try:
        client = get_milvus_client()
        if client is None:
            raise RuntimeError("Milvus 客户端初始化失败")

        vectors = generate_embeddings([query])
        dense_vector = vectors["dense"][0]
        sparse_vector = vectors["sparse"][0]
        reqs = create_hybrid_search_requests(dense_vector, sparse_vector, limit=RAW_TOP_K)

        anti_fraud_fields = [
            "knowledge_id",
            "knowledge_type",
            "fraud_type",
            "title",
            "summary",
            "risk_tags_text",
            "priority",
        ]
        # Milvus 中只取轻量字段；完整 content 由 Mongo 回查，保证主库一致性。
        search_result = hybrid_search(
            client,
            collection_name,
            reqs,
            ranker_weights=(0.6, 0.4),
            norm_score=True,
            limit=RAW_TOP_K,
            output_fields=anti_fraud_fields,
        )
        hits = search_result[0] if search_result and len(search_result) > 0 else []
        docs = _hydrate_docs_from_mongo([_hit_to_doc(hit) for hit in hits])
        reranked_docs = _rerank_docs(docs, state)
        state["retrieved_docs"] = _diversify_docs(reranked_docs, state.get("route_name", ""), TOP_K)
    except Exception as e:
        # 知识检索不可用不应阻断客服回答，规则引擎仍可给出风险结论。
        state["retrieved_docs"] = []
        append_warning(state, f"向量检索失败，已返回空检索结果：{e}")

    mark_node_done(state, NODE_NAME)
    return state
