import os
from pymilvus import MilvusClient, AnnSearchRequest, WeightedRanker
from app.conf.milvus_config import milvus_config
from app.core.logger import logger
from app.core.security import env_bool

# 全局Milvus客户端实例，实现单例复用
_milvus_client = None


def get_milvus_client():
    """
    Milvus客户端单例获取方法
    实现客户端连接复用，避免重复创建连接消耗资源
    :return: MilvusClient实例，连接失败返回None
    """
    try:
        global _milvus_client
        # 单例判断：未初始化则创建新连接
        if _milvus_client is None:
            milvus_uri = milvus_config.milvus_url
            # 校验Milvus连接地址配置
            if not milvus_uri:
                logger.error("Milvus客户端连接失败：缺少MILVUS_URL环境变量配置")
                return None
            # 初始化Milvus客户端
            milvus_options = {}
            if env_bool("MILVUS_TLS", env_bool("MILVUS_SSL", False)):
                milvus_options["secure"] = True
                for env_name, option_name in (
                    ("MILVUS_TLS_SERVER_NAME", "server_name"),
                    ("MILVUS_TLS_CA_FILE", "ca_pem_path"),
                    ("MILVUS_TLS_CLIENT_CERT_FILE", "client_pem_path"),
                    ("MILVUS_TLS_CLIENT_KEY_FILE", "client_key_path"),
                    ("MILVUS_TLS_CLIENT_KEY_PASSWORD", "client_key_password"),
                ):
                    value = os.getenv(env_name, "").strip()
                    if value:
                        milvus_options[option_name] = value
            token = os.getenv("MILVUS_TOKEN", "").strip()
            if token:
                milvus_options["token"] = token
            _milvus_client = MilvusClient(uri=milvus_uri, **milvus_options)
            logger.info("Milvus客户端连接成功")
        return _milvus_client
    except Exception as e:
        logger.error(f"Milvus客户端连接异常：{str(e)}", exc_info=True)
        return None


def fetch_fraud_knowledge_by_ids(
        client,
        collection_name: str,
        knowledge_ids,
        *,
        output_fields=None,
):
    """
    通过 knowledge_id 批量查询反诈结构化知识记录。
    Milvus 中 knowledge_id 是业务唯一 ID，适合根据检索摘要回查完整知识记录。
    """
    if client is None or not collection_name or not knowledge_ids:
        return []

    if output_fields is None:
        output_fields = [
            "knowledge_id",
            "knowledge_type",
            "fraud_type",
            "title",
            "summary",
            "risk_tags_text",
            "priority",
        ]

    safe_ids = [str(item).replace("\\", "\\\\").replace('"', '\\"') for item in knowledge_ids if item]
    if not safe_ids:
        return []

    expr = "knowledge_id in [" + ", ".join(f'"{item}"' for item in safe_ids) + "]"
    try:
        return client.query(collection_name=collection_name, filter=expr, output_fields=output_fields) or []
    except Exception as e:
        logger.error(f"Milvus query方法批量查询反诈知识失败：{str(e)}", exc_info=True)
        return []


def create_hybrid_search_requests(dense_vector, sparse_vector, dense_params=None, sparse_params=None, expr=None,
                                  limit=5):
    """
    构建Milvus混合搜索请求对象
    分别创建稠密/稀疏向量的搜索请求，用于后续混合搜索融合
    :param dense_vector: 文本生成的稠密向量
    :param sparse_vector: 文本生成的稀疏向量
    :param dense_params: 稠密向量搜索参数，默认使用余弦相似度
    :param sparse_params: 稀疏向量搜索参数，默认使用内积相似度
    :param expr: 搜索过滤表达式，用于精准筛选数据
    :param limit: 单向量搜索返回结果数量，默认5
    :return: 搜索请求列表，包含[dense_req, sparse_req]
    """
    # 稠密向量默认搜索参数：余弦相似度（COSINE），适配BGE-M3稠密向量并与建库参数保持一致
    if dense_params is None:
        dense_params = {"metric_type": "COSINE"}
    # 稀疏向量默认搜索参数：内积（IP），适配BGE-M3稀疏向量
    if sparse_params is None:
        sparse_params = {"metric_type": "IP"}

    # 构建稠密向量搜索请求，关联Milvus的dense_vector字段 近似最近邻（ANN）检索请求的核心类
    dense_req = AnnSearchRequest(
        data=[dense_vector],
        anns_field="dense_vector",
        param=dense_params,
        expr=expr,
        limit=limit
    )

    # 构建稀疏向量搜索请求，关联Milvus的sparse_vector字段
    sparse_req = AnnSearchRequest(
        data=[sparse_vector],
        anns_field="sparse_vector",
        param=sparse_params,
        expr=expr,
        limit=limit
    )

    return [dense_req, sparse_req]


def hybrid_search(client, collection_name, reqs, ranker_weights=(0.5, 0.5), norm_score=False, limit=5,
                  output_fields=None, search_params=None):
    """
    执行Milvus稠密+稀疏向量混合搜索
    基于WeightedRanker实现双向量搜索结果加权融合，提升检索准确性
    :param client: MilvusClient实例
    :param collection_name: 集合名称
    :param reqs: 搜索请求列表，固定为[dense_req, sparse_req]
    :param ranker_weights: 加权融合权重，默认(0.5,0.5)，依次对应稠密/稀疏向量
    :param norm_score: 是否归一化评分后再融合，避免评分量级差异导致权重失效
    :param limit: 混合搜索最终返回结果数量，默认5
    :param output_fields: 需要返回的字段列表，默认返回knowledge_id
    :param search_params: 搜索参数，如ef/topk等，默认None
    :return: 混合搜索结果列表，搜索失败返回None
    """
    try:
        # 初始化加权排名器：按权重融合稠密/稀疏向量的搜索结果
        # norm_score=True：先将两个向量评分归一化到0~1区间，再加权计算
        rerank = WeightedRanker(ranker_weights[0], ranker_weights[1], norm_score=norm_score)

        # 默认返回字段：反诈知识业务标识
        if output_fields is None:
            output_fields = ["knowledge_id"]

        # 执行混合搜索：融合稠密+稀疏向量结果，按权重重新排序
        res = client.hybrid_search(
            collection_name=collection_name,
            reqs=reqs,
            ranker=rerank,
            limit=limit,
            output_fields=output_fields,
            search_params=search_params
        )

        logger.info(f"Milvus混合搜索完成，集合[{collection_name}]共检索到{len(res[0])}条结果")
        return res
    except Exception as e:
        logger.error(f"Milvus混合搜索执行失败，集合[{collection_name}]：{str(e)}", exc_info=True)
        return None
