import hashlib
import math
import os
import re

from pymilvus.model.hybrid import BGEM3EmbeddingFunction
from app.core.logger import logger
from app.conf.embedding_config import embedding_config

# 模型单例对象，避免重复初始化
_bge_m3_ef = None

HASH_SPARSE_DIM = 250002
HASH_TERMS = [
    "刷单", "返利", "返佣", "垫付", "补单", "提现失败", "解冻费", "保证金",
    "游戏", "代充", "账号密码", "私下交易", "验证码", "银行卡", "身份证",
    "屏幕共享", "远程控制", "客服", "退款", "理赔", "公检法", "安全账户",
    "投资", "理财", "高收益", "稳赚", "虚拟币", "贷款", "校园贷", "刷流水",
    "陌生链接", "二维码", "人脸识别", "删除记录", "保密", "报警", "止付",
]


def _embedding_backend() -> str:
    return os.getenv("ANTI_FRAUD_EMBEDDING_BACKEND", "auto").strip().lower()


def _hash_int(value: str) -> int:
    digest = hashlib.blake2b(value.encode("utf-8"), digest_size=8).digest()
    return int.from_bytes(digest, "big", signed=False)


def _hash_tokens(text: str) -> list[str]:
    text = (text or "").lower()
    tokens = re.findall(r"[a-z0-9_./:-]+|[\u4e00-\u9fff]", text)
    chars = [token for token in tokens if re.fullmatch(r"[\u4e00-\u9fff]", token)]
    terms: list[str] = []

    for term in HASH_TERMS:
        if term.lower() in text:
            terms.extend([term] * 3)

    terms.extend(token for token in tokens if len(token) > 1)
    terms.extend("".join(chars[index:index + 2]) for index in range(max(0, len(chars) - 1)))
    terms.extend("".join(chars[index:index + 3]) for index in range(max(0, len(chars) - 2)))
    if not terms:
        terms = tokens or ["empty"]
    return terms


def _l2_normalize_dense(values: list[float]) -> list[float]:
    norm = math.sqrt(sum(value * value for value in values))
    if norm <= 0:
        return values
    return [value / norm for value in values]


def _l2_normalize_sparse(values: dict[int, float]) -> dict[int, float]:
    norm = math.sqrt(sum(value * value for value in values.values()))
    if norm <= 0:
        return values
    return {key: value / norm for key, value in values.items()}


def generate_hash_embeddings(texts):
    dim = int(os.getenv("EMBEDDING_DIM", "1024") or 1024)
    dense_vectors = []
    sparse_vectors = []

    for text in texts:
        dense = [0.0] * dim
        sparse: dict[int, float] = {}
        for token in _hash_tokens(text):
            hashed = _hash_int(token)
            dense_index = hashed % dim
            sign = 1.0 if (hashed & 1) else -1.0
            dense[dense_index] += sign
            sparse_index = hashed % HASH_SPARSE_DIM
            sparse[sparse_index] = sparse.get(sparse_index, 0.0) + 1.0

        dense_vectors.append(_l2_normalize_dense(dense))
        sparse_vectors.append(_l2_normalize_sparse(sparse))

    return {"dense": dense_vectors, "sparse": sparse_vectors}

def get_bge_m3_ef():
    """
    获取BGE-M3模型单例对象，自动加载环境变量配置
    :return: 初始化完成的BGEM3EmbeddingFunction实例
    """
    global _bge_m3_ef
    # 单例模式：已初始化则直接返回，避免重复加载模型
    if _bge_m3_ef is not None:
        logger.debug("BGE-M3模型单例已存在，直接返回实例")
        return _bge_m3_ef

    # 从环境变量加载配置，无配置则使用默认值
    # 本地有可以使用本地地址！ 没有使用 "BAAI/bge-m3" 会自动下载！ 如果云端部署也可以使用url地址！
    model_name = embedding_config.bge_m3_path or "BAAI/bge-m3"
    device = embedding_config.bge_device or "cpu"
    use_fp16 = embedding_config.bge_fp16 or False

    # 打印模型初始化配置，便于问题排查
    logger.info(
        "开始初始化BGE-M3模型",
        extra={
            "model_name": model_name,
            "device": device,
            "use_fp16": use_fp16,
            "normalize_embeddings": True
        }
    )

    try:
        # 初始化BGE-M3模型，开启原生L2归一化（适配Milvus IP内积检索）
        _bge_m3_ef = BGEM3EmbeddingFunction(
            model_name=model_name,
            device=device,
            use_fp16=use_fp16,
            normalize_embeddings=True  # 模型原生对稠密+稀疏向量做L2归一化
        )
        logger.success("BGE-M3模型初始化成功，已开启原生L2归一化")
        return _bge_m3_ef
    except Exception as e:
        logger.error(f"BGE-M3模型初始化失败：{str(e)}", exc_info=True)
        raise  # 向上抛出异常，由调用方处理


def generate_embeddings(texts):
    """
    为文本列表生成稠密+稀疏混合向量嵌入（模型原生L2归一化）
    :param texts: 要生成嵌入的文本列表，单文本也需封装为列表
    :return: 字典格式的向量结果，key为dense/sparse，对应嵌套列表/字典列表
    :raise: 向量生成过程中的异常，由调用方捕获处理
    """
    # 入参合法性校验
    if not isinstance(texts, list) or len(texts) == 0:
        logger.warning("生成向量入参不合法，texts必须为非空列表")
        raise ValueError("参数texts必须是包含文本的非空列表")

    backend = _embedding_backend()
    if backend in {"hash", "deterministic", "local_hash"}:
        logger.info(f"开始为{len(texts)}条文本生成确定性hash混合向量嵌入")
        result = generate_hash_embeddings(texts)
        result["embedding_backend"] = "hash"
        return result

    logger.info(f"开始为{len(texts)}条文本生成混合向量嵌入")
    try:
        # 加载BGE-M3模型单例
        model = get_bge_m3_ef()
        # 模型编码生成向量，返回dense（稠密向量）+sparse（CSR格式稀疏向量）
        embeddings = model.encode_documents(texts)
        logger.debug(f"模型编码完成，开始解析稀疏向量格式，共{len(texts)}条")

        # 初始化稀疏向量处理结果，解析为字典格式（适配序列化/存储）
        processed_sparse = []
        for i in range(len(texts)):
            # 提取第i个文本的稀疏向量索引：np.int64 → Python int（满足字典key可哈希要求）
            sparse_indices = embeddings["sparse"].indices[
                embeddings["sparse"].indptr[i]:embeddings["sparse"].indptr[i + 1]
            ].tolist()
            # 提取第i个文本的稀疏向量权重：np.float32 → Python float（适配JSON序列化/接口返回）
            sparse_data = embeddings["sparse"].data[
                embeddings["sparse"].indptr[i]:embeddings["sparse"].indptr[i + 1]
            ].tolist()
            # 构造{特征索引: 归一化权重}的稀疏向量字典
            sparse_dict = {k: v for k, v in zip(sparse_indices, sparse_data)}
            processed_sparse.append(sparse_dict)

        # 构造最终返回结果，稠密向量转列表（解决numpy数组不可序列化问题）
        result = {
            "dense": [emb.tolist() for emb in embeddings["dense"]],  # 嵌套列表，与输入文本一一对应
            "sparse": processed_sparse,  # 字典列表，模型已做L2归一化
            "embedding_backend": "bge-m3",
        }
        logger.success(f"{len(texts)}条文本向量生成完成，格式已适配工业级使用")
        return result

    except Exception as e:
        if backend in {"auto", "semantic_auto", "bge_or_hash"}:
            logger.warning(f"BGE-M3向量生成失败，自动降级为确定性hash向量：{str(e)}", exc_info=True)
            result = generate_hash_embeddings(texts)
            result["embedding_backend"] = "hash_fallback"
            return result
        logger.error(f"文本向量生成失败：{str(e)}", exc_info=True)
        raise  # 不吞异常，向上传递让调用方做重试/降级处理


"""
核心设计亮点&适配说明：
1. 模型原生归一化：开启normalize_embeddings = True，自动对稠密+稀疏向量做L2归一化，完美适配Milvus IP内积检索（单位化后IP等价于余弦，计算更快）；
2. 彻底解决NumPy类型做key问题：sparse_indices加.tolist()，将np.int64转为Python原生int，满足字典key的可哈希要求，无报错风险；
3. 稀疏值适配序列化：sparse_data加.tolist()，将np.float32转为Python原生float，支持JSON写入/接口返回/Milvus入库等所有场景；
4. 单例模式优化：模型仅初始化一次，避免重复加载耗时耗资源，提升批量处理效率；
5. 格式匹配业务调用：返回dense嵌套列表、sparse字典列表，与vector_result["dense"][0]/sparse_vector["sparse"][0]取值逻辑完美契合；
6. 分级日志覆盖：从模型初始化、向量生成到异常报错，全流程日志记录，便于生产环境问题排查；
7. 入参合法性校验：防止空列表/非列表入参导致的内部报错，提升工具类健壮性。
"""
