# 导入核心依赖（和其他配置类共用，只需导入一次）
from dataclasses import dataclass
import os
from dotenv import load_dotenv

# 提前加载.env配置文件（全局执行一次即可，无需重复写）
load_dotenv()

# ===================== 其他配置类（LLM/Embedding）可放在上方，保持原有代码不变 =====================
# ... 你的LLMConfig、EmbeddingConfig代码 ...

# 定义Milvus向量数据库配置类
@dataclass
class MilvusConfig:
    milvus_url: str              # Milvus服务端连接地址
    anti_fraud_collection: str   # 反诈结构化知识集合名称

# 实例化Milvus配置对象（和其他配置对象命名风格统一）
milvus_config = MilvusConfig(
    milvus_url=os.getenv("MILVUS_URL"),
    anti_fraud_collection=os.getenv("ANTI_FRAUD_COLLECTION") or os.getenv("FRAUD_KNOWLEDGE_COLLECTION") or "anti_fraud_knowledge",
)
