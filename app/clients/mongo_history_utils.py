# 导入系统模块：用于读取环境变量
import os
# 导入日志模块：用于记录程序运行日志（成功/失败/错误信息）
import logging
# 导入类型注解模块：用于函数参数/返回值的类型提示，提升代码可读性和规范性
from typing import List, Dict, Any, Optional
# 导入时间模块：用于生成时间戳，记录对话的创建时间
from datetime import datetime
# 导入pymongo核心模块：MongoDB原生Python驱动，实现数据库连接和操作
# ASCENDING：表示升序排序，用于MongoDB索引和查询排序
from pymongo import MongoClient, ASCENDING, DESCENDING
# 导入bson的ObjectId：MongoDB默认的主键类型，用于唯一标识文档
from bson import ObjectId
# 导入dotenv模块：用于从.env文件加载环境变量，避免硬编码敏感配置（如MongoDB连接地址）
from dotenv import load_dotenv

from app.core.data_protection import ProtectedDatabase, retention_collections
from app.core.security import env_bool

# 加载.env文件中的环境变量，使os.getenv能读取到配置
load_dotenv()


class HistoryMongoTool:
    """
    MongoDB 历史对话记录读写工具类 (基于原生 PyMongo 实现)
    核心功能：封装MongoDB的连接、集合初始化、索引创建，为上层提供统一的数据库操作入口
    扩展功能：支持与LangChain消息对象的格式转换（原代码预留能力）
    """
    def __init__(self):
        """
        类初始化方法：完成MongoDB的连接、数据库/集合获取、索引创建
        初始化失败会抛出异常并记录错误日志，确保程序感知连接问题
        """
        try:
            # 从环境变量读取MongoDB连接地址（敏感配置，不硬编码）
            self.mongo_url = os.getenv("MONGO_URL")
            # 从环境变量读取要使用的数据库名称
            self.db_name = os.getenv("MONGO_DB_NAME")

            # 创建MongoDB客户端实例，建立与数据库的连接。Mongo 不可用时要快速降级，
            # 避免语义路由、闲聊或 Web 兜底在历史记录初始化上长时间阻塞。
            mongo_options = {
                "serverSelectionTimeoutMS": int(os.getenv("MONGO_SERVER_SELECTION_TIMEOUT_MS", "2000")),
                "connectTimeoutMS": int(os.getenv("MONGO_CONNECT_TIMEOUT_MS", "2000")),
                "socketTimeoutMS": int(os.getenv("MONGO_SOCKET_TIMEOUT_MS", "5000")),
            }
            if env_bool("MONGO_TLS", env_bool("MONGO_SSL", False)):
                mongo_options.update(
                    {
                        "tls": True,
                        "tlsAllowInvalidCertificates": env_bool("MONGO_TLS_ALLOW_INVALID_CERTS", False),
                    }
                )
                ca_file = os.getenv("MONGO_TLS_CA_FILE", "").strip()
                cert_file = os.getenv("MONGO_TLS_CERT_KEY_FILE", "").strip()
                if ca_file:
                    mongo_options["tlsCAFile"] = ca_file
                if cert_file:
                    mongo_options["tlsCertificateKeyFile"] = cert_file
            self.client = MongoClient(self.mongo_url, **mongo_options)
            # 获取指定名称的数据库对象
            self.db = ProtectedDatabase(self.client[self.db_name])
            # 获取对话记录的集合（相当于关系型数据库的表），集合名：chat_message
            self.chat_message = self.db["chat_message"]
            self.case_state = self.db["anti_fraud_case_state"]
            self.session_state = self.db["anti_fraud_session_state"]
            self.case_event = self.db["anti_fraud_case_event"]

            # 为chat_message集合创建复合索引，提升查询性能
            # 索引规则：session_id升序 + ts降序，适配"按会话查最新记录"的核心查询场景
            # create_index自带幂等性：索引已存在时不会重复创建，无需额外判断
            self.chat_message.create_index([("session_id", 1), ("ts", -1)])
            # Rebuild scripts create this index as sparse; keep the same options so
            # repeated app startup does not hit IndexKeySpecsConflict.
            self.case_state.create_index([("session_id", ASCENDING)], unique=True, sparse=True)
            self.session_state.create_index([("session_id", ASCENDING)], unique=True, sparse=True)
            self.case_event.create_index([("session_id", ASCENDING), ("created_at", ASCENDING)])
            self.case_event.create_index([("case_id", ASCENDING), ("created_at", ASCENDING)])

            for collection_name in retention_collections():
                # The history client may run without the business client in
                # lightweight workers, so create only the collections it uses.
                if collection_name in {"chat_message", "anti_fraud_case_state", "anti_fraud_session_state", "anti_fraud_case_event"}:
                    self.db[collection_name].create_index(
                        [("data_retention_expires_at", ASCENDING)],
                        expireAfterSeconds=0,
                        name="data_retention_ttl",
                    )

            # 记录成功日志，确认数据库连接和初始化完成
            logging.info(f"Successfully connected to MongoDB: {self.db_name}")
        except Exception as e:
            # 捕获所有初始化异常，记录详细错误日志
            logging.error(f"Failed to connect to MongoDB: {e}")
            # 重新抛出异常，让调用方感知初始化失败，避免使用未初始化的实例
            raise


# 定义全局变量：存储HistoryMongoTool的单例实例
# 作用：避免多次创建HistoryMongoTool实例，从而避免重复建立MongoDB连接
_history_mongo_tool = None
# 模块加载时尝试初始化单例实例，实现预加载
# 目的：将数据库连接的初始化提前到模块加载阶段，避免第一次调用接口时才建立连接（提升首次响应速度）
try:
    _history_mongo_tool = HistoryMongoTool()
except Exception as e:
    # 初始化失败时仅记录警告日志，不抛出异常
    # 原因：模块加载阶段的异常可能导致整个程序启动失败，此处保留懒加载兜底（get_history_mongo_tool会再次尝试创建）
    logging.warning(f"Could not initialize HistoryMongoTool on module load: {e}")

def get_history_mongo_tool() -> Optional[HistoryMongoTool]:
    """
    获取HistoryMongoTool的单例实例（懒加载模式）
    核心逻辑：全局实例为空时创建，不为空时直接返回，保证整个程序只有一个数据库连接实例
    :return: HistoryMongoTool的单例实例
    """
    # 声明使用全局变量，避免函数内视为局部变量
    global _history_mongo_tool
    # 懒加载：仅当全局实例为空时，才创建新的实例
    if _history_mongo_tool is None:
        try:
            _history_mongo_tool = HistoryMongoTool()
        except Exception as e:
            logging.warning(f"HistoryMongoTool unavailable, continue without chat history: {e}")
            return None
    # 返回单例实例
    return _history_mongo_tool



def clear_history(session_id: str) -> int:
    """
    清空指定会话的所有历史对话记录
    :param session_id: 会话唯一标识，用于筛选要删除的记录
    :return: 实际删除的文档数量，删除失败返回0
    """
    # 获取全局的HistoryMongoTool实例，使用单例模式避免重复创建数据库连接
    mongo_tool = get_history_mongo_tool()
    try:
        # 执行批量删除操作：删除所有session_id匹配的文档
        result = mongo_tool.chat_message.delete_many({"session_id": session_id})
        mongo_tool.case_state.delete_many({"session_id": session_id})
        if hasattr(mongo_tool, "session_state"):
            mongo_tool.session_state.delete_many({"session_id": session_id})
        if hasattr(mongo_tool, "case_event"):
            mongo_tool.case_event.delete_many({"session_id": session_id})
        # 记录删除成功日志，包含删除数量和会话ID，便于问题排查
        logging.info(f"Deleted {result.deleted_count} messages for session {session_id}")
        # 返回实际删除的数量（delete_many的返回对象包含deleted_count属性）
        return result.deleted_count
    except Exception as e:
        # 捕获删除异常，记录错误日志，包含会话ID
        logging.error(f"Error clearing history for session {session_id}: {e}")
        # 异常时返回0，标识删除失败
        return 0


def get_case_state(session_id: str) -> Dict[str, Any]:
    """
    读取指定会话对应的诈骗事件状态。
    一个 session_id 对应一个诈骗事件。
    """
    if not session_id:
        return {}
    mongo_tool = get_history_mongo_tool()
    if mongo_tool is None:
        return {}
    if mongo_tool is None:
        return 0
    try:
        doc = mongo_tool.case_state.find_one({"session_id": session_id}) or {}
        if doc.get("_id") is not None:
            doc["_id"] = str(doc["_id"])
        return doc
    except Exception as e:
        logging.error(f"Error getting case_state for session {session_id}: {e}")
        return {}


def save_case_state(session_id: str, case_state: Dict[str, Any]) -> None:
    """
    保存或更新指定会话对应的诈骗事件状态。
    """
    if not session_id:
        return
    mongo_tool = get_history_mongo_tool()
    if mongo_tool is None:
        return
    document = dict(case_state or {})
    document["session_id"] = session_id
    document["updated_at"] = datetime.now().isoformat()
    document.pop("_id", None)
    try:
        mongo_tool.case_state.update_one(
            {"session_id": session_id},
            {"$set": document},
            upsert=True,
        )
    except Exception as e:
        logging.error(f"Error saving case_state for session {session_id}: {e}")


def save_chat_message(
        session_id: str,
        role: str,
        text: str,
        rewritten_query: str = "",
        fraud_types: List[str] = None,
        risk_summary: Dict[str, Any] = None,
        image_urls: List[str] = None,
        message_id: str = None,
        video_cards: List[Dict[str, Any]] = None
) -> str:
    """
    写入/更新单条会话记录到MongoDB
    支持两种模式：无message_id时新增记录，有message_id时更新已有记录
    :param session_id: 会话唯一标识，关联对话所属的会话
    :param role: 消息角色，固定值：user（用户）/assistant（助手）
    :param text: 对话核心内容，用户的提问或助手的回答
    :param rewritten_query: 重写后的查询语句（可选，用于检索增强等场景，默认空字符串）
    :param fraud_types: 疑似诈骗类型列表
    :param risk_summary: 反诈风险识别摘要
    :param image_urls: 关联的图片URL列表（可选，默认None）
    :param message_id: 记录主键ID（可选，有值则更新，无值则新增）
    :return: 插入/更新的记录唯一标识（新增返回ObjectId字符串，更新返回传入的message_id）
    """
    # 生成当前时间的时间戳（秒级），用于记录消息的创建时间，后续用于排序和查询
    ts = datetime.now().timestamp()

    # 构造要插入/更新的文档数据（MongoDB的基本数据单元是文档，类似Python字典）
    document = {
        "session_id": session_id,  # 会话ID，关联维度
        "role": role,  # 消息角色
        "text": text,  # 消息内容
        "rewritten_query": rewritten_query or "",  # 重写查询，空值处理为空字符串
        "fraud_types": fraud_types or [],
        "risk_summary": risk_summary or {},
        "image_urls": image_urls,  # 关联图片URL列表
        "ts": ts  # 时间戳，排序和时间筛选维度
    }
    if video_cards is not None:
        allowed_keys = {
            "video_id",
            "scam_id",
            "scam_name",
            "title",
            "cover_url",
            "source_url",
            "platform",
            "publisher",
            "official_account",
            "duration_seconds",
            "orientation",
            "label",
            "source_published_at",
        }
        document["video_cards"] = [
            {key: item.get(key) for key in allowed_keys if item.get(key) not in (None, "")}
            for item in (video_cards or [])
            if isinstance(item, dict)
        ]

    mongo_tool = get_history_mongo_tool()
    if mongo_tool is None:
        return ""
    if message_id:
        mongo_tool.chat_message.update_one(
            {"_id": ObjectId(message_id)},
            {"$set": document}
        )
        return message_id

    result = mongo_tool.chat_message.insert_one(document)
    return str(result.inserted_id)


def save_risk_chat_message(
        session_id: str,
        role: str,
        text: str,
        rewritten_query: str = "",
        fraud_types: List[str] = None,
        risk_summary: Dict[str, Any] = None,
        message_id: str = None,
        video_cards: List[Dict[str, Any]] = None
) -> str:
    """
    保存反诈会话消息。保留 save_chat_message 兼容旧调用，同时提供语义更清晰的包装。
    """
    return save_chat_message(
        session_id=session_id,
        role=role,
        text=text,
        rewritten_query=rewritten_query,
        fraud_types=fraud_types or [],
        risk_summary=risk_summary or {},
        message_id=message_id,
        video_cards=video_cards,
    )


def update_message_fraud_types(ids: List[str], fraud_types: List[str]) -> int:
    """
    批量更新历史会话记录的疑似诈骗类型。
    :param ids: 要更新的记录主键ID列表（字符串类型）
    :param fraud_types: 要设置的疑似诈骗类型列表
    :return: 实际更新的文档数量，更新失败返回0
    """
    # 获取全局的HistoryMongoTool实例，使用单例模式
    mongo_tool = get_history_mongo_tool()
    if mongo_tool is None:
        return 0
    try:
        # 将字符串类型的主键列表转为MongoDB的ObjectId类型（数据库中主键是ObjectId类型）
        object_ids = [ObjectId(i) for i in ids]
        # 执行批量更新操作
        result = mongo_tool.chat_message.update_many(
            # 更新条件：复合条件，同时满足
            {
                "_id": {"$in": object_ids}# 主键在指定的ID列表中（批量筛选）
            },
            {"$set": {"fraud_types": fraud_types}}
        )
        logging.info(f"Updated {result.modified_count} records to fraud_types: {fraud_types}")
        # 返回实际更新的数量（modified_count：真正被修改的文档数，区别于matched_count）
        return result.modified_count
    except Exception as e:
        # 捕获批量更新异常，记录错误日志
        logging.error(f"Error updating history fraud_types: {e}")
        # 异常时返回0，标识更新失败
        return 0


def get_recent_messages(session_id: str, limit: int = 10) -> List[Dict[str, Any]]:
    """
    查询指定会话的最近N条对话记录，返回原始字典格式
    结果按时间正序排列，可直接喂给LLM作为上下文
    :param session_id: 会话唯一标识，用于筛选指定会话的记录
    :param limit: 条数限制，默认返回最近10条
    :return: 对话记录列表（字典格式），查询失败返回空列表
    """
    # 获取全局的HistoryMongoTool实例，使用单例模式
    mongo_tool = get_history_mongo_tool()
    if mongo_tool is None:
        return []
    try:
        # 构造查询条件：仅查询指定session_id的记录
        query = {"session_id": session_id}

        # 先按时间倒序取最新 limit 条，再恢复为旧到新的对话顺序。
        # 直接按升序再 limit 会错误取到整个会话最早的消息。
        cursor = mongo_tool.chat_message.find(query).sort("ts", DESCENDING).limit(limit)
        # 将游标转为列表后反转，供前端和 LLM 按时间顺序消费。
        messages = list(cursor)
        messages.reverse()
        # 返回查询结果列表
        return messages
    except Exception as e:
        # 捕获查询异常，记录错误日志
        logging.error(f"Error getting recent messages: {e}")
        # 异常时返回空列表，避免上层处理None报错
        return []


# 主程序入口：仅当直接运行该脚本时执行，用于简单的功能测试
if __name__ == "__main__":
    # 简单测试代码：验证数据库的写入和查询功能是否正常
    # 测试会话ID，用于标识测试的对话记录
    sid = "000015_hybrid"
    # 1. 写入用户消息（手动指定ts=1000，便于测试排序）
    save_chat_message(sid, "user", "你好 (Hybrid)")
    # 2. 写入助手回复（手动指定ts=1001，按时间顺序紧跟用户消息）
    save_chat_message(sid, "assistant", "你好！我是基于原生 Mongo + LangChain 对象的助手。")
    # 3. 写入带风险摘要的反诈消息
    save_risk_chat_message(
        sid,
        "user",
        "有人让我做任务垫付300元返400元，靠谱吗？",
        fraud_types=["刷单返利诈骗"],
        risk_summary={"risk_level": "高风险", "risk_score": 92},
    )

    # 4. 查询指定会话的最近5条记录，验证查询功能
    print("--- 查询 LangChain 对象记录 ---")
    messages = get_recent_messages(sid, limit=5)
    # 打印查询到的记录数量
    print(f"查询到的记录数: {len(messages)}")
    # 遍历打印每条记录的详细内容
    for m in messages:
        print(f" {m}  ")
