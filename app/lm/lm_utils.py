# 环境配置与依赖导入
from langchain_openai import ChatOpenAI
from langchain_core.exceptions import LangChainException
from typing import Optional

# 项目内部依赖
from app.conf.lm_config import lm_config
from app.core.logger import logger

# 全局缓存：键为(模型名, JSON输出模式)元组，值为ChatOpenAI实例
# 作用：避免重复初始化客户端，提升性能，统一实例管理
_llm_client_cache = {}


class PrivacyAwareLLMClient:
    """Proxy that redacts common personal identifiers before provider calls."""

    def __init__(self, client):
        self._client = client

    def _sanitize_input(self, value):
        # Lazy import avoids the memory-manager -> rule-engine -> lm-utils cycle
        # during application startup.
        from app.query_process.agent.memory.memory_redactor import sanitize_external_payload

        if isinstance(value, list):
            sanitized = []
            for item in value:
                if hasattr(item, "model_copy") and hasattr(item, "content"):
                    sanitized.append(item.model_copy(update={"content": sanitize_external_payload(item.content)}))
                else:
                    sanitized.append(sanitize_external_payload(item))
            return sanitized
        if hasattr(value, "model_copy") and hasattr(value, "content"):
            return value.model_copy(update={"content": sanitize_external_payload(value.content)})
        return sanitize_external_payload(value)

    def invoke(self, value, *args, **kwargs):
        return self._client.invoke(self._sanitize_input(value), *args, **kwargs)

    def stream(self, value, *args, **kwargs):
        return self._client.stream(self._sanitize_input(value), *args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._client, name)


def _clean_config_value(value: Optional[str]) -> str:
    return str(value or "").strip().strip('"').strip("'")


def get_llm_config_error() -> Optional[str]:
    api_key = _clean_config_value(lm_config.api_key)
    base_url = _clean_config_value(lm_config.base_url)
    model = _clean_config_value(lm_config.llm_model)

    if not api_key:
        return "OPENAI_API_KEY is missing in .env"
    if any(ord(ch) > 127 for ch in api_key):
        return "OPENAI_API_KEY contains non-ASCII characters; please replace the placeholder with a real provider key"
    lowered_key = api_key.lower()
    if any(marker in lowered_key for marker in ("your", "placeholder", "api key", "openai_api_key")):
        return "OPENAI_API_KEY still looks like a placeholder"
    if not base_url:
        return "OPENAI_BASE_URL is missing in .env"
    if any(ord(ch) > 127 for ch in base_url):
        return "OPENAI_BASE_URL contains non-ASCII characters"
    if not base_url.startswith(("http://", "https://")):
        return "OPENAI_BASE_URL must start with http:// or https://"
    if model and any(ord(ch) > 127 for ch in model):
        return "LLM_DEFAULT_MODEL contains non-ASCII characters"
    return None


def is_llm_config_ready() -> bool:
    return get_llm_config_error() is None


def _normalized_reasoning_effort(value: Optional[str]) -> Optional[str]:
    """Keep provider reasoning_effort inside the deployed API's accepted set."""
    effort = str(value or "").strip().lower()
    if not effort:
        return None
    mapping = {
        "none": "low",
        "minimal": "low",
        "xhigh": "high",
        "extra_high": "high",
        "very_high": "high",
    }
    effort = mapping.get(effort, effort)
    return effort if effort in {"low", "medium", "high"} else "high"


def get_llm_client(model: Optional[str] = None, json_mode: bool = False) -> ChatOpenAI:
    """
    获取带全局缓存的LangChain ChatOpenAI客户端实例
    适配DeepSeek/OpenAI/千问等OpenAI兼容API，支持自定义模型和JSON标准化输出
    核心特性：缓存机制+配置统一加载+异常精准捕获+国产模型参数适配

    :param model: 模型名称，优先级：传入参数 > 配置文件lm_config.llm_model > 内置默认deepseek-chat
    :param json_mode: 是否开启JSON输出模式，开启后返回标准json_object格式（适配结构化数据解析）
    :return: 初始化完成的ChatOpenAI实例（优先从全局缓存获取，未命中则新建并缓存）
    :raise ValueError: 缺失API密钥/基础地址等核心配置
    :raise Exception: 模型初始化失败（LangChain封装层异常）
    """
    # 1. 确定目标模型（优先级递减，保证模型名非空）
    config_error = get_llm_config_error()
    if config_error:
        raise ValueError(f"[LLM client] {config_error}")

    target_model = _clean_config_value(model) or _clean_config_value(lm_config.llm_model) or "deepseek-chat"
    api_key = _clean_config_value(lm_config.api_key)
    base_url = _clean_config_value(lm_config.base_url)
    # 缓存键：模型名+JSON模式，唯一标识不同配置的客户端
    cache_key = (target_model, json_mode, base_url)

    # 2. 缓存命中：直接返回已初始化的实例，避免重复创建
    if cache_key in _llm_client_cache:
        logger.debug(f"[LLM客户端] 缓存命中，直接返回实例：模型={target_model}，JSON模式={json_mode}")
        return _llm_client_cache[cache_key]

    # 3. 核心配置校验：拦截缺失的API关键配置，提前抛出明确异常
    if not api_key:
        raise ValueError("[LLM客户端] 配置缺失：请在.env中配置OPENAI_API_KEY（大模型API密钥）")
    if not base_url:
        raise ValueError("[LLM客户端] 配置缺失：请在.env中配置OPENAI_BASE_URL（API接口基础地址）")
    logger.info(f"[LLM客户端] 开始初始化新实例：模型={target_model}，JSON模式={json_mode}")

    # 4. 配置参数组装：区分厂商私有参数和OpenAI通用参数。
    # DeepSeek不需要enable_thinking；该参数只在DashScope/Qwen接口下透传。
    is_qwen_provider = "dashscope" in base_url or target_model.lower().startswith("qwen")
    extra_body = {"enable_thinking": False} if is_qwen_provider else None
    # model_kwargs：OpenAI通用参数，所有兼容API均支持
    model_kwargs = {}
    if json_mode:
        # 开启JSON标准输出模式，强制模型返回可解析的json_object
        model_kwargs["response_format"] = {"type": "json_object"}
        logger.debug(f"[LLM客户端] 已开启JSON输出模式，模型将返回标准JSON结构")
    reasoning_effort = _normalized_reasoning_effort(lm_config.reasoning_effort)
    if reasoning_effort:
        model_kwargs["reasoning_effort"] = reasoning_effort

    # 5. 客户端初始化：捕获LangChain封装层异常，抛出更友好的提示
    try:
        raw_llm_client = ChatOpenAI(
            model=target_model,  # 目标模型名
            temperature=lm_config.llm_temperature or 0.1,  # 低温度保证输出确定性（0~1）
            api_key=api_key,  # API密钥
            base_url=base_url,  # API基础地址（适配国产模型代理地址）
            extra_body=extra_body,  # 厂商私有参数透传；DeepSeek下为None
            model_kwargs=model_kwargs,  # OpenAI通用参数
        )
        llm_client = PrivacyAwareLLMClient(raw_llm_client)
    except LangChainException as e:
        raise Exception(f"[LLM客户端] 模型【{target_model}】初始化失败（LangChain层）：{str(e)}") from e

    # 6. 新实例存入全局缓存，供后续调用复用
    _llm_client_cache[cache_key] = llm_client
    logger.info(f"[LLM客户端] 实例初始化成功并缓存：模型={target_model}，JSON模式={json_mode}")

    return llm_client


# 测试示例：验证客户端创建、缓存机制及日志输出
if __name__ == "__main__":
    logger.info("===== 开始执行LLM客户端工具测试 =====")
    try:
        # 测试1：默认配置（默认模型+普通模式）
        client1 = get_llm_client()
        logger.info("✅ 测试1通过：默认配置客户端创建成功")

        # 测试2：指定多模态模型（qwen-vl-plus）+ 普通模式
        client2 = get_llm_client(model="qwen-vl-plus")
        logger.info("✅ 测试2通过：指定多模态模型客户端创建成功")

        # 测试3：同一模型+模式，验证缓存命中
        client3 = get_llm_client(model="qwen-vl-plus")
        logger.info(f"✅ 测试3通过：缓存机制验证成功，client2与client3为同一实例：{client2 is client3}")

        # 测试4：开启JSON输出模式
        client4 = get_llm_client(model="deepseek-chat", json_mode=True)
        logger.info("✅ 测试4通过：JSON输出模式客户端创建成功")

    except Exception as e:
        logger.error(f"❌ LLM客户端工具测试失败：{str(e)}", exc_info=True)
    finally:
        logger.info("===== LLM客户端工具测试结束 =====")
