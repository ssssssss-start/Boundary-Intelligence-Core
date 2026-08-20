# 导入核心依赖：数据类、环境变量读取、路径处理
from dataclasses import dataclass
import os
from dotenv import load_dotenv

# 提前加载.env配置文件（必须在读取环境变量前执行，确保os.getenv能获取到值）
# 若.env不在项目根目录，可指定路径：load_dotenv(dotenv_path=Path(__file__).parent / ".env")
load_dotenv()


# 定义minerU服务配置
@dataclass
class LLMConfig:
    base_url: str
    api_key : str
    lv_model: str
    llm_model: str
    llm_temperature: float
    reasoning_effort: str | None


def _normalize_reasoning_effort(value: str | None) -> str | None:
    effort = (value or "").strip().lower()
    if not effort:
        return None
    if effort in {"none", "off", "false", "0"}:
        return None
    if effort == "xhigh":
        return "high"
    if effort in {"low", "medium", "high"}:
        return effort
    return "high"


def _env(name: str, default: str = "") -> str:
    return (os.getenv(name) or default).strip().strip('"').strip("'")


def _env_float(name: str, default: float) -> float:
    raw = _env(name)
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


lm_config = LLMConfig(
    base_url=_env("OPENAI_BASE_URL"),
    api_key=_env("OPENAI_API_KEY"),
    lv_model=_env("VL_MODEL"),
    llm_model=_env("LLM_DEFAULT_MODEL"),
    llm_temperature=_env_float("LLM_DEFAULT_TEMPERATURE", 0.1),
    reasoning_effort=_normalize_reasoning_effort(
        os.getenv("OPENAI_REASONING_EFFORT") or os.getenv("LLM_REASONING_EFFORT")
    ),
)
