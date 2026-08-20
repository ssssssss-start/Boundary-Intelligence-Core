# 当前环境依赖与模型清单

统一交付口径日期：2026-08-02。历史环境盘点生成于 2026-06-08；如与本文件旧快照描述冲突，以根目录 `DELIVERY_BASELINE.md` 和 `pyproject.toml` 为准。

## Python 环境

- Python：3.11+（推荐 3.11 或 3.12；`pyproject.toml` 的可安装约束为 `>=3.11`）
- 当前虚拟环境：`.venv`
- 当前 `.venv` 内未安装 `pip` 模块；本文件中的依赖版本通过 Python 标准库 `importlib.metadata` 从真实环境读取。
- 完整 Python 包版本见根目录 `requirements.txt`，共 112 个包。

推荐复现方式：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m ensurepip --upgrade
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

如果继续使用本项目已有 `uv.lock`，也可以用 uv 按锁文件同步环境。

## 核心运行依赖

项目入口服务：

- 导入服务：`python -m app.import_process.api.file_import_service`
- 查询/聊天/后台服务：`python -m app.query_process.api.query_service`

主要框架与能力：

- FastAPI / Uvicorn：Web API 与页面服务
- LangChain / LangGraph / OpenAI SDK：大模型调用与流程编排
- PyMongo：MongoDB 业务库
- PyMilvus / pymilvus.model：Milvus 向量库与 BGE-M3 混合向量
- Transformers / Torch / FlagEmbedding / sentence-transformers：本地模型和向量能力
- Pydantic：接口和结构化数据校验

## 外部服务

当前 `.env` 中配置：

```env
MONGO_URL=mongodb://localhost:27017
MONGO_DB_NAME=anti_fraud_rag

MILVUS_URL=http://localhost:19530
ANTI_FRAUD_COLLECTION=anti_fraud_knowledge
```

需要本地或服务器启动：

- MongoDB：`localhost:27017`
- Milvus：`localhost:19530`

## 大模型 API

当前不是本地大模型，而是 OpenAI 兼容 API：

```env
OPENAI_BASE_URL=https://api.deepseek.com
LLM_DEFAULT_MODEL=deepseek-chat
VISION_BASE_URL=https://dashscope.aliyuncs.com/compatible-mode/v1
VISION_MODEL=qwen-vl-plus
LLM_DEFAULT_TEMPERATURE=0.1
```

需要配置：

```env
OPENAI_API_KEY=你的 DeepSeek API Key
VISION_API_KEY=你的 DashScope API Key
```

说明：

- `deepseek-chat` 不需要本地下载模型。
- `qwen-vl-plus` 用于聊天截图 OCR 与视觉风险分析，不需要本地下载。
- `VL_MODEL` 是旧兼容字段；视觉链路以 `VISION_MODEL` 为准。

## 必需下载的本地模型

### 1. BAAI/bge-m3

用途：

- 反诈知识导入时生成 dense + sparse 混合向量
- Milvus `anti_fraud_knowledge` / 教育 RAG 向量集合重建

当前配置：

```env
BGE_M3=BAAI/bge-m3
BGE_M3_PATH=D:\ai_models\modelscope_cache\models\BAAI\bge-m3
BGE_DEVICE=cpu
BGE_FP16=0
EMBEDDING_DIM=1024
ANTI_FRAUD_EMBEDDING_BACKEND=auto
```

推荐下载到：

```text
项目目录\models\BAAI\bge-m3
```

模型下载地址：

- ModelScope：https://modelscope.cn/models/BAAI/bge-m3
- Hugging Face：https://huggingface.co/BAAI/bge-m3

模型版本：

- 模型名称：`BAAI/bge-m3`
- 本机缓存记录的 ModelScope 文件 revision：`e44369c5623cc146f016da906583db4ee0e3488d`
- ModelScope 主分支标记：`master`

ModelScope 下载示例：

```powershell
modelscope download --model BAAI/bge-m3 --revision e44369c5623cc146f016da906583db4ee0e3488d --local_dir .\models\BAAI\bge-m3
```

如果下载工具不支持该 revision 参数，也可以直接下载当前主分支：

```powershell
modelscope download --model BAAI/bge-m3 --local_dir .\models\BAAI\bge-m3
```

注意：

- 交付压缩包不包含 BGE-M3 模型文件，需要按上面的地址另行下载。
- 当前 `.env.example` 默认 `BGE_M3_PATH=./models/BAAI/bge-m3`，下载后放到该目录即可。
- 当前 `.env` 设置了 `MODELSCOPE_OFFLINE=1`，所以部署时如果离线运行，必须提前把模型下载到 `BGE_M3_PATH`。
- 当前代码在 `ANTI_FRAUD_EMBEDDING_BACKEND=auto` 下会先尝试 BGE-M3；如果 BGE-M3 初始化或编码失败，会降级为确定性 hash 向量。
- 如果部署机暂时不准备下载 BGE-M3，可显式设置 `ANTI_FRAUD_EMBEDDING_BACKEND=hash`，但语义检索效果会弱于真实 BGE-M3。

## 配置中预留但当前源码未使用的模型

### BAAI/bge-reranker-large

当前 `.env` 里有配置：

```env
BGE_RERANKER_LARGE=D:\ai_models\modelscope_cache\models\rerank\BAAI\bge-reranker-large
BGE_RERANKER_DEVICE=cpu
BGE_RERANKER_FP16=0
```

但本次检查源码时，没有发现 `FlagReranker`、`BGE_RERANKER_*` 或 `bge-reranker-large` 的实际调用。当前检索重排使用的是 Milvus `WeightedRanker` 做 dense/sparse 加权融合，不需要下载 `bge-reranker-large`。

结论：

- 当前版本必需模型：`BAAI/bge-m3`
- 当前版本可不下载：`BAAI/bge-reranker-large`
- 大模型：`deepseek-chat` 走 API，不下载本地模型

## 模型缓存目录

当前 `.env`：

```env
MODELSCOPE_CACHE=D:/ai_models/modelscope_cache
HF_HOME=D:/ai_models/huggingface_cache
MODELSCOPE_OFFLINE=1
```

建议部署时保持这两个目录有足够磁盘空间，并确认服务账号有读写权限。

## 当前完整包版本

完整列表已写入：

```text
requirements.txt
```

该文件是按当前 `.venv` 实际安装包生成，不是只按 `pyproject.toml` 的一层依赖生成，因此包含传递依赖版本。
