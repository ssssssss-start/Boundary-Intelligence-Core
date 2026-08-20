# 模型下载清单

交付包不包含模型文件。部署机器需要按下列信息下载模型。

## BGE-M3

用途：

- 反诈知识 dense + sparse 混合向量生成
- Milvus 知识库和科普 RAG 向量库重建

模型名称：

```text
BAAI/bge-m3
```

下载地址：

- ModelScope：https://modelscope.cn/models/BAAI/bge-m3
- Hugging Face：https://huggingface.co/BAAI/bge-m3

建议固定版本：

```text
e44369c5623cc146f016da906583db4ee0e3488d
```

本机缓存记录：

```text
ModelScope revision: master
File revision: e44369c5623cc146f016da906583db4ee0e3488d
```

推荐放置路径：

```text
.\models\BAAI\bge-m3
```

对应 `.env`：

```env
BGE_M3=BAAI/bge-m3
BGE_M3_PATH=./models/BAAI/bge-m3
BGE_DEVICE=cpu
BGE_FP16=0
```

ModelScope 下载命令：

```powershell
modelscope download --model BAAI/bge-m3 --revision e44369c5623cc146f016da906583db4ee0e3488d --local_dir .\models\BAAI\bge-m3
```

如果 revision 参数不可用，可以下载主分支：

```powershell
modelscope download --model BAAI/bge-m3 --local_dir .\models\BAAI\bge-m3
```

## 不需要下载的模型

- `deepseek-chat`：走 API，不是本地模型。
- `BAAI/bge-reranker-large`：当前 `.env` 里有预留字段，但源码未实际调用，暂时不用下载。
