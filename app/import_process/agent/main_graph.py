from langgraph.graph import END, StateGraph

from app.import_process.agent.state import ImportGraphState
from app.import_process.agent.nodes.node_load_fraud_knowledge import node_load_fraud_knowledge
from app.import_process.agent.nodes.node_validate_fraud_knowledge import node_validate_fraud_knowledge
from app.import_process.agent.nodes.node_import_fraud_knowledge_mongo import node_import_fraud_knowledge_mongo
from app.import_process.agent.nodes.node_build_embedding_text import node_build_embedding_text
from app.import_process.agent.nodes.node_fraud_knowledge_embedding import node_fraud_knowledge_embedding
from app.import_process.agent.nodes.node_import_fraud_knowledge_milvus import node_import_fraud_knowledge_milvus


def build_import_graph():
    """
    构建反诈知识结构化导入工作流。

    新链路不再执行 PDF/Markdown 解析、文档切片和旧主体识别，只导入
    data/anti_fraud_knowledge.json 中的结构化反诈知识记录。
    """
    workflow = StateGraph(ImportGraphState)

    workflow.add_node("node_load_fraud_knowledge", node_load_fraud_knowledge)
    workflow.add_node("node_validate_fraud_knowledge", node_validate_fraud_knowledge)
    workflow.add_node("node_import_fraud_knowledge_mongo", node_import_fraud_knowledge_mongo)
    workflow.add_node("node_build_embedding_text", node_build_embedding_text)
    workflow.add_node("node_fraud_knowledge_embedding", node_fraud_knowledge_embedding)
    workflow.add_node("node_import_fraud_knowledge_milvus", node_import_fraud_knowledge_milvus)

    workflow.set_entry_point("node_load_fraud_knowledge")
    workflow.add_edge("node_load_fraud_knowledge", "node_validate_fraud_knowledge")
    workflow.add_edge("node_validate_fraud_knowledge", "node_import_fraud_knowledge_mongo")
    workflow.add_edge("node_import_fraud_knowledge_mongo", "node_build_embedding_text")
    workflow.add_edge("node_build_embedding_text", "node_fraud_knowledge_embedding")
    workflow.add_edge("node_fraud_knowledge_embedding", "node_import_fraud_knowledge_milvus")
    workflow.add_edge("node_import_fraud_knowledge_milvus", END)

    return workflow.compile()


kb_import_app = build_import_graph()
