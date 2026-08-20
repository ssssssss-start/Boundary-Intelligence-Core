"""Query 智能体主图编排。

新版风险会话不再使用“槽位门控 -> 状态机 -> 风险解除核验”的 6 节点流程。
风险对话统一交给一个语义风险代理节点：

用户输入 -> LLM 场景/事实研判 -> 知识库与规则裁决 -> LLM 实时回答
"""

from langgraph.graph import END, StateGraph

from app.query_process.agent.nodes.node_semantic_risk_agent import (
    NODE_SEMANTIC_RISK_AGENT,
    node_semantic_risk_agent,
)
from app.query_process.agent.state import QueryGraphState


def build_query_graph():
    """构建 LLM-first 语义风险工作流。"""
    graph = StateGraph(QueryGraphState)
    graph.add_node(NODE_SEMANTIC_RISK_AGENT, node_semantic_risk_agent)
    graph.set_entry_point(NODE_SEMANTIC_RISK_AGENT)
    graph.add_edge(NODE_SEMANTIC_RISK_AGENT, END)
    return graph.compile()


query_app = build_query_graph()
