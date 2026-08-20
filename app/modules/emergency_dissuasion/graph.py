"""应急劝阻模块图入口。

该模块现在与主查询图一样使用 LLM-first 语义风险代理，不再复用旧的
6 节点状态机流程。
"""

from langgraph.graph import END, StateGraph

from app.query_process.agent.nodes.node_semantic_risk_agent import (
    NODE_SEMANTIC_RISK_AGENT,
    node_semantic_risk_agent,
)
from app.query_process.agent.state import QueryGraphState


def build_emergency_dissuasion_graph():
    graph = StateGraph(QueryGraphState)
    graph.add_node(NODE_SEMANTIC_RISK_AGENT, node_semantic_risk_agent)
    graph.set_entry_point(NODE_SEMANTIC_RISK_AGENT)
    graph.add_edge(NODE_SEMANTIC_RISK_AGENT, END)
    return graph.compile()


emergency_dissuasion_app = build_emergency_dissuasion_graph()
