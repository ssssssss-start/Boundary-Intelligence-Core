"""Single-node semantic risk agent.

This node replaces the old slot-gate/state-machine risk workflow for chat.
It delegates semantic fact extraction and final expression to the LLM, while
structured knowledge and rules remain internal constraints.
"""

from __future__ import annotations

from typing import Any, Dict

from app.query_process.agent.nodes.common import mark_node_done, mark_node_start
from app.query_process.services.semantic_risk_agent import run_semantic_risk_agent


NODE_SEMANTIC_RISK_AGENT = "node_semantic_risk_agent"


def node_semantic_risk_agent(state: Dict[str, Any]) -> Dict[str, Any]:
    mark_node_start(state, NODE_SEMANTIC_RISK_AGENT)
    try:
        return run_semantic_risk_agent(state)
    finally:
        mark_node_done(state, NODE_SEMANTIC_RISK_AGENT)


__all__ = ["NODE_SEMANTIC_RISK_AGENT", "node_semantic_risk_agent"]
