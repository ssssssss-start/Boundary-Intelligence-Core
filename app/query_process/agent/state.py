"""QueryGraphState 类型定义。

LangGraph 的每个节点都会接收并返回同一个 state 字典。
这个 TypedDict 不会在运行时强制校验，但它是节点契约文档：
字段写在这里，后续节点才能稳定读取，接口层也能按同一结构做摘要输出。
"""

from typing import List, Dict, Any
from typing_extensions import TypedDict


class QueryGraphState(TypedDict, total=False):
    """
    QueryGraphState 定义反诈智能守护 Query 工作流中的状态数据。

    Query 工作流：
    用户问题
    → 案件状态读取
    → 案件上下文分析
    → 意图识别
    → 风险特征抽取
    → 案件状态更新
    → 安全状态评估
    → 规则引擎判断
    → 风险评分
    → 干预路径决策
    → 干预目标决策
    → 回答 Prompt 构造
    → 最终回答生成
    → 案件状态保存
    """

    # ======================
    # 1. 基础输入
    # 这些字段由 API 层创建，是整条图的最小启动参数。
    # ======================
    session_id: str
    case_id: str
    original_query: str
    intent_hint: str
    history: List[Dict[str, Any]]
    history_text: str
    is_stream: bool

    # ======================
    # 2. 场景理解
    # case_context_type:
    #   1 = 劝阻咨询，用户正在被诱导但未确认损失。
    #   2 = 被骗求助，已付款、已泄露或已发生明显损失。
    #   3 = 反诈学习，没有具体正在发生的诈骗事件。
    # ======================
    case_state: Dict[str, Any]
    memory_context: Dict[str, Any]
    route_context: Dict[str, Any]
    pending_question: Dict[str, Any]
    turn_memory: Dict[str, Any]
    memory_summary: str
    case_context_type: int
    case_context_id: int
    case_context_label: str

    # ======================
    # 3. 意图识别
    # 固定取值：
    # anti_fraud_qa / risk_help / emergency_help /
    # risk_fact_clarification / education_game / smalltalk / clarify
    # ======================
    intent: str
    intent_confidence: float
    route_decision: Dict[str, Any]

    # ======================
    # 4. 风险识别
    # fraud_type/fraud_stage 是主判断，possible_* 会保留多候选。
    # risk_features 使用 app.anti_fraud.schema.RISK_FEATURES 中的标准标签。
    # risk_feature_judgement 是 LLM 对规则候选特征的语义裁判结果：
    # 它会区分“已经发生 / 对方要求 / 明确否认 / 科普假设 / 不确定”。
    # adjudicated_risk_features 是裁判后真正进入规则匹配和风险评分的特征。
    # ======================
    fraud_type: str
    fraud_stage: str
    risk_features: List[str]
    risk_feature_judgement: Dict[str, Any]
    adjudicated_risk_features: List[str]
    small_rebate_without_unrecovered_loss: bool
    entities: Dict[str, List[str]]
    missing_info: List[str]

    # ======================
    # 4.1 六节点紧凑工作流结构
    # slots 是用户事实槽位；scam_understanding 是骗局理解；
    # risk/intervention/resolution 是二分类风险闭环的核心结构。
    # ======================
    slots: Dict[str, Any]
    slot_evidence: Dict[str, str]
    slot_gate: Dict[str, Any]
    workflow_action: str
    scam_understanding: Dict[str, Any]
    risk: Dict[str, Any]
    intervention: Dict[str, Any]
    realtime_dissuasion: Dict[str, Any]
    semantic_scene: Dict[str, Any]
    semantic_risk_analysis: Dict[str, Any]
    semantic_risk_decision: Dict[str, Any]
    scenario_frame: Dict[str, Any]
    dialogue_policy: Dict[str, Any]
    resolution: Dict[str, Any]
    resolution_followup_intent: Dict[str, Any]
    dialogue_response_constraints: Dict[str, Any]
    education_plan: Dict[str, Any]

    # ======================
    # 5. 规则评分
    # matched_rules 来自规则引擎，是最终风险裁决的重要依据。
    # risk_score/risk_level 不直接交给 LLM 决定，避免模型自由发挥。
    # ======================
    matched_rules: List[Dict[str, Any]]
    rule_engine: Dict[str, Any]
    risk_score: int
    risk_level: str
    score_reason: str

    # ======================
    # 6. 输出生成
    # route_name 决定知识检索和回答策略：
    # prevention_consult / loss_response / education。
    # ======================
    route_name: str
    intervention_goal: str
    retrieved_docs: List[Dict[str, Any]]
    prompt: str
    answer: str
    result_summary: Dict[str, Any]

    # ======================
    # 内部过程字段
    # 这些字段用于节点间传递、调试和多轮案件状态维护，不作为对外主契约。
    # ======================
    previous_case_state: Dict[str, Any]
    case_context_analysis: Dict[str, Any]
    safety_status: str
    safety_assessment: Dict[str, Any]
    safety_assessment_raw_response: str
    case_should_close: bool
    scam_pattern_risk: str
    user_exposure_risk: str
    confirmed_facts: Dict[str, Any]
    uncertain_facts: List[str]
    case_closure_decision: Dict[str, Any]
    case_closure_raw_response: str
    case_closed: bool
    closure_reason: str
    closure_confidence: float
    case_context_confidence: float
    case_context_reason: str
    case_status: str
    user_situation: str
    # payment_status/loss_status 是 LLM 语义判断加本地硬事实校验后的状态。
    # 用它区分“对方要求我垫付”和“我已经垫付了”。
    payment_status: str
    loss_status: str
    status_evidence: str
    user_has_paid: Any
    user_has_loss: Any
    loss_amount: str
    payment_method: str
    user_has_shared_code: Any
    user_has_screen_share: Any
    user_has_downloaded_app: Any
    user_clicked_link: Any
    user_provided_identity_or_bank: Any
    current_risk_actions: List[str]
    opponent_identity: str
    platform_or_app: str
    links_or_apps: List[str]
    opponent_next_action: str
    safety_confirmed: bool
    ready_for_education: bool
    pending_resolution_actions: List[str]
    intent_reason: str
    intent_raw_response: str
    keywords: List[str]
    possible_fraud_types: List[str]
    possible_fraud_stages: List[str]
    risk_level_hint: str
    normalized_risk_features: List[str]
    risk_feature_raw_response: str
    rewritten_query: str
    retrieval_query: str
    answer_strategy: str
    next_question: str
    rewrite_raw_response: str
    warnings: List[str]
