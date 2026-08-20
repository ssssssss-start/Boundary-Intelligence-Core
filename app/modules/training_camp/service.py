import json
import re
import random
import uuid
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List
from langchain_core.messages import HumanMessage, SystemMessage

from app.clients.mongo_business_utils import (
    get_game_level_answer,
    get_game_level_by_id,
    get_user_game_progress,
    list_game_levels,
    record_game_result,
    record_game_simulation_result,
    upsert_game_levels,
)
from app.core.logger import logger
from app.lm.lm_utils import get_llm_client


DEFAULT_USER_ID = "demo_user"

QUESTION_POINTS = 2
SIMULATION_POINTS = 10

RANK_BADGES = [
    (300, "王者"),
    (280, "钻石I"),
    (260, "钻石II"),
    (240, "钻石III"),
    (220, "钻石IV"),
    (200, "钻石V"),
    (180, "黄金I"),
    (160, "黄金II"),
    (140, "黄金III"),
    (120, "黄金IV"),
    (100, "黄金V"),
    (80, "白银I"),
    (60, "白银II"),
    (40, "白银III"),
    (20, "白银IV"),
    (0, "白银V"),
]

DIFFICULTY_PROFILES = {
    "easy": {
        "label": "简单模式",
        "max_turns": 4,
        "script_style": "话术比较直接，较早暴露转账、验证码、陌生链接等明显风险点。",
        "prompt_style": "骗子水平较低，表达直接，风险信号明显，不要复杂伪装。",
    },
    "medium": {
        "label": "中等模式",
        "max_turns": 6,
        "script_style": "先建立可信身份，再逐步施压，风险点中等隐蔽。",
        "prompt_style": "骗子水平中等，先解释身份和理由，再逐步诱导用户配合。",
    },
    "hard": {
        "label": "困难模式",
        "max_turns": 8,
        "script_style": "更像真实客服或熟人，先铺垫可信背景，再用时间压力和情绪压力诱导。",
        "prompt_style": "骗子水平较高，话术克制自然，善于回应质疑，但仍必须逐步暴露可识别风险点。",
    },
}

CHINESE_NUMBERS = {
    "一": 1,
    "二": 2,
    "三": 3,
    "四": 4,
    "五": 5,
    "六": 6,
    "七": 7,
    "八": 8,
    "九": 9,
}

SCAM_ROLE_MAP = {
    "scam_brush_rebate": "刷单派单员",
    "scam_game_trade": "游戏交易中介",
    "scam_fake_investment": "投资导师",
    "scam_fake_customer_service": "冒充客服",
    "scam_fake_police": "冒充公检法人员",
    "scam_romance_investment": "网恋投资对象",
    "scam_fake_loan": "贷款客服",
    "scam_code_account_theft": "账号验证客服",
    "scam_screen_share_remote": "远程协助客服",
    "scam_ai_face_family": "仿冒亲友",
    "scam_fake_recruitment": "招聘专员",
}

SCAM_COVER_IDENTITY_MAP = {
    "scam_brush_rebate": "任务派单客服",
    "scam_game_trade": "交易平台客服",
    "scam_fake_investment": "投资顾问",
    "scam_fake_customer_service": "平台客服",
    "scam_fake_police": "公安机关工作人员",
    "scam_romance_investment": "朋友",
    "scam_fake_loan": "贷款客服",
    "scam_code_account_theft": "账号安全客服",
    "scam_screen_share_remote": "平台技术客服",
    "scam_ai_face_family": "家人",
    "scam_fake_recruitment": "招聘专员",
}

RISK_SIGNAL_KEYWORDS = [
    ("验证码", "索要验证码或动态码"),
    ("屏幕共享", "诱导开启屏幕共享"),
    ("远程", "要求远程协助或远程控制"),
    ("转账", "要求向个人或陌生账户转账"),
    ("垫付", "要求先垫付资金"),
    ("保证金", "要求缴纳保证金"),
    ("解冻费", "编造解冻费"),
    ("手续费", "编造手续费"),
    ("银行卡", "索要银行卡或支付信息"),
    ("身份证", "索要身份信息"),
    ("下载", "诱导下载陌生 App"),
    ("安全账户", "要求转入所谓安全账户"),
    ("中奖", "用中奖或礼品诱导操作"),
]

SCAM_SIM_SESSIONS: Dict[str, Dict[str, Any]] = {}

SIMULATION_MAX_TURNS = 6

LOSS_PATTERNS = [
    r"转了",
    r"已经转",
    r"打钱",
    r"汇款",
    r"付款",
    r"支付了",
    r"转给你",
    r"转过去",
    r"把钱.*给你",
    r"我交",
    r"我付",
    r"照你说",
    r"按你说",
    r"配合你",
    r"银行卡.*借",
    r"银行卡.*给",
    r"银行卡.*用",
    r"借.*银行卡",
    r"发给你验证码",
    r"验证码是",
    r"验证码.*给你",
    r"密码是",
    r"银行卡号",
    r"身份证号",
    r"我共享屏幕",
    r"共享屏幕",
    r"我下载",
    r"下载.*app",
    r"安装.*app",
    r"我点了链接",
    r"点.*链接",
]

MONEY_LOSS_PATTERNS = [
    r"转了",
    r"已经转",
    r"打钱",
    r"汇款",
    r"付款",
    r"支付了",
    r"已经付",
    r"已经支付",
    r"转给你",
    r"转过去",
    r"把钱.*给你",
    r"钱.*打过去",
    r"钱.*转过去",
]

SAFE_PATTERNS = [
    r"不转",
    r"不付款",
    r"不支付",
    r"不交钱",
    r"不打钱",
    r"不汇款",
    r"不能.*给你",
    r"不能.*转",
    r"不能.*支付",
    r"拒绝.*支付",
    r"拒绝.*转账",
    r"不发验证码",
    r"不给验证码",
    r"不共享",
    r"不下载",
    r"不点链接",
    r"官方核实",
    r"报警",
    r"96110",
    r"110",
    r"告诉家人",
    r"联系老师",
    r"保存证据",
    r"挂断",
    r"挂了",
    r"不考虑",
    r"不再沟通",
    r"不沟通",
    r"终止沟通",
    r"不联系",
]

HIGH_RISK_ACTION_PATTERNS = [
    r"(愿意|可以|好的|没问题|照你说|按你说|配合).{0,12}(银行卡|手机卡|电话卡|u盾|U盾|优盾|u盘|U盘|验证码|密码|转账|汇款|付款|链接|app|屏幕)",
    r"(银行卡|手机卡|电话卡|u盾|U盾|优盾|u盘|U盘).{0,12}(给你|借你|给你用|拿给你|交给你|带给你|来找你|去找你|见面)",
    r"(现在|马上|一会|明天|下午|晚上).{0,12}(带|拿|送|交).{0,12}(银行卡|手机卡|电话卡|u盾|U盾|优盾|u盘|U盘|现金|身份证)",
    r"(带着|拿着|带上|拿上).{0,12}(来找你|去找你|见你|见面)",
    r"(验证码|密码|银行卡号|身份证号).{0,12}(是|发你|给你|告诉你)",
]


def _seed_path() -> Path:
    return Path(__file__).resolve().parent / "data" / "seed_game_levels.json"


@lru_cache(maxsize=1)
def load_seed_levels() -> List[Dict[str, Any]]:
    with _seed_path().open("r", encoding="utf-8") as f:
        data = json.load(f)
    return data if isinstance(data, list) else []


def seed_game_levels() -> int:
    levels = load_seed_levels()
    return upsert_game_levels(levels, source=str(_seed_path()))


def _seed_level_by_id(level_id: int) -> Dict[str, Any] | None:
    target = int(level_id)
    return next((item for item in load_seed_levels() if int(item.get("level_id", 0) or 0) == target), None)


def _load_progress(user_id: str) -> Dict[str, Any]:
    try:
        return _normalize_progress(get_user_game_progress(user_id), user_id)
    except Exception as e:
        logger.warning(f"MongoDB 游戏进度读取失败，使用空进度：{e}")
        return _normalize_progress(None, user_id)


def _normalize_progress(progress: Dict[str, Any] | None, user_id: str) -> Dict[str, Any]:
    value = dict(progress or {})
    value.setdefault("user_id", user_id)
    value.setdefault("score", 0)
    value.setdefault("answered_count", 0)
    value.setdefault("correct_count", 0)
    value.setdefault("completed_levels", [])
    value.setdefault("wrong_levels", [])
    value.setdefault("simulation_count", 0)
    value.setdefault("simulation_pass_count", 0)
    value.setdefault("completed_simulations", [])
    value.setdefault("badges", [])
    return value


def rank_badge_from_score(score: int) -> str:
    value = int(score or 0)
    for threshold, badge in RANK_BADGES:
        if value >= threshold:
            return badge
    return "白银V"


def _compact_text(value: str) -> str:
    return re.sub(r"[\s，。！？、；：,.!?;:'\"“”‘’()（）【】\[\]-]+", "", str(value or "")).lower()


def _difficulty(level_id: int) -> str:
    if level_id <= 10:
        return "入门"
    if level_id <= 25:
        return "进阶"
    return "挑战"


def _risk_signals(level: Dict[str, Any]) -> List[str]:
    text = " ".join(str(level.get(key) or "") for key in ("title", "scenario", "question", "explanation", "fraud_type"))
    signals: List[str] = []
    for keyword, label in RISK_SIGNAL_KEYWORDS:
        if keyword in text and label not in signals:
            signals.append(label)
    if not signals:
        fraud_type = str(level.get("fraud_type") or "").strip()
        if fraud_type:
            signals.append(f"识别{fraud_type}中的关键异常要求")
    return signals[:4]


def _scammer_cover_identity(level: Dict[str, Any], fraud_type: str) -> str:
    scam_type_id = str(level.get("scam_type_id") or "")
    if scam_type_id in SCAM_COVER_IDENTITY_MAP:
        return SCAM_COVER_IDENTITY_MAP[scam_type_id]

    text = " ".join(str(level.get(key) or "") for key in ("title", "scenario", "question", "explanation")) + f" {fraud_type}"
    if "游戏交易" in text or "账号交易" in text:
        return "交易平台客服"
    if "刷单" in text or "返利" in text:
        return "任务派单客服"
    if "客服" in text or "退款" in text or "理赔" in text:
        return "平台客服"
    if "公检法" in text or "民警" in text or "公安" in text:
        return "公安机关工作人员"
    if "贷款" in text:
        return "贷款客服"
    if "中奖" in text or "礼品" in text:
        return "活动客服"
    if "招聘" in text:
        return "招聘专员"
    return "平台工作人员"


def _session_public(session: Dict[str, Any]) -> Dict[str, Any]:
    identity = session.get("scammer_identity") or _scammer_cover_identity(
        session.get("level", {}),
        str(session.get("fraud_type") or ""),
    )
    messages = []
    for item in session["messages"]:
        public_item = dict(item)
        if public_item.get("role") == "scammer":
            public_item["content"] = _sanitize_scammer_message(public_item.get("content", ""), identity)
        messages.append(public_item)
    return {
        "session_id": session["session_id"],
        "user_id": session["user_id"],
        "fraud_type": session["fraud_type"],
        "scammer_role": session["scammer_role"],
        "scammer_identity": identity,
        "status": session["status"],
        "turn_count": session["turn_count"],
        "max_turns": session["max_turns"],
        "difficulty": session.get("difficulty", "medium"),
        "difficulty_label": session.get("difficulty_label", "中等模式"),
        "scenario": session["scenario"],
        "risk_signals": session["risk_signals"],
        "messages": messages,
        "source": session.get("source", "local_script"),
    }


def _normalize_simulation_difficulty(value: str | None) -> str:
    key = str(value or "medium").strip().lower()
    if key in {"simple", "easy", "简单", "jiandan"}:
        return "easy"
    if key in {"hard", "difficult", "困难", "kunnan"}:
        return "hard"
    return "medium"


def _select_simulation_level(fraud_type: str | None = None) -> Dict[str, Any]:
    levels = load_seed_levels()
    if not levels:
        raise ValueError("游戏关卡种子数据为空")
    if fraud_type:
        normalized = str(fraud_type).strip()
        candidates = [
            item for item in levels
            if normalized in str(item.get("fraud_type") or "") or normalized in str(item.get("scam_type_id") or "")
        ]
        if candidates:
            return random.choice(candidates)
    return random.choice(levels)


def _scripted_scammer_line(session: Dict[str, Any], user_message: str = "") -> Dict[str, Any]:
    level = session["level"]
    role = session.get("scammer_identity", session["scammer_role"])
    fraud_type = session["fraud_type"]
    risk_signal = (session.get("risk_signals") or ["异常要求"])[0]
    turn = int(session.get("turn_count", 0) or 0)
    difficulty = session.get("difficulty", "medium")
    if difficulty == "easy":
        lines = [
            _simulation_opening_line(fraud_type, role, difficulty),
            f"流程很简单，你先配合完成“{risk_signal}”，我这边马上帮你放行。",
            "你先别走平台，按我发的方式处理更快，截图发我就行。",
            "别犹豫，名额快过期了，现在不处理后面就没法恢复。",
        ]
    elif difficulty == "hard":
        lines = [
            _simulation_opening_line(fraud_type, role, difficulty),
            f"你可以自己核对一下，异常主要卡在“{risk_signal}”这一步，我只是帮你走担保流程。",
            "如果你担心安全，可以先听我说完：不用给密码，只需要完成平台外的验证。",
            "窗口期比较短，拖太久订单会自动关闭，买家那边也会重新排队。",
            "为了避免流程失败，你保持在当前聊天里，我一步一步告诉你该点哪里。",
            "最后会出现一个确认码或保证金页面，你确认后资金就能正常结算。",
            "你如果现在退出，前面的核验可能要重来，账号交易也会被判异常。",
            "我们快完成了，你把页面显示的结果告诉我，我确认后给你收尾。",
        ]
    else:
        lines = [
            _simulation_opening_line(fraud_type, role, difficulty),
            f"你不用担心，我先帮你核对。现在主要差“{risk_signal}”这一步，处理完就能继续结算。",
            "为了不耽误买家确认，你先别退出，也别重新开单，按我这边流程来会快一点。",
            "这个处理窗口有时间限制，你现在拖太久可能会导致订单关闭或资金冻结。",
            "你先把验证页面的提示发我，必要的话按提示交一笔保证金，后面会一起退回。",
            "最后一步了，完成验证就能结束，先不要联系官方客服，免得流程被重复锁定。",
        ]
    return {
        "scammer_message": lines[min(turn, len(lines) - 1)],
        "pressure_level": min(5, turn + 1),
        "requested_action": risk_signal,
        "source": "local_script",
    }


def _simulation_opening_line(fraud_type: str, role: str, difficulty: str) -> str:
    if "游戏交易" in fraud_type:
        if difficulty == "easy":
            return f"你好，我是{role}。你这个游戏账号交易还差一步确认，先按我说的走一下。"
        if difficulty == "hard":
            return f"你好，我是{role}。你这笔账号交易买家已经确认了，我先帮你核对担保流程。"
        return f"你好，我是{role}。你这笔游戏交易显示待确认，我帮你看一下到账流程。"
    if "中奖" in fraud_type or "礼品" in fraud_type:
        return f"你好，我是{role}。你这边有个中奖名额待确认，超过时间可能就自动失效。"
    if "刷单" in fraud_type:
        return f"你好，我是{role}。你申请的任务名额已经通过，先做一单小额任务试一下。"
    return f"你好，我是{role}。你这边有一项流程需要尽快确认，我先帮你核对一下。"


def _sanitize_scammer_message(message: str, identity: str) -> str:
    value = str(message or "").strip()
    if not value:
        return value
    forbidden_labels = (
        "冒充客服",
        "可疑联系人",
        "骗子",
        "诈骗分子",
        "诈骗人员",
        "冒充公检法人员",
    )
    label_pattern = "|".join(re.escape(label) for label in forbidden_labels)
    return re.sub(
        rf"(你好，|您好，)?我是(?:一名|一个)?(?:{label_pattern})(?:诈骗)?",
        lambda match: f"{match.group(1) or ''}我是{identity}",
        value,
    )


def _llm_scammer_line(session: Dict[str, Any], user_message: str = "", use_llm: bool = True) -> Dict[str, Any]:
    if not use_llm:
        return _scripted_scammer_line(session, user_message)
    try:
        llm = get_llm_client(json_mode=True)
        identity = session.get("scammer_identity", session["scammer_role"])
        recent = session["messages"][-8:]
        system = (
            "你是防骗训练营里的角色扮演引擎，只能扮演“骗子话术模拟器”。"
            "目标是生成一轮逼真的但安全的诈骗诱导话术，帮助用户训练识别能力。"
            "你只生成骗子/可疑联系人的下一句话，不要生成用户的话，不要写“我：”，不要让用户自称骗子角色。"
            "scammer_identity 是对方对外自称身份，必须使用这个身份包装；"
            "scam_category_label 只是后台分类，绝不能自称“冒充客服”“可疑联系人”“骗子”或“诈骗分子”。"
            "用户永远是受训者/潜在受害者，不是中介、客服、民警、老师、导师或其他骗子身份。"
            "如果 latest_user_message 看起来像复述了骗子上一句话或包含骗子身份，不要承认它，继续以骗子身份自然推进。"
            "话术要贴合具体骗局，不要说“诈骗业务”“骗局业务”这类不真实措辞。"
            "禁止提供真实链接、真实账号、二维码、具体收款信息、具体金额、具体平台/App名称、具体违法操作教程或规避侦查建议。"
            "可以使用“验证金”“保证金”“担保流程”“验号链接”等风险概念，但不要写真实可执行细节。"
            "如果 turn_count 为 0，先建立具体交易背景和身份包装，不要第一句就要求转账、验证码或共享屏幕。"
            "如果 fraud_type 是游戏交易诈骗，只围绕游戏账号、装备/道具、点券、担保交易、验号、订单结算和平台外交易展开；"
            "不要无故提到微信冻结、银行卡冻结、公检法、贷款、中奖、投资等无关场景。"
            "每次只说一句骗子会说的话，长度不超过80字，口语化、自然、有场景。"
            "输出必须是 JSON："
            "{\"scammer_message\":\"...\",\"pressure_level\":1,\"requested_action\":\"...\"}"
        )
        human = {
            "fraud_type": session["fraud_type"],
            "scammer_identity": identity,
            "scam_category_label": session["scammer_role"],
            "difficulty": session.get("difficulty_label", "中等模式"),
            "difficulty_instruction": session.get("difficulty_profile", {}).get("prompt_style", ""),
            "scenario": session["scenario"],
            "risk_signals": session["risk_signals"],
            "turn_count": session["turn_count"],
            "recent_messages": recent,
            "latest_user_message": user_message,
        }
        response = llm.invoke([SystemMessage(content=system), HumanMessage(content=json.dumps(human, ensure_ascii=False))])
        content = getattr(response, "content", response)
        data = json.loads(str(content))
        message = str(data.get("scammer_message") or "").strip()
        if not message:
            raise ValueError("LLM 返回缺少 scammer_message")
        message = _sanitize_scammer_message(message, identity)
        return {
            "scammer_message": message[:160],
            "pressure_level": int(data.get("pressure_level", 1) or 1),
            "requested_action": str(data.get("requested_action") or ""),
            "source": "llm",
        }
    except Exception as exc:
        logger.warning(f"LLM 骗局模拟生成失败，降级本地脚本：{exc}")
        return _scripted_scammer_line(session, user_message)


def _match_patterns(text: str, patterns: List[str]) -> List[str]:
    return [pattern for pattern in patterns if re.search(pattern, text or "", flags=re.IGNORECASE)]


def _match_patterns_without_negation(text: str, patterns: List[str]) -> List[str]:
    value = text or ""
    hits: List[str] = []
    for pattern in patterns:
        matched = False
        for match in re.finditer(pattern, value, flags=re.IGNORECASE):
            prefix = value[max(0, match.start() - 12):match.start()]
            fragment = value[max(0, match.start() - 6):match.end()]
            if re.search(r"(不|不能|不可|别|拒绝|不要|不愿意|不会|没法|无法|停止|终止|挂断)", prefix + fragment):
                continue
            matched = True
            break
        if matched:
            hits.append(pattern)
    return hits


def _simulation_user_text(session: Dict[str, Any]) -> str:
    return "\n".join(item.get("content", "") for item in session["messages"] if item.get("role") == "user")


def _json_from_llm_content(content: Any) -> Dict[str, Any]:
    text = str(getattr(content, "content", content) or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
        text = re.sub(r"\s*```$", "", text)
    return json.loads(text)


def _evaluate_simulation_local(session: Dict[str, Any]) -> Dict[str, Any]:
    user_text = _simulation_user_text(session)
    loss_hits = _match_patterns_without_negation(user_text, LOSS_PATTERNS) + _match_patterns_without_negation(user_text, HIGH_RISK_ACTION_PATTERNS)
    loss_hits = list(dict.fromkeys(loss_hits))
    money_hits = _match_patterns_without_negation(user_text, MONEY_LOSS_PATTERNS)
    safe_hits = _match_patterns(user_text, SAFE_PATTERNS)
    score = 100
    score -= min(80, len(loss_hits) * 28)
    score += min(20, len(safe_hits) * 5)
    if int(session.get("turn_count", 0) or 0) >= session.get("max_turns", SIMULATION_MAX_TURNS) and not loss_hits:
        score += 10
    if loss_hits:
        score = min(score, 45)
    if money_hits:
        score = min(score, 9)
    score = max(0, min(100, score))
    if loss_hits:
        outcome = "被骗风险高"
    elif score >= 85:
        outcome = "成功识破"
    elif score >= 60:
        outcome = "基本安全"
    else:
        outcome = "仍有风险"
    return {
        "score": score,
        "outcome": outcome,
        "loss_signals": loss_hits,
        "money_loss_signals": money_hits,
        "safe_signals": safe_hits,
        "risk_signals": session.get("risk_signals", []),
        "debrief": _simulation_debrief(session, outcome, loss_hits, safe_hits),
        "passed": not loss_hits and score >= 60,
        "source": "local_rule",
    }


def _llm_evaluate_simulation(session: Dict[str, Any]) -> Dict[str, Any]:
    llm = get_llm_client(json_mode=True)
    messages = [
        {
            "role": item.get("role"),
            "content": item.get("content", ""),
        }
        for item in session.get("messages", [])
        if item.get("role") in {"user", "scammer"}
    ]
    system = (
        "你是防骗训练营的终局评分器。请只根据完整对话判断用户是否识破骗局。"
        "如果用户同意转账、付款、提供验证码/密码/银行卡/身份证、借出银行卡或手机卡、携带U盾/手机卡/银行卡见面、"
        "点击陌生链接、下载陌生App、开启屏幕共享，必须判为未识破或被骗风险高，即使用户没有真的完成转账。"
        "如果用户明确拒绝、停止操作、要求官方渠道核实、报警或联系可信第三方，才可判为识破。"
        "输出必须是 JSON："
        "{\"score\":0,\"outcome\":\"被骗风险高|仍有风险|基本安全|成功识破\","
        "\"passed\":false,\"loss_signals\":[\"...\"],\"safe_signals\":[\"...\"],\"debrief\":\"...\"}"
    )
    human = {
        "fraud_type": session.get("fraud_type", ""),
        "scenario": session.get("scenario", ""),
        "risk_signals": session.get("risk_signals", []),
        "messages": messages,
    }
    response = llm.invoke([SystemMessage(content=system), HumanMessage(content=json.dumps(human, ensure_ascii=False))])
    data = _json_from_llm_content(response)
    score = max(0, min(100, int(data.get("score", 0) or 0)))
    outcome = str(data.get("outcome") or "").strip()
    if outcome not in {"被骗风险高", "仍有风险", "基本安全", "成功识破"}:
        outcome = "成功识破" if score >= 85 else "基本安全" if score >= 60 else "仍有风险" if score >= 40 else "被骗风险高"
    loss_signals = [str(item) for item in data.get("loss_signals") or [] if str(item).strip()]
    safe_signals = [str(item) for item in data.get("safe_signals") or [] if str(item).strip()]
    passed = bool(data.get("passed")) and not loss_signals and score >= 60
    if not passed and score >= 60 and outcome in {"被骗风险高", "仍有风险"}:
        score = min(score, 55)
    if passed and outcome == "成功识破" and score < 85:
        score = 85
    return {
        "score": score,
        "outcome": outcome,
        "passed": passed,
        "loss_signals": loss_signals,
        "safe_signals": safe_signals,
        "risk_signals": session.get("risk_signals", []),
        "debrief": str(data.get("debrief") or _simulation_debrief(session, outcome, loss_signals, safe_signals)),
        "source": "llm",
    }


def _calibrate_simulation_result(result: Dict[str, Any], local: Dict[str, Any]) -> Dict[str, Any]:
    calibrated = dict(result)
    score = max(0, min(100, int(calibrated.get("score", 0) or 0)))
    outcome = str(calibrated.get("outcome") or "").strip()
    loss_signals = list(calibrated.get("loss_signals") or [])
    safe_signals = list(calibrated.get("safe_signals") or [])
    money_hits = list(local.get("money_loss_signals") or [])

    if money_hits:
        calibrated["loss_signals"] = list(dict.fromkeys(loss_signals + money_hits))
        calibrated["money_loss_signals"] = money_hits
        calibrated["score"] = min(score, 9)
        calibrated["outcome"] = "被骗风险高"
        calibrated["passed"] = False
        return calibrated

    if local.get("loss_signals"):
        calibrated["loss_signals"] = list(dict.fromkeys(loss_signals + list(local.get("loss_signals") or [])))
        calibrated["score"] = min(score, 45)
        calibrated["outcome"] = "被骗风险高"
        calibrated["passed"] = False
        return calibrated

    if local.get("passed") and local.get("outcome") == "成功识破":
        calibrated["score"] = max(score, int(local.get("score", 90) or 90), 90)
        calibrated["outcome"] = "成功识破"
        calibrated["passed"] = True
        calibrated["safe_signals"] = list(dict.fromkeys(safe_signals + list(local.get("safe_signals") or [])))
        return calibrated

    if outcome == "成功识破":
        score = max(score, 90 if safe_signals or local.get("safe_signals") else 85)
        calibrated["score"] = score
        calibrated["passed"] = True
        return calibrated

    if outcome == "基本安全":
        calibrated["score"] = max(score, 65)
        calibrated["passed"] = score >= 60
        return calibrated

    if safe_signals and not loss_signals and score < 60:
        calibrated["score"] = 80
        calibrated["outcome"] = "基本安全"
        calibrated["passed"] = True
        return calibrated

    calibrated["score"] = score
    calibrated["passed"] = bool(calibrated.get("passed")) and not loss_signals and score >= 60
    return calibrated


def _evaluate_simulation(session: Dict[str, Any], use_llm: bool = False) -> Dict[str, Any]:
    local = _evaluate_simulation_local(session)
    if not use_llm:
        return local
    try:
        llm_result = _llm_evaluate_simulation(session)
        return _calibrate_simulation_result(llm_result, local)
    except Exception as exc:
        logger.warning(f"LLM 骗局模拟评分失败，降级本地规则：{exc}")
        local["source"] = "local_rule"
        return local


def _simulation_debrief(session: Dict[str, Any], outcome: str, loss_hits: List[str], safe_hits: List[str]) -> str:
    if loss_hits:
        return "你在对话中出现了转账、泄露验证码/密码、点链接、下载 App 或共享屏幕等高危倾向，真实场景中应立即停止并保留证据。"
    if safe_hits:
        return "你能主动拒绝、核实官方渠道或保留证据，说明已经识别到骗子的诱导链条。"
    return "你没有明显被骗动作，但拒绝和核实表达还不够明确。真实场景中要直接拒绝转账、验证码、陌生链接和屏幕共享。"


def start_scam_simulation(
    user_id: str = DEFAULT_USER_ID,
    fraud_type: str | None = None,
    difficulty: str | None = "medium",
    use_llm: bool = True,
) -> Dict[str, Any]:
    level = _select_simulation_level(fraud_type)
    difficulty_key = _normalize_simulation_difficulty(difficulty)
    difficulty_profile = DIFFICULTY_PROFILES[difficulty_key]
    session_id = f"sim-{uuid.uuid4().hex[:12]}"
    fraud_name = str(level.get("fraud_type") or "典型骗局")
    scammer_role = SCAM_ROLE_MAP.get(str(level.get("scam_type_id") or ""), "可疑联系人")
    scammer_identity = _scammer_cover_identity(level, fraud_name)
    session = {
        "session_id": session_id,
        "user_id": user_id or DEFAULT_USER_ID,
        "level": level,
        "fraud_type": fraud_name,
        "scammer_role": scammer_role,
        "scammer_identity": scammer_identity,
        "scenario": str(level.get("scenario") or ""),
        "risk_signals": _risk_signals(level),
        "messages": [],
        "turn_count": 0,
        "max_turns": int(difficulty_profile.get("max_turns", SIMULATION_MAX_TURNS)),
        "difficulty": difficulty_key,
        "difficulty_label": str(difficulty_profile.get("label", "中等模式")),
        "difficulty_profile": difficulty_profile,
        "status": "running",
        "source": "local_script",
    }
    line = _llm_scammer_line(session, "", use_llm=use_llm)
    session["source"] = line.get("source", "local_script")
    session["messages"].append(
        {
            "role": "scammer",
            "content": line["scammer_message"],
            "pressure_level": line.get("pressure_level", 1),
            "requested_action": line.get("requested_action", ""),
        }
    )
    SCAM_SIM_SESSIONS[session_id] = session
    return {
        "message": "骗局模拟已开始",
        "simulation": _session_public(session),
        "scammer_message": line["scammer_message"],
    }


def continue_scam_simulation(
    session_id: str,
    user_message: str = "",
    voice_text: str = "",
    use_llm: bool = True,
) -> Dict[str, Any]:
    session = SCAM_SIM_SESSIONS.get(session_id)
    if not session:
        raise ValueError(f"模拟会话不存在：{session_id}")
    if session.get("status") != "running":
        return finish_scam_simulation(session_id)

    content = str(voice_text or user_message or "").strip()
    if not content:
        raise ValueError("用户回复不能为空")
    session["messages"].append({"role": "user", "content": content, "input_mode": "voice" if voice_text else "text"})
    session["turn_count"] = int(session.get("turn_count", 0) or 0) + 1
    interim = _evaluate_simulation(session, use_llm=False)
    if interim["loss_signals"] or session["turn_count"] >= session.get("max_turns", SIMULATION_MAX_TURNS):
        session["status"] = "finished"
        final = finish_scam_simulation(session_id)
        final["ended_by"] = "risk_signal" if interim["loss_signals"] else "max_turns"
        return final

    line = _llm_scammer_line(session, content, use_llm=use_llm)
    session["source"] = line.get("source", session.get("source", "local_script"))
    session["messages"].append(
        {
            "role": "scammer",
            "content": line["scammer_message"],
            "pressure_level": line.get("pressure_level", 1),
            "requested_action": line.get("requested_action", ""),
        }
    )
    return {
        "message": "模拟继续",
        "simulation": _session_public(session),
        "scammer_message": line["scammer_message"],
        "interim_score": interim["score"],
    }


def finish_scam_simulation(session_id: str, user_message: str | None = None) -> Dict[str, Any]:
    session = SCAM_SIM_SESSIONS.get(session_id)
    if not session:
        raise ValueError(f"模拟会话不存在：{session_id}")
    if user_message:
        session["messages"].append({"role": "user", "content": str(user_message), "input_mode": "text"})
        session["turn_count"] = int(session.get("turn_count", 0) or 0) + 1
    session["status"] = "finished"
    result = _evaluate_simulation(session, use_llm=True)
    passed = bool(result.get("passed", not result["loss_signals"] and result["score"] >= 60))
    score_delta = SIMULATION_POINTS if passed and not session.get("reward_recorded") else 0
    badge = "骗局模拟通关者" if score_delta else ""
    progress = _load_progress(session["user_id"])
    source = "mongo"
    if score_delta:
        try:
            progress = _normalize_progress(
                record_game_simulation_result(
                    user_id=session["user_id"],
                    session_id=session_id,
                    score_delta=score_delta,
                    passed=passed,
                    badge=badge,
                ),
                session["user_id"],
            )
            session["reward_recorded"] = True
            source = "mongo"
        except Exception as e:
            logger.warning(f"MongoDB 模拟训练积分写入失败，返回无持久化结果：{e}")
            progress = _normalize_progress(
                {
                    "user_id": session["user_id"],
                    "score": score_delta,
                    "simulation_count": 1,
                    "simulation_pass_count": 1 if passed else 0,
                    "completed_simulations": [session_id],
                    "badges": [badge] if badge else [],
                },
                session["user_id"],
            )
            session["reward_recorded"] = True
            source = "json_fallback"
    return {
        "message": "骗局模拟已结束",
        "simulation": _session_public(session),
        "result": result,
        "score": result["score"],
        "outcome": result["outcome"],
        "points_delta": score_delta,
        "badge": badge,
        "rank_badge": rank_badge_from_score(int(progress.get("score", 0) or 0)),
        "progress": progress,
        "gamification": _gamification(progress, len(load_seed_levels())),
        "source": source,
    }


def _scenario_simulation(level: Dict[str, Any]) -> Dict[str, Any]:
    scam_type_id = str(level.get("scam_type_id") or "")
    opponent_role = SCAM_ROLE_MAP.get(scam_type_id, "可疑联系人")
    fraud_type = str(level.get("fraud_type") or "典型骗局")
    scenario = str(level.get("scenario") or "")
    question = str(level.get("question") or "")
    return {
        "scene_id": f"training-scene-{int(level.get('level_id', 0) or 0):03d}",
        "mode": "scenario_simulation",
        "fraud_type": fraud_type,
        "player_role": "受训者",
        "opponent_role": opponent_role,
        "opening_line": scenario,
        "mission": question or f"判断这段{fraud_type}场景中最安全的处置方式。",
        "risk_signals": _risk_signals(level),
        "success_condition": "识别异常要求，选择或说出最安全的回应。",
    }


def _voice_interaction(level: Dict[str, Any]) -> Dict[str, Any]:
    options = [str(item) for item in level.get("options") or []]
    return {
        "enabled": True,
        "language": "zh-CN",
        "input_type": "speech_to_text",
        "prompt": "可以点击语音按钮，说出你的判断或直接说“选择第几项”。",
        "answer_hints": [f"选择第{index + 1}项：{option}" for index, option in enumerate(options)],
        "fallback": "浏览器不支持语音识别时，仍可点击选项完成闯关。",
    }


def _public_level(level: Dict[str, Any], total: int = 0) -> Dict[str, Any]:
    public = dict(level)
    public.pop("_id", None)
    public.pop("answer", None)
    level_id = int(public.get("level_id", 0) or 0)
    public["level_no"] = level_id
    public["chapter"] = public.get("fraud_type") or "综合防骗训练"
    public["difficulty"] = _difficulty(level_id)
    public["total_levels"] = total
    public["interaction_modes"] = ["choice", "voice"]
    public["scenario_simulation"] = _scenario_simulation(level)
    public["voice_interaction"] = _voice_interaction(level)
    public["reward_preview"] = {
        "points": QUESTION_POINTS,
        "badge": str(level.get("badge", "") or ""),
    }
    return public


def _fallback_level(level_id: int) -> Dict[str, Any]:
    levels = load_seed_levels()
    if not levels:
        raise ValueError("游戏关卡种子数据为空")
    index = max(0, min(int(level_id) - 1, len(levels) - 1))
    return _public_level(levels[index], total=len(levels))


def _gamification(progress: Dict[str, Any], total: int) -> Dict[str, Any]:
    completed = list(progress.get("completed_levels") or [])
    badges = list(progress.get("badges") or [])
    score = int(progress.get("score", 0) or 0)
    rank_badge = rank_badge_from_score(score)
    completion_rate = round(len(set(completed)) / total, 4) if total else 0
    return {
        "score": score,
        "badges": badges,
        "rank_badge": rank_badge,
        "rank": rank_badge,
        "completed_levels": completed,
        "completion_rate": completion_rate,
        "assessment_level": _assessment_label(int(progress.get("answered_count", 0) or 0), int(progress.get("correct_count", 0) or 0), total),
    }


def _assessment_label(answered: int, correct: int, total: int) -> str:
    accuracy = correct / answered if answered else 0
    if answered >= total and accuracy >= 0.9:
        return "优秀"
    if accuracy >= 0.7:
        return "良好"
    if answered:
        return "需加强"
    return "未测评"


def get_next_level(user_id: str = DEFAULT_USER_ID, level_id: int | None = None) -> Dict[str, Any]:
    levels = load_seed_levels()
    total = len(levels)
    progress = _load_progress(user_id)
    completed = {int(item) for item in (progress.get("completed_levels") or []) if str(item).isdigit()}
    if level_id is None:
        candidate = next((item for item in levels if int(item.get("level_id", 0) or 0) not in completed), None)
        level_id = int(candidate.get("level_id")) if candidate else 1
    level = _seed_level_by_id(int(level_id)) or (levels[0] if levels else None)
    if not level:
        raise ValueError("游戏关卡种子数据为空")
    try:
        seed_game_levels()
    except Exception as e:
        logger.warning(f"MongoDB 游戏关卡同步失败，继续使用本地 200 题种子：{e}")
    return {
        "message": "获取关卡成功",
        "level": _public_level(level, total=total),
        "total": total,
        "progress": progress,
        "gamification": _gamification(progress, total),
        "multimodal": {"voice_enabled": True, "speech_recognition": "browser"},
        "source": "seed",
    }


def _spoken_index(text: str, option_count: int) -> int | None:
    compact = _compact_text(text)
    if not compact:
        return None
    for index in range(1, option_count + 1):
        if f"第{index}项" in compact or f"选{index}" in compact or f"选择{index}" in compact:
            return index - 1
    for char, value in CHINESE_NUMBERS.items():
        if value <= option_count and (f"第{char}项" in compact or f"选{char}" in compact or f"选择{char}" in compact):
            return value - 1
    for index, letter in enumerate("abcd"[:option_count]):
        if compact in {letter, f"选{letter}", f"选择{letter}"}:
            return index
    return None


def _match_answer(level: Dict[str, Any], answer: str, voice_text: str = "") -> Dict[str, Any]:
    expected = str(level.get("answer", "")).strip()
    options = [str(item).strip() for item in level.get("options") or []]
    submitted = str(answer or "").strip()
    transcript = str(voice_text or "").strip()
    source_text = transcript or submitted
    source = "voice_transcript" if transcript else "choice"

    selected = submitted
    confidence = 1.0 if submitted == expected and submitted else 0.0
    if transcript:
        spoken_index = _spoken_index(transcript, len(options))
        if spoken_index is not None:
            selected = options[spoken_index]
            confidence = 0.9
        else:
            compact_transcript = _compact_text(transcript)
            for option in options:
                compact_option = _compact_text(option)
                if compact_option and (compact_option in compact_transcript or compact_transcript in compact_option):
                    selected = option
                    confidence = 0.86
                    break
            if not selected and source_text:
                selected = source_text

    correct = _compact_text(selected) == _compact_text(expected)
    if correct and confidence == 0.0:
        confidence = 1.0
    return {
        "expected": expected,
        "selected_answer": selected,
        "source": source,
        "voice_text": transcript,
        "confidence": round(confidence, 2),
        "correct": correct,
    }


def _load_level_for_answer(level_id: int) -> tuple[Dict[str, Any] | None, str]:
    seed_level = _seed_level_by_id(level_id)
    if seed_level:
        try:
            seed_game_levels()
        except Exception as e:
            logger.warning(f"MongoDB 游戏关卡同步失败，答题使用本地种子：{e}")
        return seed_level, "seed"
    try:
        level = get_game_level_answer(level_id)
        if level:
            return level, "mongo"
    except Exception as e:
        logger.warning(f"MongoDB 游戏答题读取失败，降级使用本地种子：{e}")
    level = next((item for item in load_seed_levels() if int(item.get("level_id", 0)) == int(level_id)), None)
    return level, "json_fallback"


def _next_level_id(level_id: int, total: int) -> int:
    if total <= 0:
        return int(level_id)
    return int(level_id) + 1 if int(level_id) < total else 1


def submit_level(
    user_id: str,
    level_id: int,
    answer: str = "",
    interaction_mode: str = "choice",
    voice_text: str = "",
    audio_meta: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    level, source = _load_level_for_answer(level_id)
    if not level:
        raise ValueError(f"关卡不存在：{level_id}")

    match = _match_answer(level, answer, voice_text)
    is_correct = bool(match["correct"])
    points_delta = QUESTION_POINTS if is_correct else 0
    badge = str(level.get("badge", "") or "") if is_correct else ""

    try:
        progress = record_game_result(
            user_id=user_id,
            level_id=int(level_id),
            is_correct=is_correct,
            points_delta=points_delta,
            badge=badge,
        )
    except Exception as e:
        logger.warning(f"MongoDB 游戏进度写入失败，返回无持久化结果：{e}")
        progress = {
            "user_id": user_id,
            "score": points_delta,
            "answered_count": 1,
            "correct_count": 1 if is_correct else 0,
            "completed_levels": [int(level_id)] if is_correct else [],
            "wrong_levels": [] if is_correct else [int(level_id)],
            "badges": [badge] if badge else [],
        }
        source = "json_fallback"
    progress = _normalize_progress(progress, user_id)

    levels = load_seed_levels()
    total = len(levels)
    next_id = _next_level_id(level_id, total)
    return {
        "message": "答题完成",
        "level_id": int(level_id),
        "correct": is_correct,
        "answer": match["expected"],
        "selected_answer": match["selected_answer"],
        "points_delta": points_delta,
        "badge": badge,
        "explanation": level.get("explanation", ""),
        "interaction": {
            "mode": interaction_mode or match["source"],
            "answer_source": match["source"],
            "voice_text": match["voice_text"],
            "confidence": match["confidence"],
            "audio_meta": audio_meta or {},
        },
        "simulation_feedback": {
            "npc_response": "你识别出了关键风险，成功阻断骗局。" if is_correct else "这个回应仍可能被对方继续诱导，建议回看风险信号。",
            "debrief": level.get("explanation", ""),
            "risk_signals": _risk_signals(level),
        },
        "reward": {
            "points_delta": points_delta,
            "badge_unlocked": badge,
            "score_total": progress.get("score", 0),
            "badges_total": len(progress.get("badges") or []),
        },
        "next_level_id": next_id,
        "progress": progress,
        "gamification": _gamification(progress, total),
        "source": source,
    }


def build_game_report(user_id: str = DEFAULT_USER_ID) -> Dict[str, Any]:
    levels = load_seed_levels()
    progress = _load_progress(user_id)

    total = len(levels)
    answered = int(progress.get("answered_count", 0) or 0)
    correct = int(progress.get("correct_count", 0) or 0)
    accuracy = round(correct / answered, 4) if answered else 0
    badges = list(progress.get("badges") or [])
    available_badges = sorted({str(item.get("badge")) for item in load_seed_levels() if item.get("badge")})
    assessment = _assessment_label(answered, correct, total)
    completion_rate = round(len(set(progress.get("completed_levels") or [])) / total, 4) if total else 0
    score = int(progress.get("score", 0) or 0)
    rank_badge = rank_badge_from_score(score)
    simulation_count = int(progress.get("simulation_count", 0) or 0)
    simulation_pass_count = int(progress.get("simulation_pass_count", 0) or 0)

    return {
        "message": "测评报告生成完成",
        "user_id": user_id,
        "total_levels": total,
        "answered_count": answered,
        "correct_count": correct,
        "accuracy": accuracy,
        "completion_rate": completion_rate,
        "score": score,
        "badges": badges,
        "rank_badge": rank_badge,
        "assessment_level": rank_badge,
        "accuracy_level": assessment,
        "simulation_count": simulation_count,
        "simulation_pass_count": simulation_pass_count,
        "score_rules": {
            "question_correct": QUESTION_POINTS,
            "simulation_pass": SIMULATION_POINTS,
            "rank_badges": {
                "白银V": "0-19分",
                "白银IV": "20-39分",
                "白银III": "40-59分",
                "白银II": "60-79分",
                "白银I": "80-99分",
                "黄金V": "100-119分",
                "黄金IV": "120-139分",
                "黄金III": "140-159分",
                "黄金II": "160-179分",
                "黄金I": "180-199分",
                "钻石V": "200-219分",
                "钻石IV": "220-239分",
                "钻石III": "240-259分",
                "钻石II": "260-279分",
                "钻石I": "280-299分",
                "王者": "300分及以上",
            },
        },
        "training_modes": ["题库闯关", "实时骗局模拟", "语音对话"],
        "multimodal_capabilities": {
            "voice_interaction": True,
            "speech_to_text": "browser",
            "text_choice_fallback": True,
            "llm_roleplay": True,
        },
        "achievement_summary": {
            "badges_unlocked": len(badges),
            "available_badges": len(available_badges),
            "rank_badge": rank_badge,
            "next_badge": _next_rank_badge(score),
        },
    }


def _next_rank_badge(score: int) -> str:
    value = int(score or 0)
    for threshold, badge in reversed(RANK_BADGES):
        if value < threshold:
            return badge
    return ""
