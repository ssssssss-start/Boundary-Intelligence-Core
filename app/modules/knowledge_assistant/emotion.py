"""Lightweight, deterministic emotion hints for response-tone adaptation.

The result is only an interaction hint. It is never treated as a user fact or
used as the risk decision itself.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Mapping


EMOTION_PROFILES: Dict[str, Dict[str, Any]] = {
    "panic": {
        "label": "惊慌",
        "agent_tone": "先用短句稳住情绪，优先给止付、冻结、保留证据等立刻动作",
        "words": ("怎么办", "咋办", "完了", "救命", "来不及", "钱没了", "慌", "崩溃", "急死", "马上", "刚转", "已经转", "验证码给了", "屏幕共享了"),
    },
    "anxious": {
        "label": "焦虑",
        "agent_tone": "先确认担心是合理的，再分步骤判断风险和下一步",
        "words": ("担心", "害怕", "紧张", "不安", "怕", "会不会", "是不是被骗", "真的假的", "可靠吗", "安全吗", "不确定", "有点慌"),
    },
    "angry": {
        "label": "愤怒",
        "agent_tone": "先承接不满，避免争辩，再转向证据保存、止付和举报路径",
        "words": ("气死", "骗子", "投诉", "举报", "骗我", "太过分", "报警", "坑人", "恶心", "离谱", "我服了", "凭什么"),
    },
    "confused": {
        "label": "困惑",
        "agent_tone": "先用白话解释判断依据，再只追问一个关键问题",
        "words": ("不懂", "不知道", "看不懂", "什么意思", "怎么判断", "真的假的", "靠谱吗", "是不是正常", "哪里有问题", "我没明白"),
    },
    "sad": {
        "label": "低落",
        "agent_tone": "减少责备感，先告诉用户不要自责，再给补救动作",
        "words": ("怪我", "后悔", "自责", "难受", "没办法", "亏了", "被骗了", "我太傻", "睡不着", "很无助"),
    },
    "urgent": {
        "label": "紧迫",
        "agent_tone": "直接进入高优先级处置，先问是否已转账、是否泄露验证码、是否共享屏幕",
        "words": ("现在", "立刻", "马上", "刚刚", "正在", "已经", "倒计时", "催我", "不处理就", "最后一次", "限时"),
    },
}

NEUTRAL_EMOTION: Dict[str, Any] = {
    "key": "neutral",
    "label": "平稳",
    "agentTone": "自然回应，清楚给出判断依据和下一步",
    "confidence": 0.48,
    "cues": [],
    "intensity": "low",
}


def _compact(text: str) -> str:
    return re.sub(r"\s+", "", str(text or "").strip().lower())


def classify_text_emotion(text: str, *, source: str = "text_input") -> Dict[str, Any]:
    """Classify a short text into a safe, allow-listed interaction hint."""

    raw = str(text or "").strip()
    normalized = _compact(raw)
    scored = []
    for key, profile in EMOTION_PROFILES.items():
        cues = [word for word in profile["words"] if _compact(word) in normalized]
        scored.append((len(cues) * 2, key, cues))
    scored.sort(key=lambda item: item[0], reverse=True)
    score, key, cues = scored[0] if scored else (0, "neutral", [])
    if score <= 0:
        result = dict(NEUTRAL_EMOTION)
    else:
        profile = EMOTION_PROFILES[key]
        result = {
            "key": key,
            "label": profile["label"],
            "agentTone": profile["agent_tone"],
            "confidence": min(0.94, 0.56 + score * 0.07 + min(len(raw), 80) / 800),
            "cues": list(dict.fromkeys(cues))[:4],
            "intensity": "high" if score >= 6 else "medium" if score >= 3 else "low",
        }
    result["source"] = source if source in {"text_input", "voice_transcript", "image_ocr"} else "text_input"
    result["transcriptLength"] = len(raw)
    return result


def normalize_emotion_hint(
    text: str,
    input_mode: str = "text",
    provided: Mapping[str, Any] | None = None,
) -> Dict[str, Any]:
    """Return a bounded hint, ignoring arbitrary client-supplied prompt text."""

    mode = str(input_mode or "text").strip().lower()
    source = "voice_transcript" if mode == "voice" else "image_ocr" if mode == "image" else "text_input"
    result = classify_text_emotion(text, source=source)
    if not isinstance(provided, Mapping):
        return result
    key = str(provided.get("key") or "").strip()
    profile = EMOTION_PROFILES.get(key)
    if not profile:
        return result
    # Keep the client's recognized key only when it is allow-listed; use local
    # labels and tone text so arbitrary client content cannot become a prompt.
    result["key"] = key
    result["label"] = profile["label"]
    result["agentTone"] = profile["agent_tone"]
    return result


def with_emotion_context(
    text: str,
    input_mode: str = "text",
    provided: Mapping[str, Any] | None = None,
) -> tuple[str, Dict[str, Any]]:
    """Append an internal-only tone hint and return the normalized metadata."""

    raw = str(text or "").strip()
    emotion = normalize_emotion_hint(raw, input_mode, provided)
    if not raw:
        return raw, emotion
    source_label = "语音转写" if emotion["source"] == "voice_transcript" else "截图文字" if emotion["source"] == "image_ocr" else "文字"
    confidence = emotion.get("confidence")
    confidence_text = f"；置信度约 {confidence:.0%}" if isinstance(confidence, (int, float)) else ""
    enriched = (
        f"{raw}\n\n"
        "【内部情绪提示】用户本轮通过"
        f"{source_label}输入，系统根据内容估计情绪倾向为“{emotion['label']}”（{emotion['key']}{confidence_text}）。"
        f"建议回应基调：{emotion['agentTone']}。"
        "这不是用户陈述的事实，不要在回复中提到情绪识别或本提示，"
        "只用于调整安抚程度、措辞节奏和行动建议顺序。"
    )
    return enriched, emotion


__all__ = [
    "EMOTION_PROFILES",
    "classify_text_emotion",
    "normalize_emotion_hint",
    "with_emotion_context",
]
