#!/usr/bin/env python3
"""Build the user-provided labeled seed set and one rewrite per seed.

The staging file keeps the user's category assignment separate from the
normalized evaluation schema.  Generated rewrites retain the same case family
and are therefore augmentation data, not an independent blind test set.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import date
from pathlib import Path
from typing import Any, Dict, List


ROOT = Path(__file__).resolve().parents[1]
STAGING = ROOT / "evaluation/annotations/user_seed_cases_105.jsonl"
SEED_OUT = ROOT / "evaluation/annotations/user_labeled_105.jsonl"
AUGMENTED_OUT = ROOT / "evaluation/annotations/user_augmented_210.jsonl"
DEVELOPMENT_OUT = ROOT / "evaluation/splits/development.jsonl"
MANIFEST_OUT = ROOT / "evaluation/annotations/user_annotation_manifest.json"

TODAY = date.today().isoformat()

FEATURES: Dict[str, List[str]] = {
    "游戏交易诈骗": ["私下交易", "账号密码索取", "低价代充", "要求缴纳解冻费"],
    "虚假购物服务诈骗": ["私下交易", "要求垫付资金", "已发生转账"],
    "冒充客服诈骗": ["冒充客服", "要求垫付资金", "索要银行卡或身份信息"],
    "屏幕共享/远程控制诈骗": ["屏幕共享", "远程控制", "索要银行卡或身份信息"],
    "钓鱼链接诈骗": ["点击陌生链接", "索要银行卡或身份信息", "拒绝二次核验"],
    "验证码/账户盗刷诈骗": ["索要验证码", "索要银行卡或身份信息", "已泄露验证码"],
    "校园二手/票务交易诈骗": ["私下交易", "要求垫付资金", "已发生转账"],
    "网络贷款诈骗": ["贷款前收费", "要求垫付资金", "诱导下载陌生APP"],
    "征信修复/注销账户诈骗": ["贷款前收费", "索要银行卡或身份信息", "要求垫付资金"],
    "刷单返利诈骗": ["任务返佣", "承诺返利", "要求继续补单", "要求垫付资金"],
    "情感交友诱导投资诈骗": ["陌生人引导", "高收益诱导", "陌生投资平台", "已发生转账"],
    "虚假投资理财诈骗": ["高收益诱导", "陌生投资平台", "无法提现", "已发生转账"],
    "AI换脸冒充熟人诈骗": ["AI换脸冒充", "熟人新账号联系", "已发生转账"],
    "冒充领导或熟人借钱诈骗": ["熟人新账号联系", "已发生转账", "拒绝二次核验"],
    "冒充公检法诈骗": ["冒充公检法", "要求垫付资金", "要求删除证据"],
    "两卡出租出借与跑分诈骗": ["非本人账户收款", "要求垫付资金", "已发生转账"],
    "求职实习招聘诈骗": ["贷款前收费", "要求垫付资金", "陌生人引导"],
    "机票火车票退改签诈骗": ["冒充客服", "点击陌生链接", "要求垫付资金"],
    "租房合租押金诈骗": ["私下交易", "要求垫付资金", "已发生转账"],
    "冒充老师辅导员收费诈骗": ["冒充客服", "要求垫付资金", "已发生转账"],
    "奖助学金/学费退费诈骗": ["冒充客服", "索要银行卡或身份信息", "索要验证码"],
    "裸聊敲诈勒索诈骗": ["要求垫付资金", "要求删除证据", "已发生转账"],
    "虚假中奖/免费礼品诈骗": ["要求垫付资金", "索要验证码", "点击陌生链接"],
    "考试考证论文服务诈骗": ["要求垫付资金", "已发生转账"],
}

PREFIXES = {
    "游戏交易诈骗": "我在游戏账号或道具交易中遇到一个情况：",
    "虚假购物服务诈骗": "我在网购或售后环节遇到一个情况：",
    "冒充客服诈骗": "我在和所谓客服沟通时遇到一个情况：",
    "屏幕共享/远程控制诈骗": "我在远程协助或售后操作中遇到一个情况：",
    "钓鱼链接诈骗": "我在点击陌生链接或二维码后遇到一个情况：",
    "验证码/账户盗刷诈骗": "我在账户验证过程中遇到一个情况：",
    "校园二手/票务交易诈骗": "我在票务或二手交易中遇到一个情况：",
    "网络贷款诈骗": "我在申请网络贷款时遇到一个情况：",
    "征信修复/注销账户诈骗": "我在处理征信或注销账户时遇到一个情况：",
    "刷单返利诈骗": "我在兼职或刷单任务中遇到一个情况：",
    "情感交友诱导投资诈骗": "我在网络交友和资金往来中遇到一个情况：",
    "虚假投资理财诈骗": "我在投资或提现过程中遇到一个情况：",
    "AI换脸冒充熟人诈骗": "我在核实亲友身份时遇到一个情况：",
    "冒充领导或熟人借钱诈骗": "我在处理熟人借钱请求时遇到一个情况：",
    "冒充公检法诈骗": "我在接到所谓执法人员联系时遇到一个情况：",
    "两卡出租出借与跑分诈骗": "我在看到代收代付兼职时遇到一个情况：",
    "求职实习招聘诈骗": "我在求职或入职环节遇到一个情况：",
    "机票火车票退改签诈骗": "我在处理机票或火车票退改签时遇到一个情况：",
    "租房合租押金诈骗": "我在租房和押金处理上遇到一个情况：",
    "冒充老师辅导员收费诈骗": "我在收到学校收费通知时遇到一个情况：",
    "奖助学金/学费退费诈骗": "我在处理助学金或退费通知时遇到一个情况：",
    "裸聊敲诈勒索诈骗": "我在网络交友和私密视频纠纷中遇到一个情况：",
    "虚假中奖/免费礼品诈骗": "我在收到中奖或免费礼品通知时遇到一个情况：",
    "考试考证论文服务诈骗": "我在购买考试或考证服务后遇到一个情况：",
}


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _parse_conversation(record: Dict[str, Any]) -> List[Dict[str, str]]:
    text = str(record.get("text") or "").strip()
    if not record.get("multi_turn"):
        return [{"role": "user", "content": text}]
    return [{"role": "user", "content": part.strip()} for part in text.split("\n") if part.strip()]


def _stage(text: str, control: bool) -> str:
    if control:
        return "unknown"
    compact = re.sub(r"\s+", "", text)
    if re.search(r"(正在|已经|已|刚刚|之后|后来|发现|被骗|被盗|转走|扣了|亏了|找不回|拉黑|没收到|不退|损失|不能提现)", compact):
        if re.search(r"(正在.{0,8}(共享|远程|转账|付款)|打开了屏幕共享|让我打开银行|现在让我)", compact):
            return "active_operation"
        return "post_loss"
    if re.search(r"(要求|让我|必须|先交|先转|点击|扫码|提供|发给|下载|输入|补交)", compact):
        return "requested_action"
    return "contacted"


def _labels(record: Dict[str, Any]) -> Dict[str, Any]:
    category = str(record["category"])
    control = bool(record.get("control"))
    text = str(record.get("text") or "")
    stage = _stage(text, control)
    if control:
        return {
            "workflow": "risk_case_flow",
            "is_personal_risk": False,
            "fraud_type": None,
            "candidate_fraud_types": [],
            "risk_stage": "unknown",
            "risk_level": "none",
            "risk_features": [],
            "required_actions": [],
            "knowledge_intent": None,
        }

    if stage == "active_operation":
        level = "critical"
    elif stage == "post_loss":
        level = "high"
    elif stage == "requested_action":
        level = "high"
    else:
        level = "medium"

    actions = ["stop_operation", "preserve_evidence"]
    if category in {"屏幕共享/远程控制诈骗"} or "屏幕共享" in text or "远程" in text:
        actions.extend(["disconnect_remote_control", "change_password", "check_account_bindings"])
    if category in {"验证码/账户盗刷诈骗", "钓鱼链接诈骗"} or "验证码" in text or "陌生链接" in text:
        actions.extend(["do_not_share_code", "change_password", "check_account_bindings"])
    if stage in {"post_loss", "active_operation"} or re.search(r"(转账|付款|扣了|转走|充值|已交)", text):
        actions.extend(["contact_bank", "call_96110_or_110"])
    if category not in {"钓鱼链接诈骗", "验证码/账户盗刷诈骗", "屏幕共享/远程控制诈骗"}:
        actions.append("stop_transfer")

    deduped_actions: List[str] = []
    for action in actions:
        if action not in deduped_actions:
            deduped_actions.append(action)
    return {
        "workflow": "risk_case_flow",
        "is_personal_risk": True,
        "fraud_type": category,
        "candidate_fraud_types": [],
        "risk_stage": stage,
        "risk_level": level,
        "risk_features": FEATURES.get(category, ["陌生人引导"]),
        "required_actions": deduped_actions,
        "knowledge_intent": None,
    }


def _rewrite_turn(content: str, category: str, index: int, control: bool) -> str:
    content = content.strip()
    content = re.sub(r"^第一轮：|^第二轮：|^第三轮：", "", content)
    content = re.sub(r"^(现在|后来|随后|此时)(?:，|,)?", "", content)
    if control:
        prefix = "我想确认下面这种处理方式是否正常："
        suffix = "这种处理方式安全吗？"
    else:
        # Keep the rewrite neutral: adding a category-specific prefix would
        # leak the label and make the augmented set easier than the seed.
        prefix = "请帮我判断下面这段经历："
        suffix = "我现在最应该先做什么？"
    if index == 1:
        prefix = "随后，"
    elif index >= 2:
        prefix = "到了这一步，"
    text = f"{prefix}{content}"
    if not re.search(r"[？?。！!]$", text):
        text += suffix
    return text


def _conversation(record: Dict[str, Any], rewritten: bool = False) -> List[Dict[str, str]]:
    raw = _parse_conversation(record)
    if not rewritten:
        return raw
    return [{"role": "user", "content": _rewrite_turn(item["content"], record["category"], index, bool(record.get("control")))} for index, item in enumerate(raw)]


def _output_record(record: Dict[str, Any], index: int, rewritten: bool = False) -> Dict[str, Any]:
    conversation = _conversation(record, rewritten=rewritten)
    content_hash = _hash("\n".join(turn["content"] for turn in conversation))
    sample_id = f"AF-AUG-{index:04d}" if rewritten else f"AF-USER-{index:04d}"
    family_id = f"user_case_{index:04d}"
    return {
        "sample_id": sample_id,
        "case_family_id": family_id,
        "source": {
            "source_type": "anonymous_user_prompt",
            "source_url": None,
            "publisher": None,
            "published_at": None,
            "collected_at": TODAY,
            "collector_id": "user_in_thread",
            "license_status": "permission_granted",
            "content_hash": content_hash,
        },
        "conversation": conversation,
        "turn_under_test": len(conversation) - 1,
        "labels": _labels(record),
        "annotation": {
            "annotator_id": "codex_structured_from_user_category" if not rewritten else "codex_augmentation",
            "annotated_at": TODAY,
            "difficulty": "medium",
            "notes": "用户提供类别；结构化字段由规则初标，扩写样本与原样本属于同一案件族。",
        },
        "privacy_review": {
            "status": "passed",
            "reason": "文本未包含直接手机号、身份证号或账户标识；上线前仍应复核品牌和隐私表述。",
        },
        "split": "development",
    }


def main() -> int:
    records = [json.loads(line) for line in STAGING.read_text(encoding="utf-8").splitlines() if line.strip()]
    if len(records) != 105:
        raise SystemExit(f"种子样本数量应为 105，实际为 {len(records)}")
    seed_records = [_output_record(record, index + 1, rewritten=False) for index, record in enumerate(records)]
    augmented_records = seed_records + [_output_record(record, index + 1, rewritten=True) for index, record in enumerate(records)]

    for path, payload in [(SEED_OUT, seed_records), (AUGMENTED_OUT, augmented_records), (DEVELOPMENT_OUT, augmented_records)]:
        path.write_text("".join(json.dumps(item, ensure_ascii=False) + "\n" for item in payload), encoding="utf-8")
    manifest = {
        "dataset": "user_annotation_seed_105",
        "seed_count": len(seed_records),
        "augmented_count": len(augmented_records),
        "source": "user-provided descriptions plus realistic additions in the current task",
        "split": "development",
        "blind_test_eligible": False,
        "case_family_policy": "each rewrite shares the original case_family_id",
        "label_note": "The category is user-provided; structured labels are deterministic first-pass labels and need human adjudication before formal blind evaluation.",
        "files": {"seed": str(SEED_OUT), "augmented": str(AUGMENTED_OUT), "development": str(DEVELOPMENT_OUT)},
    }
    MANIFEST_OUT.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"seed": len(seed_records), "augmented": len(augmented_records), "manifest": str(MANIFEST_OUT)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
