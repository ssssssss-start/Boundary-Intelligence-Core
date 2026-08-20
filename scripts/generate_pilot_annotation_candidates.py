#!/usr/bin/env python3
"""Generate 100 clearly-labelled synthetic candidates for annotation calibration.

These candidates are intentionally label-free and MUST NOT be treated as an
independent blind test. They exist to calibrate the guideline and tooling.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RAW_PATH = ROOT / "evaluation" / "raw_candidates" / "pilot_100.jsonl"
ANON_PATH = ROOT / "evaluation" / "anonymized" / "pilot_100.jsonl"


KNOWLEDGE_TOPICS = [
    "刷单返利诈骗", "游戏交易诈骗", "冒充公检法诈骗", "虚假投资理财诈骗", "校园贷诈骗",
]
KNOWLEDGE_QUESTIONS = [
    "什么是{topic}？",
    "{topic}一般有哪些套路？",
    "能讲一个{topic}的典型案例吗？",
    "学生应该怎么防范{topic}？",
    "{topic}涉及哪些法律和报警注意事项？",
]

RISK_TEXTS = [
    "兼职群前两单都返了钱，现在派单员让我垫付800元做联单，靠谱吗？",
    "我已经刷了三单，平台说数据错误，还要再补2000元才能提现。",
    "对方让我连续充值完成任务，我正在支付页面，怎么办？",
    "刷单客服说最后一单做完就全部返还，我已经付过一次了。",
    "群里说点赞关注能赚钱，刚开始不要钱，现在让我交保证金。",
    "游戏群买家让我把装备先交给中间人验货，然后才付款。",
    "我卖游戏账号，对方发来一个担保平台，让我先交账户解冻费。",
    "有人低价卖游戏皮肤，但要求离开官方平台用二维码付款。",
    "游戏客服说账号交易异常，让我把密码和验证码发给他核验。",
    "买家让我开屏幕共享展示游戏仓库，还让我打开支付软件。",
    "自称公安的人说我涉嫌洗钱，让我把钱转入安全账户接受调查。",
    "对方发来通缉令，说案件保密，不能告诉家人和老师。",
    "有人冒充民警让我下载会议App并共享屏幕，我已经打开了。",
    "假警察正在电话里催我做资金清查，我现在还没转账。",
    "对方说不配合就来学校抓我，还索要身份证和银行卡信息。",
    "投资老师承诺每月稳赚，让我下载陌生App买虚拟币。",
    "理财平台开始能小额提现，现在大额提现要先交税费。",
    "网友带我投资黄金，我已经入金一万元，现在账户无法登录。",
    "直播间老师推荐内部股票群，助理一直催我向个人账户转账。",
    "投资平台显示盈利很多，但客服说交认证费后才能提现。",
    "校园贷款App说无抵押秒到账，但放款前要先交手续费。",
    "贷款客服说我银行卡号填错，需要转钱刷流水解除冻结。",
    "我申请学生贷款只到账3500，合同却写5000，还扣了服务费。",
    "对方说能修复征信，让我先付款并提供身份证和银行卡。",
    "贷款平台威胁我不交保证金就通知学校和家长。",
    "退款客服让我下载远程控制软件，我已经允许了设备权限。",
    "短信链接里让我填写银行卡和验证码，我刚把银行卡填了。",
    "有人冒充辅导员收班费，要求今天之内扫码转账。",
    "二手群卖演唱会票的人让我先付定金，再线下取票。",
    "租房中介没让我看房就催我交留房费，说晚了就没了。",
    "网上认识的人每天关心我，现在推荐我一起投资数字货币。",
    "招聘广告说出国做客服月薪五万，让我先交签证费并上交护照。",
    "亲友视频里借钱，但说话方式不太对，还要求马上转账。",
    "快递理赔客服准确说出订单信息，让我打开屏幕共享。",
    "对方索要验证码时我没有给，也已经挂断电话，还要做什么？",
    "我已经联系银行止付并报警，聊天记录也保存了，下一步呢？",
    "刚才点了陌生链接，但没有填任何信息，现在需要改密码吗？",
    "我把游戏密码告诉对方了，但还能登录，应该先做什么？",
    "钱已经转出，对方又让我删除聊天记录，我该怎么追回？",
    "我妈正在和所谓客服屏幕共享，我怎么马上帮她停下来？",
]

NEGATIVE_TEXTS = [
    "老师让我写一篇刷单诈骗的课堂作业，能提供一个知识提纲吗？",
    "新闻里说有人把验证码告诉骗子，这属于什么诈骗手法？",
    "我已经向学校官网公布的账户缴纳学费，如何确认是否到账？",
    "银行柜台工作人员核对了我的身份证，这种正常流程有哪些边界？",
    "我在游戏官方交易平台买了装备并正常到账，想了解平台外交易风险。",
    "帮我把‘不要共享屏幕’翻译成英文，用于反诈海报。",
    "学校组织观看冒充公检法反诈视频，请帮我总结三个知识点。",
    "家长给我转了生活费，我想了解普通转账需要注意什么。",
    "正规贷款合同里通常会出现哪些费用，怎么区分诈骗？",
    "警方反诈宣传让我安装国家反诈中心App，这个软件有什么作用？",
    "我没有转账，也没有下载软件，只收到一条促销短信，应该如何判断？",
    "对方没有让我交钱，只是发了投资课程，我想先了解相关骗局。",
    "课程案例里说账户不能提现，请解释这种套路，不是我本人遇到的。",
    "帮我设计一道关于游戏账号交易风险的选择题。",
    "请比较校园贷诈骗和正规助学贷款，不涉及我的个人情况。",
    "论文里要引用虚假投资案例，有哪些公开官方来源？",
    "我想给同学做一次验证码安全科普，应该讲哪些内容？",
    "请总结报警、止付和保存证据的先后顺序，作为学习笔记。",
    "反诈演练中演员让我转入安全账户，这个情节为什么危险？",
    "如果有人要求下载陌生App，一般要检查哪些权限？",
]

OTHER_TEXTS = [
    "你好。",
    "谢谢你，我明白了。",
    "你是谁，能帮我做什么？",
    "刚才语音识别错了，我说的是游戏装备。",
    "今天心情不太好。",
    "这个怎么办？",
    "有人联系我了。",
    "这是真的吗？",
    "我已经弄好了。",
    "能继续说吗？",
]

MULTITURN = [
    [
        {"role": "user", "content": "群里有人让我做点赞任务。"},
        {"role": "assistant", "content": "对方有没有要求你先垫钱或充值？"},
        {"role": "user", "content": "前两次没有，这次让我付500。"}
    ],
    [
        {"role": "user", "content": "有人自称公安，说我涉案。"},
        {"role": "assistant", "content": "对方是否要求保密、共享屏幕或转入安全账户？"},
        {"role": "user", "content": "有，我正在共享屏幕。"}
    ],
    [
        {"role": "user", "content": "我想了解虚假投资骗局。"},
        {"role": "assistant", "content": "常见信号包括稳赚承诺、陌生平台和提现受阻。"},
        {"role": "user", "content": "其实我现在就在一个平台里不能提现。"}
    ],
    [
        {"role": "user", "content": "游戏交易时把密码给了对方。"},
        {"role": "assistant", "content": "请立即修改密码并检查绑定设备。"},
        {"role": "user", "content": "密码改了，陌生设备也退出了。"}
    ],
    [
        {"role": "user", "content": "我已经把钱转给贷款客服了。"},
        {"role": "assistant", "content": "请立即联系银行止付、保存证据并报警。"},
        {"role": "user", "content": "银行联系了，证据也保存了。另一个人又让我交解冻费。"}
    ],
]


def record(index: int, conversation: list[dict[str, str]], family: str) -> dict:
    sample_id = f"AF-PILOT-{index:04d}"
    content = json.dumps(conversation, ensure_ascii=False, sort_keys=True)
    return {
        "sample_id": sample_id,
        "case_family_id": family,
        "source": {
            "source_type": "team_authored_synthetic",
            "source_url": None,
            "publisher": None,
            "published_at": None,
            "collected_at": datetime.now().astimezone().date().isoformat(),
            "collector_id": "codex_pilot_generator",
            "license_status": "internal_synthetic",
            "content_hash": hashlib.sha256(content.encode("utf-8")).hexdigest(),
        },
        "conversation": conversation,
        "turn_under_test": len(conversation) - 1,
        "split": "unassigned",
    }


def main() -> None:
    conversations: list[tuple[list[dict[str, str]], str]] = []
    for topic_index, topic in enumerate(KNOWLEDGE_TOPICS, start=1):
        for question_index, template in enumerate(KNOWLEDGE_QUESTIONS, start=1):
            conversations.append(([{"role": "user", "content": template.format(topic=topic)}], f"knowledge_{topic_index}_{question_index}"))
    conversations.extend(
        ([{"role": "user", "content": text}], f"risk_{index:02d}")
        for index, text in enumerate(RISK_TEXTS, start=1)
    )
    conversations.extend(
        ([{"role": "user", "content": text}], f"negative_{index:02d}")
        for index, text in enumerate(NEGATIVE_TEXTS, start=1)
    )
    conversations.extend(
        ([{"role": "user", "content": text}], f"other_{index:02d}")
        for index, text in enumerate(OTHER_TEXTS, start=1)
    )
    conversations.extend((turns, f"multiturn_{index:02d}") for index, turns in enumerate(MULTITURN, start=1))
    assert len(conversations) == 100, len(conversations)

    rows = [record(index, turns, family) for index, (turns, family) in enumerate(conversations, start=1)]
    raw_text = "\n".join(json.dumps(row, ensure_ascii=False) for row in rows) + "\n"
    anonymized_rows = [{**row, "privacy_review": {"status": "passed", "reason": "synthetic_no_real_personal_data"}} for row in rows]
    anon_text = "\n".join(json.dumps(row, ensure_ascii=False) for row in anonymized_rows) + "\n"
    RAW_PATH.parent.mkdir(parents=True, exist_ok=True)
    ANON_PATH.parent.mkdir(parents=True, exist_ok=True)
    RAW_PATH.write_text(raw_text, encoding="utf-8")
    ANON_PATH.write_text(anon_text, encoding="utf-8")
    annotation_dir = ROOT / "evaluation" / "annotations"
    annotation_dir.mkdir(parents=True, exist_ok=True)
    for annotator_id, filename in [("A", "annotator_a.jsonl"), ("B", "annotator_b.jsonl")]:
        metadata = {
            "record_type": "metadata",
            "dataset": "pilot_100",
            "annotator_id": annotator_id,
            "status": "not_started",
            "instructions": "独立填写labels与annotation，不得查看系统预测或另一位标注员结果",
        }
        annotation_rows = []
        for row in anonymized_rows:
            annotation_rows.append({
                "record_type": "annotation",
                "sample_id": row["sample_id"],
                "case_family_id": row["case_family_id"],
                "conversation": row["conversation"],
                "turn_under_test": row["turn_under_test"],
                "labels": {
                    "workflow": None,
                    "is_personal_risk": None,
                    "fraud_type": None,
                    "candidate_fraud_types": [],
                    "risk_stage": None,
                    "risk_level": None,
                    "risk_features": [],
                    "required_actions": [],
                    "knowledge_intent": None,
                },
                "annotation": {
                    "annotator_id": annotator_id,
                    "annotated_at": None,
                    "difficulty": None,
                    "notes": "",
                },
            })
        annotation_text = "\n".join(
            [json.dumps(metadata, ensure_ascii=False), *[json.dumps(item, ensure_ascii=False) for item in annotation_rows]]
        ) + "\n"
        (annotation_dir / filename).write_text(annotation_text, encoding="utf-8")
    split_dir = ROOT / "evaluation" / "splits"
    split_dir.mkdir(parents=True, exist_ok=True)
    for filename in ["development.jsonl", "validation.jsonl", "blind_test.jsonl"]:
        path = split_dir / filename
        if not path.exists():
            path.touch()
    print(json.dumps({"count": len(rows), "raw": str(RAW_PATH), "anonymized": str(ANON_PATH)}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
