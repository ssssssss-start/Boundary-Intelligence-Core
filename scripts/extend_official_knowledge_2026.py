"""Extend the structured anti-fraud knowledge base with official-source items."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List


ROOT = Path(__file__).resolve().parents[1]
KNOWLEDGE_DIR = ROOT / "data" / "knowledge"
NOW = "2026-06-06T14:10:00"
VERSION = "official_expansion_2026_06_06"

SRC_2025_MANUAL = "https://www.gov.cn/lianbo/bumen/202506/content_7028568.htm"
SRC_COURT_2026 = "https://www.court.gov.cn/zixun/xiangqing/490051.html"
SRC_CROSS_BORDER = "https://www.gov.cn/lianbo/bumen/202407/content_6964837.htm"
SRC_ANTI_FRAUD_LAW = "https://www.npc.gov.cn/c2/c30834/202209/t20220902_319186.html"
SRC_MARKET_HEALTH = "https://www.samr.gov.cn/xw/sj/art/2025/art_a5fe6982180c4219b263bbba42bfd77b.html"
SRC_NHSA = "https://www.nhsa.gov.cn/"


def load(name: str) -> List[Dict[str, Any]]:
    path = KNOWLEDGE_DIR / f"{name}.json"
    return json.loads(path.read_text(encoding="utf-8"))


def dump(name: str, rows: List[Dict[str, Any]]) -> None:
    path = KNOWLEDGE_DIR / f"{name}.json"
    path.write_text(json.dumps(rows, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def stamp(row: Dict[str, Any]) -> Dict[str, Any]:
    row.setdefault("created_at", NOW)
    row["updated_at"] = NOW
    row["knowledge_version"] = VERSION
    return row


def upsert(rows: List[Dict[str, Any]], id_field: str, new_rows: List[Dict[str, Any]]) -> None:
    index = {str(row.get(id_field)): i for i, row in enumerate(rows) if row.get(id_field)}
    for row in new_rows:
        stamp(row)
        key = str(row[id_field])
        if key in index:
            rows[index[key]] = row
        else:
            index[key] = len(rows)
            rows.append(row)


def add_fraud_type(
    scam_id: str,
    name: str,
    aliases: List[str],
    description: str,
    channels: List[str],
    targets: List[str],
    risk_level: str,
    stages: List[str],
    goals: List[str],
    critical: List[str],
    loss: List[str],
    one_sentence: str,
    formula: str,
    refs: List[str],
) -> Dict[str, Any]:
    return {
        "scam_id": scam_id,
        "name": name,
        "aliases": aliases,
        "description": description,
        "common_channels": channels,
        "target_users": targets,
        "default_risk_level": risk_level,
        "typical_stages": stages,
        "primary_intervention_goals": goals,
        "critical_facts": critical,
        "loss_signals": loss,
        "one_sentence_rule": one_sentence,
        "risk_formula": formula,
        "knowledge_coverage": {
            "has_teaching_path": True,
            "has_stage_prevention": True,
            "has_multiple_cases": True,
            "has_report_guide": True,
            "has_evidence_guide": True,
        },
        "source_refs": refs + [SRC_ANTI_FRAUD_LAW, "local:official_expansion_2026_06_06"],
    }


def feature(
    fid: str,
    scam_id: str,
    fraud_type: str,
    name: str,
    keywords: List[str],
    weight: int,
    stage: str,
    goal: str,
    explanation: str,
    hint: str,
    refs: List[str],
) -> Dict[str, Any]:
    return {
        "feature_id": fid,
        "scam_id": scam_id,
        "fraud_type": fraud_type,
        "feature_name": name,
        "keywords": keywords,
        "risk_weight": weight,
        "stage": stage,
        "intervention_goal": goal,
        "explanation": explanation,
        "evidence_extract_hint": hint,
        "source_refs": refs + [SRC_ANTI_FRAUD_LAW, "local:official_expansion_2026_06_06"],
    }


def rule(
    rid: str,
    fraud_type: str,
    stages: List[str],
    all_terms: List[str],
    any_terms: List[str],
    score: int,
    level: str,
    goal: str,
    explanation: str,
    refs: List[str],
) -> Dict[str, Any]:
    return {
        "rule_id": rid,
        "fraud_type": fraud_type,
        "stages": stages,
        "conditions": {"all": all_terms, "any": any_terms, "min_any": 1},
        "risk_score": score,
        "risk_level": level,
        "intervention_goal": goal,
        "explanation": explanation,
        "escalation_policy": {
            "realtime_dissuasion": True,
            "emergency_if_already_lost": score >= 90,
            "next_step": "先停止付款、转账、填码、共享屏幕或继续联系，再通过官方渠道核验并保存证据。",
        },
        "condition_schema_version": "v2",
        "semantic_condition_groups": [
            {
                "operator": "all",
                "terms": [{"term": term, "condition_type": "feature", "matched_feature_ids": []} for term in all_terms],
            },
            {
                "operator": "any",
                "terms": [{"term": term, "condition_type": "feature", "matched_feature_ids": []} for term in any_terms],
            },
        ],
        "feature_conditions": {
            "all": all_terms,
            "any": any_terms,
            "matched_feature_ids": [],
        },
        "fact_conditions": [],
        "action_conditions": [],
        "semantic_conditions": [],
        "risk_reasoning_steps": [
            "识别用户描述的诈骗类型和阶段",
            "确认是否出现资金、账号、验证码、屏幕共享、陌生App或个人信息暴露",
            "优先阻止当前最危险动作，再给止损、取证和报警建议",
        ],
        "source_refs": refs + [SRC_ANTI_FRAUD_LAW, "local:official_expansion_2026_06_06"],
    }


def advice(aid: str, fraud_type: str, stage: str, goal: str, text: str, do: List[str], dont: List[str], verify: List[str], misconceptions: List[str], refs: List[str]) -> Dict[str, Any]:
    return {
        "advice_id": aid,
        "fraud_type": fraud_type,
        "risk_stage": stage,
        "intervention_goal": goal,
        "advice": text,
        "do": do,
        "dont": dont,
        "official_verification_methods": verify,
        "common_misconceptions": misconceptions,
        "source_refs": refs + [SRC_ANTI_FRAUD_LAW, "local:official_expansion_2026_06_06"],
    }


def case(cid: str, fraud_type: str, stage: str, summary: str, pattern: str, lesson: str, use_when: List[str], refs: List[str]) -> Dict[str, Any]:
    return {
        "case_id": cid,
        "fraud_type": fraud_type,
        "risk_stage": stage,
        "summary": summary,
        "key_pattern": pattern,
        "lesson": lesson,
        "privacy_level": "official_public_desensitized",
        "use_when": use_when,
        "source_refs": refs + ["local:official_expansion_2026_06_06"],
    }


def report_guide(gid: str, fraud_type: str, input_type: str, required: List[str], template: str, evidence: List[str], next_actions: List[str], refs: List[str]) -> Dict[str, Any]:
    return {
        "guide_id": gid,
        "input_type": input_type,
        "fraud_type": fraud_type,
        "required_fields": required,
        "suggested_summary_template": template,
        "evidence_checklist": evidence,
        "next_actions": next_actions,
        "source_refs": refs + [SRC_ANTI_FRAUD_LAW, "local:official_expansion_2026_06_06"],
    }


def evidence_guide(gid: str, fraud_type: str, scenario: str, items: List[str], tips: List[str], warning: str, refs: List[str]) -> Dict[str, Any]:
    return {
        "guide_id": gid,
        "fraud_type": fraud_type,
        "scenario": scenario,
        "evidence_items": items,
        "collection_tips": tips,
        "warning": warning,
        "source_refs": refs + [SRC_ANTI_FRAUD_LAW, "local:official_expansion_2026_06_06"],
    }


def law(lid: str, topic: str, behaviors: List[str], summary: str, actions: List[str], evidence: List[str], related: List[str], refs: List[str], basis: str = "official_guidance") -> Dict[str, Any]:
    return {
        "law_id": lid,
        "topic": topic,
        "related_behaviors": behaviors,
        "plain_summary": summary,
        "actions": actions,
        "evidence_to_preserve": evidence,
        "disclaimer": "以下为一般风险处置和法律常识，不替代公安机关、司法机关、银行或专业律师意见。",
        "related_scam_types": related,
        "legal_basis_type": basis,
        "user_visible_boundary": "只输出一般处置常识，不替代公安机关、银行或专业法律意见。",
        "source_refs": refs + [SRC_ANTI_FRAUD_LAW, "local:official_expansion_2026_06_06"],
    }


def policy(pid: str, fraud_type: str, scam_id: str, aliases: List[str], rule_text: str, refs: List[str]) -> Dict[str, Any]:
    return {
        "policy_id": pid,
        "policy_type": "scam_teaching_path",
        "title": f"{fraud_type}教学路径",
        "enabled": True,
        "priority": 88,
        "fraud_type": fraud_type,
        "scam_id": scam_id,
        "aliases": aliases,
        "stage_goals": {
            "overview": f"先让用户记住：{rule_text}",
            "features": "讲清身份包装、诱导动作、资金或信息暴露、官方核验缺失等识别点。",
            "tactics": "拆解从接触引流、建立信任、制造紧迫感到付款或信息暴露的流程。",
            "case": "用官方公开脱敏案例复盘关键风险信号。",
            "prevention": "给出停止动作、官方核验、证据保存和报警/举报建议。",
            "law": "讲反电诈、个人信息、帮助犯罪和取证报案的通用法律常识。",
            "summary": "用一句话帮助用户记住该类骗局的判断规则。",
        },
        "one_sentence_rule": rule_text,
        "source_refs": refs + [SRC_ANTI_FRAUD_LAW, "local:official_expansion_2026_06_06"],
        "teaching_material_requirements": {
            "must_use": ["scam_features", "prevention_advice", "typical_cases", "law_clauses"],
            "stage_policy": "每轮只取当前阶段最相关材料，避免一次性百科输出。",
            "must_cover_in_summary": ["核心识别点", "关键手法", "防范核验", "证据和报警常识"],
        },
        "closure_policy": {
            "summary_stage_closes_workflow": True,
            "after_summary": "active_workflow=idle；用户短确认不继续触发教学。",
        },
    }


def main() -> None:
    scam_types = load("scam_types")
    scam_features = load("scam_features")
    risk_rules = load("risk_rules")
    prevention = load("prevention_advice")
    cases = load("typical_cases")
    reports = load("report_guides")
    evidence = load("evidence_guides")
    laws = load("law_clauses")
    policies = load("knowledge_dialogue_policy")

    refs_manual = [SRC_2025_MANUAL]
    refs_court = [SRC_COURT_2026]
    refs_cross = [SRC_CROSS_BORDER, SRC_COURT_2026]
    refs_health = [SRC_MARKET_HEALTH]
    refs_nhsa = [SRC_NHSA]

    new_types = [
        add_fraud_type(
            "scam_cross_border_high_salary",
            "跨境高薪招工诱骗诈骗",
            ["境外高薪", "出国高工资", "海外客服招聘", "边境招工", "包机票包签证", "电诈园区诱骗"],
            "以境外高薪、包吃住、无经验也可入职等话术诱骗出境或赴边境，后续可能被限制人身自由、强迫从事电诈或被索要赎金。",
            ["墙面小广告", "短视频私信", "微信群", "熟人介绍", "招聘网站", "境外社交软件"],
            ["求职者", "青年学生", "待业人员", "债务压力人群"],
            "极高风险",
            ["接触引流阶段", "资金转账前阶段", "身份信息暴露阶段", "已损失阶段"],
            ["stop_contact", "preserve_evidence", "call_police"],
            ["是否已联系招工方", "是否被要求交签证费/押金/路费", "是否提交身份证/护照", "是否准备出境或已到边境", "是否被要求保密或断联"],
            ["已交中介费或押金", "已提交护照身份证", "被安排到边境集合", "被要求切断家人联系", "境外后无法自由离开"],
            "墙上、群里或私信里的境外高薪轻松工作，凡是让你交钱、交证件或秘密出境，先按高危诈骗和人身风险处理。",
            "境外高薪/包签证/无需经验 + 私下联系、先交费用、提交证件、秘密出境或限制联系",
            refs_cross,
        ),
        add_fraud_type(
            "scam_elderly_health_product",
            "养老保健品诈骗",
            ["保健品诈骗", "免费讲座", "养生仪器", "专家义诊", "包治百病", "老年人养生骗局"],
            "以免费体检、健康讲座、专家义诊、赠品抽奖等方式取得老年人信任，再夸大疗效、虚构病情或诱导高价购买保健品、仪器和服务。",
            ["线下讲座", "社区活动", "电话营销", "微信群", "直播间", "上门推销"],
            ["老年人", "慢病患者", "独居老人", "关注养生人群"],
            "中高风险",
            ["接触引流阶段", "建立信任阶段", "资金转账前阶段", "已损失阶段"],
            ["stop_transfer", "verify_official", "preserve_evidence"],
            ["产品是否宣称治疗疾病", "是否有免费体检/专家身份", "是否要求现场付款或预存", "是否有正规批号和票据", "是否诱导老人隐瞒家人"],
            ["高价购买无效产品", "被诱导预存套餐", "无法退款", "销售方失联", "延误正规治疗"],
            "保健食品不是药，凡是宣称包治病、用免费体检吓你买高价产品，都要先停下来核验。",
            "免费讲座/体检/专家义诊 + 夸大疗效、恐吓病情、高价预存、催促老人隐瞒家人",
            refs_health,
        ),
        add_fraud_type(
            "scam_national_asset_project",
            "民族资产解冻/虚假国家项目诈骗",
            ["民族资产解冻", "国家项目", "扶贫款", "央企内部名额", "数字资产解冻", "缴费领补贴"],
            "冒用国家机关、央企或历史资产名义，宣称缴纳会员费、激活费或材料费后可领取巨额补贴、分红或资产解冻款。",
            ["微信群", "QQ群", "短视频", "熟人转发", "伪造红头文件", "会议软件"],
            ["中老年人", "投资理财人群", "熟人群成员", "关注补贴福利人群"],
            "高风险",
            ["接触引流阶段", "资金转账前阶段", "已损失阶段"],
            ["stop_transfer", "preserve_evidence", "call_police"],
            ["项目名称和发起主体", "是否要求交会员费/激活费", "是否有伪造公文证书", "是否承诺巨额返利", "是否要求拉人头"],
            ["已缴纳入会费", "继续要求激活费/保证金", "拉人头扩散", "项目群解散", "负责人失联"],
            "凡是打着国家项目、资产解冻、内部补贴旗号让你先交钱领大钱的，基本就是诈骗。",
            "国家/央企/历史资产包装 + 伪造文件、巨额收益承诺、先缴费、拉人头",
            refs_manual,
        ),
        add_fraud_type(
            "scam_medical_insurance_fund",
            "医保骗保/医保卡倒卖诈骗",
            ["医保骗保", "医保卡套现", "倒卖医保药品", "刷医保返钱", "医保个人账户变现"],
            "以医保卡套现、刷卡返钱、倒卖药品或冒名就医等方式诱导参保人参与骗取医保基金，可能造成个人账户损失和法律风险。",
            ["药店", "诊所", "熟人介绍", "微信群", "短视频私信"],
            ["参保人", "老年人", "慢病患者", "药品需求人群"],
            "中高风险",
            ["接触引流阶段", "身份信息暴露阶段", "已损失阶段"],
            ["stop_identity_exposure", "preserve_evidence", "verify_official"],
            ["是否提供医保卡/电子医保码", "是否冒名就医或虚假购药", "是否承诺返钱", "是否倒卖药品", "是否泄露身份证和医保信息"],
            ["医保账户被盗刷", "个人信息泄露", "参与骗保被追责", "药品倒卖风险", "后续就医受影响"],
            "医保卡和医保码不能外借、套现或刷卡返钱，参与骗保不只是被骗，还可能承担法律责任。",
            "刷医保返钱/套现/冒名就医 + 外借医保凭证、虚假购药、倒卖药品、个人信息暴露",
            refs_nhsa,
        ),
        add_fraud_type(
            "scam_virtual_currency_laundering",
            "虚拟货币洗钱跑分诈骗",
            ["虚拟币跑分", "USDT代买", "数字货币搬砖", "刷流水", "代收代付", "银行卡刷流水"],
            "以高额佣金、搬砖套利、代买虚拟币或刷流水为名，让用户提供银行卡、支付账户或参与收付款，实际可能帮助电诈资金转移。",
            ["Telegram", "微信群", "QQ群", "招聘平台", "熟人介绍", "虚拟币交易群"],
            ["兼职求职者", "学生", "负债人群", "虚拟币用户"],
            "高风险",
            ["接触引流阶段", "资金转账前阶段", "已损失阶段"],
            ["stop_transfer", "preserve_evidence", "call_police"],
            ["是否提供银行卡/支付账号", "是否代收代付", "是否购买或转出虚拟币", "是否收取佣金", "资金来源是否解释不清"],
            ["银行卡被冻结", "账户涉案", "资金被划扣", "被要求继续跑分", "涉嫌帮信或洗钱风险"],
            "凡是让你出卡、出码、代收代付或用虚拟币转移陌生资金的，高概率是在帮诈骗资金洗钱。",
            "高佣金兼职/虚拟币搬砖 + 出借账户、代收代付、购买USDT、资金来源不明",
            refs_court,
        ),
        add_fraud_type(
            "scam_live_commerce_private_trade",
            "直播带货/私域交易诈骗",
            ["直播购物诈骗", "私域下单", "低价抢购", "福利群团购", "货不对板", "私下转账购物"],
            "通过直播间、短视频或福利群用低价、限时、内部价吸引下单，再引导脱离平台私下转账，常见货不对板、拒不退款或失联。",
            ["直播间", "短视频私信", "微信群", "私域商城", "二维码收款"],
            ["网购用户", "学生", "老年消费者", "低价购物人群"],
            "中风险",
            ["接触引流阶段", "资金转账前阶段", "已损失阶段"],
            ["stop_transfer", "verify_official", "preserve_evidence"],
            ["是否脱离平台交易", "是否私下扫码付款", "是否承诺明显低价", "是否拒绝开票或售后", "是否诱导加群复购"],
            ["付款后不发货", "货不对板", "拒不退款", "商家失联", "售后转为继续收费"],
            "直播购物只走平台订单和售后，凡是让你私下转账、加群付款或跳过平台保障的，先别付。",
            "直播低价/福利群 + 私下转账、脱离平台、拒绝售后、货不对板或失联",
            [SRC_MARKET_HEALTH, SRC_2025_MANUAL],
        ),
    ]

    upsert(scam_types, "scam_id", new_types)

    feature_rows = [
        feature("FEAT_CROSS_BORDER_HIGH_PAY", "scam_cross_border_high_salary", "跨境高薪招工诱骗诈骗", "境外高薪诱导", ["出国高工资", "境外高薪", "月入过万", "包吃住", "无需经验"], 35, "接触引流阶段", "stop_contact", "用明显不合理的境外高薪吸引求职者脱离常规招聘渠道。", "提取薪资承诺、国家地区和招聘渠道。", refs_cross),
        feature("FEAT_CROSS_BORDER_PRIVATE_CONTACT", "scam_cross_border_high_salary", "跨境高薪招工诱骗诈骗", "私下跨境联系", ["加密聊天", "私聊", "不要告诉家人", "熟人介绍", "境外号码"], 30, "接触引流阶段", "stop_contact", "要求私下联系和保密会削弱外部核验，是出境诱骗高危信号。", "提取联系软件、保密要求和介绍人身份。", refs_cross),
        feature("FEAT_CROSS_BORDER_UPFRONT_FEE", "scam_cross_border_high_salary", "跨境高薪招工诱骗诈骗", "出境前收费", ["签证费", "路费", "保证金", "报名费", "中介费"], 35, "资金转账前阶段", "stop_transfer", "以签证、路费、岗位保证等名义先收费，常用于持续控制或诈骗。", "提取费用名目和金额。", refs_cross),
        feature("FEAT_CROSS_BORDER_ID_DOCS", "scam_cross_border_high_salary", "跨境高薪招工诱骗诈骗", "索要证件材料", ["身份证", "护照", "银行卡", "人脸识别", "证件照"], 30, "身份信息暴露阶段", "stop_identity_exposure", "提前收集身份证、护照和银行卡可能导致身份冒用和控制风险。", "提取对方索要的证件和提交方式。", refs_cross),
        feature("FEAT_CROSS_BORDER_ASSEMBLY", "scam_cross_border_high_salary", "跨境高薪招工诱骗诈骗", "边境集合出境", ["边境集合", "偷渡", "过关", "接应", "护送"], 45, "已损失阶段", "call_police", "安排秘密集合或非正规出境可能伴随人身安全和强迫犯罪风险。", "提取集合地点、出行安排和同行人员。", refs_cross),
        feature("FEAT_HEALTH_FREE_LECTURE", "scam_elderly_health_product", "养老保健品诈骗", "免费讲座义诊", ["免费讲座", "免费体检", "专家义诊", "健康讲座", "送鸡蛋"], 25, "接触引流阶段", "verify_official", "用免费活动和赠品吸引老年人到场，是保健品诈骗常见入口。", "提取活动地点、主办方和赠品。", refs_health),
        feature("FEAT_HEALTH_CURE_CLAIM", "scam_elderly_health_product", "养老保健品诈骗", "夸大治疗功效", ["包治百病", "治癌", "降糖降压", "替代药物", "根治"], 35, "建立信任阶段", "verify_official", "保健食品不得替代药品，宣称治疗疾病是明显风险信号。", "提取疗效承诺和疾病名称。", refs_health),
        feature("FEAT_HEALTH_FAKE_EXPERT", "scam_elderly_health_product", "养老保健品诈骗", "假专家背书", ["院士", "名医", "专家推荐", "内部产品", "科研成果"], 30, "建立信任阶段", "verify_official", "冒用专家、医院或科研名义增强可信度。", "提取专家姓名、机构和证书。", refs_health),
        feature("FEAT_HEALTH_HIGH_PRICE_PREPAY", "scam_elderly_health_product", "养老保健品诈骗", "高价预存套餐", ["预存", "套餐", "买十送十", "限时优惠", "会员价"], 35, "资金转账前阶段", "stop_transfer", "现场高价预存和限时优惠会让老年人难以冷静核验。", "提取付款金额、套餐周期和收款方。", refs_health),
        feature("FEAT_HEALTH_HIDE_FAMILY", "scam_elderly_health_product", "养老保健品诈骗", "诱导隐瞒家人", ["别告诉孩子", "家人不懂", "偷偷买", "名额有限", "今天必须定"], 30, "资金转账前阶段", "stop_transfer", "要求隐瞒家人是阻断外部劝阻的典型话术。", "提取保密话术和催促方式。", refs_health),
        feature("FEAT_NATIONAL_PROJECT_NAME", "scam_national_asset_project", "民族资产解冻/虚假国家项目诈骗", "国家项目包装", ["国家项目", "央企项目", "扶贫款", "共同富裕", "内部名额"], 35, "接触引流阶段", "stop_transfer", "冒用国家机关或央企名义包装项目，增强可信度。", "提取项目名称和发起主体。", refs_manual),
        feature("FEAT_NATIONAL_FAKE_DOC", "scam_national_asset_project", "民族资产解冻/虚假国家项目诈骗", "伪造红头文件", ["红头文件", "授权书", "证书", "公章", "批文"], 30, "建立信任阶段", "verify_official", "伪造公文、证书和印章是此类诈骗常见工具。", "提取文件名称、落款和编号。", refs_manual),
        feature("FEAT_NATIONAL_UPFRONT_FEE", "scam_national_asset_project", "民族资产解冻/虚假国家项目诈骗", "缴费领取补贴", ["会员费", "激活费", "材料费", "解冻费", "手续费"], 40, "资金转账前阶段", "stop_transfer", "让用户先缴小额费用领取大额资金，是核心高危信号。", "提取费用名目、金额和收款账户。", refs_manual),
        feature("FEAT_NATIONAL_HUGE_RETURN", "scam_national_asset_project", "民族资产解冻/虚假国家项目诈骗", "巨额分红承诺", ["领几十万", "分红", "资产解冻", "返利", "补贴到账"], 35, "接触引流阶段", "stop_transfer", "承诺不合理巨额收益或补贴，常用于诱导缴费和拉人。", "提取收益金额和到账条件。", refs_manual),
        feature("FEAT_NATIONAL_RECRUIT_DOWNLINE", "scam_national_asset_project", "民族资产解冻/虚假国家项目诈骗", "拉人头扩散", ["发展会员", "拉人", "团队", "下线", "推广奖励"], 30, "建立信任阶段", "preserve_evidence", "拉人头会扩大受害范围，也可能引发传销式扩散风险。", "提取拉人要求和奖励规则。", refs_manual),
        feature("FEAT_MEDICARE_CARD_LENDING", "scam_medical_insurance_fund", "医保骗保/医保卡倒卖诈骗", "外借医保凭证", ["医保卡借我", "电子医保码", "刷码", "代刷", "冒名就医"], 35, "身份信息暴露阶段", "stop_identity_exposure", "外借医保卡或医保码可能导致盗刷、骗保和个人责任风险。", "提取外借对象和使用场景。", refs_nhsa),
        feature("FEAT_MEDICARE_CASHBACK", "scam_medical_insurance_fund", "医保骗保/医保卡倒卖诈骗", "刷医保返钱", ["刷医保返钱", "套现", "返现", "药店返钱", "现金回收"], 35, "资金转账前阶段", "stop_transfer", "医保个人账户不能用于违规套现，返钱诱导常伴随骗保。", "提取返钱比例和药店/诊所信息。", refs_nhsa),
        feature("FEAT_MEDICARE_DRUG_RESALE", "scam_medical_insurance_fund", "医保骗保/医保卡倒卖诈骗", "倒卖医保药品", ["收药", "卖药", "回收药品", "慢病药", "医保药倒卖"], 35, "已损失阶段", "preserve_evidence", "倒卖医保药品可能损害医保基金和个人用药安全。", "提取药品名称、数量和收购方。", refs_nhsa),
        feature("FEAT_MEDICARE_FAKE_TREATMENT", "scam_medical_insurance_fund", "医保骗保/医保卡倒卖诈骗", "虚假诊疗购药", ["虚假住院", "虚假检查", "挂床", "假病历", "空刷"], 40, "已损失阶段", "call_police", "虚假诊疗或购药是骗取医保基金的典型行为。", "提取医疗机构、诊疗项目和票据。", refs_nhsa),
        feature("FEAT_MEDICARE_IDENTITY_LEAK", "scam_medical_insurance_fund", "医保骗保/医保卡倒卖诈骗", "医保身份信息泄露", ["身份证", "社保卡", "医保账号", "人脸认证", "短信验证码"], 30, "身份信息暴露阶段", "stop_identity_exposure", "医保身份信息泄露可能被冒用就医、购药或盗刷。", "提取泄露信息类型和对方身份。", refs_nhsa),
        feature("FEAT_VC_HIGH_COMMISSION", "scam_virtual_currency_laundering", "虚拟货币洗钱跑分诈骗", "高佣金跑分", ["高佣金", "跑分", "刷流水", "日结", "躺赚"], 35, "接触引流阶段", "stop_transfer", "用高佣金吸引用户提供账户或参与转账。", "提取佣金比例和任务要求。", refs_court),
        feature("FEAT_VC_ACCOUNT_LENDING", "scam_virtual_currency_laundering", "虚拟货币洗钱跑分诈骗", "出借账户收付款", ["银行卡", "支付宝", "微信收款", "收款码", "代收"], 40, "资金转账前阶段", "stop_transfer", "出借账户或收款码可能帮助电诈资金转移。", "提取账户类型和收付款金额。", refs_court),
        feature("FEAT_VC_USDT_TRANSFER", "scam_virtual_currency_laundering", "虚拟货币洗钱跑分诈骗", "虚拟币转移资金", ["USDT", "虚拟币", "数字货币", "钱包地址", "链上转账"], 40, "资金转账前阶段", "stop_transfer", "用虚拟货币转换资金可增加追赃难度，是洗钱跑分常见方式。", "提取币种、钱包地址和交易平台。", refs_court),
        feature("FEAT_VC_SOURCE_UNKNOWN", "scam_virtual_currency_laundering", "虚拟货币洗钱跑分诈骗", "资金来源不明", ["不用问来源", "帮忙过账", "临时周转", "刷流水", "客户款"], 35, "资金转账前阶段", "stop_transfer", "资金来源解释不清时继续代收代付风险极高。", "提取对方对资金来源的解释。", refs_court),
        feature("FEAT_VC_ACCOUNT_FROZEN", "scam_virtual_currency_laundering", "虚拟货币洗钱跑分诈骗", "账户被冻结", ["银行卡冻结", "支付宝冻结", "司法冻结", "止付", "涉案账户"], 45, "已损失阶段", "call_police", "账户被冻结往往说明资金链条已被风控或司法机关关注。", "提取冻结平台、通知内容和涉案金额。", refs_court),
        feature("FEAT_LIVE_LOW_PRICE", "scam_live_commerce_private_trade", "直播带货/私域交易诈骗", "明显低价诱导", ["低价抢购", "清仓", "内部价", "福利价", "限时秒杀"], 25, "接触引流阶段", "verify_official", "明显低价和限时诱导会促使用户跳过核验。", "提取商品、价格差异和直播间名称。", [SRC_MARKET_HEALTH, SRC_2025_MANUAL]),
        feature("FEAT_LIVE_PRIVATE_PAY", "scam_live_commerce_private_trade", "直播带货/私域交易诈骗", "私下扫码付款", ["扫码付款", "微信转账", "支付宝转账", "私下付款", "不走平台"], 40, "资金转账前阶段", "stop_transfer", "脱离平台付款会失去订单、售后和支付保障。", "提取收款码、账户和付款理由。", [SRC_MARKET_HEALTH, SRC_2025_MANUAL]),
        feature("FEAT_LIVE_OFF_PLATFORM_GROUP", "scam_live_commerce_private_trade", "直播带货/私域交易诈骗", "引导私域下单", ["加群", "加客服微信", "私域商城", "小程序下单", "群接龙"], 30, "接触引流阶段", "verify_official", "从平台直播间引流到私域交易，会降低平台监管和售后保障。", "提取群名、客服账号和下单入口。", [SRC_MARKET_HEALTH, SRC_2025_MANUAL]),
        feature("FEAT_LIVE_NO_AFTERSALE", "scam_live_commerce_private_trade", "直播带货/私域交易诈骗", "拒绝售后退款", ["不退不换", "售后拖延", "客服失联", "退款失败", "补邮费"], 35, "已损失阶段", "preserve_evidence", "拒绝售后或拖延退款常见于货不对板和私域交易诈骗。", "提取售后沟通和退款记录。", [SRC_MARKET_HEALTH, SRC_2025_MANUAL]),
        feature("FEAT_LIVE_FAKE_AUTH", "scam_live_commerce_private_trade", "直播带货/私域交易诈骗", "虚假授权背书", ["官方授权", "专柜同款", "品牌尾货", "正品保证", "假一赔十"], 30, "建立信任阶段", "verify_official", "虚假授权和正品背书用于掩盖私下交易风险。", "提取授权证明和品牌信息。", [SRC_MARKET_HEALTH, SRC_2025_MANUAL]),
    ]
    upsert(scam_features, "feature_id", feature_rows)

    new_rules = [
        rule("RULE_CROSS_BORDER_HIGH_SALARY_001", "跨境高薪招工诱骗诈骗", ["接触引流阶段", "资金转账前阶段"], ["境外高薪诱导"], ["私下跨境联系", "出境前收费", "索要证件材料", "边境集合出境"], 94, "极高风险", "stop_contact", "境外高薪叠加私下联系、收费、证件或出境安排，触发人身和诈骗双重风险。", refs_cross),
        rule("RULE_HEALTH_PRODUCT_ELDERLY_001", "养老保健品诈骗", ["建立信任阶段", "资金转账前阶段"], ["夸大治疗功效"], ["免费讲座义诊", "假专家背书", "高价预存套餐", "诱导隐瞒家人"], 82, "中高风险", "stop_transfer", "保健品宣称治疗疾病并催促高价购买，属于老年消费诈骗高危模式。", refs_health),
        rule("RULE_NATIONAL_ASSET_PROJECT_001", "民族资产解冻/虚假国家项目诈骗", ["接触引流阶段", "资金转账前阶段"], ["国家项目包装"], ["伪造红头文件", "缴费领取补贴", "巨额分红承诺", "拉人头扩散"], 90, "高风险", "stop_transfer", "国家项目包装叠加先缴费领巨额收益，符合民族资产解冻类诈骗特征。", refs_manual),
        rule("RULE_MEDICARE_FUND_FRAUD_001", "医保骗保/医保卡倒卖诈骗", ["身份信息暴露阶段", "已损失阶段"], ["外借医保凭证"], ["刷医保返钱", "倒卖医保药品", "虚假诊疗购药", "医保身份信息泄露"], 86, "中高风险", "stop_identity_exposure", "外借医保凭证并参与返钱、倒卖或虚假诊疗，既有被骗风险也有法律责任风险。", refs_nhsa),
        rule("RULE_VIRTUAL_CURRENCY_LAUNDERING_001", "虚拟货币洗钱跑分诈骗", ["资金转账前阶段", "已损失阶段"], ["高佣金跑分"], ["出借账户收付款", "虚拟币转移资金", "资金来源不明", "账户被冻结"], 96, "高风险", "stop_transfer", "高佣金跑分叠加账户出借或虚拟币转移，可能帮助电诈资金转移。", refs_court),
        rule("RULE_LIVE_PRIVATE_TRADE_001", "直播带货/私域交易诈骗", ["接触引流阶段", "资金转账前阶段"], ["私下扫码付款"], ["明显低价诱导", "引导私域下单", "拒绝售后退款", "虚假授权背书"], 78, "中风险", "stop_transfer", "直播购物脱离平台私下付款，会显著增加货不对板、拒不退款和失联风险。", [SRC_MARKET_HEALTH, SRC_2025_MANUAL]),
    ]
    upsert(risk_rules, "rule_id", new_rules)

    new_advice = [
        advice("PREVENT_CROSS_BORDER_001", "跨境高薪招工诱骗诈骗", "接触引流阶段", "stop_contact", "遇到境外高薪、包签证、无需经验的招工信息，先不要联系和提交证件，必须通过正规劳务、企业官网和人社渠道核验。", ["不打广告电话，不加私聊账号", "向家人、老师、人社部门或派出所核实", "保存广告照片、号码和聊天记录"], ["不要交签证费/押金/路费", "不要交身份证、护照或银行卡", "不要按对方要求秘密出境"], ["当地人社部门", "学校就业中心", "公安机关", "企业官网"], ["工资越高越可靠", "熟人介绍就安全", "先交证件方便办手续"], refs_cross),
        advice("PREVENT_HEALTH_PRODUCT_001", "养老保健品诈骗", "资金转账前阶段", "stop_transfer", "保健食品不能替代药品，遇到免费讲座、专家义诊后要求高价购买或预存套餐，应先让家人陪同核验。", ["查产品批准文号和经营主体", "保留宣传单、收据和付款记录", "必要时向市场监管或消协咨询"], ["不要相信包治百病", "不要现场冲动付款", "不要瞒着家人购买大额套餐"], ["市场监管部门", "消费者协会", "正规医院", "药监公开查询渠道"], ["专家说了就一定有效", "免费体检结果能证明必须购买", "今天不买就错过治疗"], refs_health),
        advice("PREVENT_NATIONAL_PROJECT_001", "民族资产解冻/虚假国家项目诈骗", "资金转账前阶段", "stop_transfer", "国家补贴、资产解冻和央企项目不会通过微信群收会员费或激活费发放巨额资金。", ["核验发文机关官网", "保存群公告、收款码和伪造文件", "向公安机关或社区反诈人员咨询"], ["不要交会员费/激活费", "不要拉亲友入群", "不要传播伪造文件"], ["政府官网", "12345政务服务", "公安机关"], ["有红头文件就是真的", "先交小钱能领大钱", "群里很多人报名说明可靠"], refs_manual),
        advice("PREVENT_MEDICARE_001", "医保骗保/医保卡倒卖诈骗", "身份信息暴露阶段", "stop_identity_exposure", "医保卡、电子医保码和医保身份信息只能本人合规就医购药使用，不能外借、套现或倒卖药品。", ["立即停止外借医保凭证", "检查医保消费记录", "向医保部门或定点机构核实异常记录"], ["不要刷医保返钱", "不要出借医保码", "不要参与倒卖医保药品"], ["国家医保服务平台", "当地医保局", "定点医疗机构"], ["医保个人账户余额是自己的想怎么用都行", "刷卡返钱只是薅福利", "熟人借用不会有风险"], refs_nhsa),
        advice("PREVENT_VIRTUAL_CURRENCY_001", "虚拟货币洗钱跑分诈骗", "资金转账前阶段", "stop_transfer", "不要为了高佣金出借银行卡、收款码或虚拟币钱包，代收代付陌生资金可能卷入电诈洗钱。", ["停止收付款和虚拟币转账", "保存任务群、钱包地址和资金流水", "如账户被冻结，联系银行并配合公安核查"], ["不要出借账户", "不要购买或转出来源不明的USDT", "不要删除聊天记录"], ["银行官方客服", "公安机关", "支付平台官方客服"], ["只是刷流水不违法", "虚拟币查不到就安全", "拿佣金说明只是兼职"], refs_court),
        advice("PREVENT_LIVE_PRIVATE_TRADE_001", "直播带货/私域交易诈骗", "资金转账前阶段", "stop_transfer", "直播购物要留在平台订单和售后体系内，任何让你加群私下扫码付款的交易都先暂停。", ["通过平台店铺下单", "核验商家资质和售后规则", "保存直播回放、商品页和聊天记录"], ["不要私下转账", "不要跳过平台担保", "不要相信明显低价和限时催付"], ["电商平台官方客服", "市场监管部门", "消费者协会"], ["主播承诺正品就一定真", "群里付款更便宜更安全", "私下付款也能平台售后"], [SRC_MARKET_HEALTH, SRC_2025_MANUAL]),
    ]
    extra_advice_specs = [
        ("CROSS_BORDER", "跨境高薪招工诱骗诈骗", "身份信息暴露阶段", "stop_identity_exposure", "不要把身份证、护照、银行卡、人脸识别或家庭住址发给境外招工方。", refs_cross),
        ("CROSS_BORDER_TRAVEL", "跨境高薪招工诱骗诈骗", "已损失阶段", "call_police", "如果已经准备赴边境或出境，先停下并把位置、联系人和行程告诉家人或公安机关。", refs_cross),
        ("HEALTH_VERIFY", "养老保健品诈骗", "建立信任阶段", "verify_official", "所谓专家义诊、免费体检和疗效承诺要用医院、药监和市场监管公开渠道核验。", refs_health),
        ("HEALTH_AFTER_LOSS", "养老保健品诈骗", "已损失阶段", "preserve_evidence", "已经购买高价保健品时，保留包装、票据、宣传材料和聊天记录，优先走消协或市场监管投诉。", refs_health),
        ("NATIONAL_VERIFY", "民族资产解冻/虚假国家项目诈骗", "建立信任阶段", "verify_official", "看到红头文件、央企授权或内部名额时，不转发、不缴费，先到政府或企业官网核验。", refs_manual),
        ("NATIONAL_GROUP", "民族资产解冻/虚假国家项目诈骗", "已损失阶段", "preserve_evidence", "已入群或已缴费时，保存群公告、管理员账号、收款码和拉人规则，不再发展下线。", refs_manual),
        ("MEDICARE_VERIFY", "医保骗保/医保卡倒卖诈骗", "建立信任阶段", "verify_official", "发现医保消费异常或被要求刷码返钱时，通过国家医保服务平台或当地医保部门核验。", refs_nhsa),
        ("MEDICARE_AFTER", "医保骗保/医保卡倒卖诈骗", "已损失阶段", "preserve_evidence", "医保码已被他人使用后，尽快查询消费记录，保存对方账号和返钱记录并向医保部门反映。", refs_nhsa),
        ("VC_ACCOUNT", "虚拟货币洗钱跑分诈骗", "接触引流阶段", "stop_transfer", "任何让你提供银行卡、收款码或钱包地址帮忙过账的兼职，都先按涉诈资金转移处理。", refs_court),
        ("VC_FROZEN", "虚拟货币洗钱跑分诈骗", "已损失阶段", "call_police", "账户已被冻结时，不要找所谓解冻中介，直接联系银行、支付平台并配合公安核查。", refs_court),
        ("LIVE_VERIFY", "直播带货/私域交易诈骗", "建立信任阶段", "verify_official", "看到官方授权、专柜同款或低价尾货时，只信平台店铺资质和订单页面，不信私聊截图。", [SRC_MARKET_HEALTH, SRC_2025_MANUAL]),
        ("LIVE_AFTER", "直播带货/私域交易诈骗", "已损失阶段", "preserve_evidence", "已私下付款或收到货不对板商品时，保存直播截图、付款凭证、物流和售后聊天。", [SRC_MARKET_HEALTH, SRC_2025_MANUAL]),
    ]
    new_advice.extend(
        advice(
            f"PREVENT_{suffix}_2026",
            fraud_type,
            stage,
            goal,
            text,
            ["停止当前高危操作", "通过官方渠道核验", "保存聊天、付款和页面截图"],
            ["不要继续付款", "不要删除证据", "不要按对方要求保密"],
            ["官方App/官网", "公安机关或主管部门", "家人或可信第三方"],
            ["对方说得专业就是真的", "先交一点钱风险不大", "熟人或群友推荐就可靠"],
            refs,
        )
        for suffix, fraud_type, stage, goal, text, refs in extra_advice_specs
    )
    upsert(prevention, "advice_id", new_advice)

    new_cases = [
        case("CASE_CROSS_BORDER_2026_001", "跨境高薪招工诱骗诈骗", "接触引流阶段", "用户看到境外高薪客服招聘，对方要求私聊、提交证件并先交路费，随后安排到边境集合。", "境外高薪 + 私下联系 + 交证件交费用 + 边境集合。", "正规出国务工必须通过合法劳务和官方渠道核验，不能按陌生招工方秘密出境。", ["境外高薪诱导", "出境前收费", "边境集合出境"], refs_cross),
        case("CASE_HEALTH_PRODUCT_2026_001", "养老保健品诈骗", "资金转账前阶段", "老年人参加免费健康讲座，被所谓专家用体检结果吓唬后购买高价保健品套餐。", "免费讲座义诊 + 夸大疾病 + 高价预存。", "保健食品不能替代药品，购买前要让家人陪同并核验批准信息。", ["免费讲座义诊", "夸大治疗功效", "高价预存套餐"], refs_health),
        case("CASE_NATIONAL_PROJECT_2026_001", "民族资产解冻/虚假国家项目诈骗", "资金转账前阶段", "用户在微信群看到所谓国家资产解冻项目，群内发布伪造文件并要求缴纳激活费领取补贴。", "国家项目包装 + 伪造文件 + 先缴费领大额补贴。", "任何国家补贴都不会通过微信群收取激活费或会员费。", ["国家项目包装", "伪造红头文件", "缴费领取补贴"], refs_manual),
        case("CASE_MEDICARE_2026_001", "医保骗保/医保卡倒卖诈骗", "身份信息暴露阶段", "参保人被熟人劝说把医保码借给药店刷药返钱，后续发现医保消费记录异常。", "医保码外借 + 刷卡返钱 + 异常消费。", "医保凭证不能外借或套现，异常记录要及时向医保部门核实。", ["外借医保凭证", "刷医保返钱", "医保身份信息泄露"], refs_nhsa),
        case("CASE_VIRTUAL_CURRENCY_2026_001", "虚拟货币洗钱跑分诈骗", "已损失阶段", "用户参加高佣金跑分任务，使用银行卡收款后购买虚拟币转出，银行卡随后被冻结。", "高佣金跑分 + 代收代付 + USDT转移 + 账户冻结。", "陌生资金不能代收代付，虚拟币转账也可能成为电诈资金转移环节。", ["高佣金跑分", "虚拟币转移资金", "账户被冻结"], refs_court),
        case("CASE_LIVE_PRIVATE_TRADE_2026_001", "直播带货/私域交易诈骗", "已损失阶段", "用户在直播间被引导加客服微信私下付款购买低价商品，收货后货不对板且客服失联。", "直播低价 + 私域付款 + 货不对板 + 售后失联。", "脱离平台私下付款会失去订单和售后保障。", ["明显低价诱导", "私下扫码付款", "拒绝售后退款"], [SRC_MARKET_HEALTH, SRC_2025_MANUAL]),
    ]
    extra_case_specs = [
        ("CASE_CROSS_BORDER_2026_002", "跨境高薪招工诱骗诈骗", "身份信息暴露阶段", "用户在短视频私信看到海外客服招聘，对方要求先提交身份证和护照照片用于“办工签”。", "海外客服招聘 + 索要证件 + 私信沟通。", "办签证和劳务手续必须走合法机构，证件不能发给陌生招工方。", ["索要证件材料", "私下跨境联系"], refs_cross),
        ("CASE_CROSS_BORDER_2026_003", "跨境高薪招工诱骗诈骗", "资金转账前阶段", "用户被熟人介绍去境外工作，对方称可安排接应但要先交保证金和路费。", "熟人介绍 + 境外接应 + 先交费用。", "熟人转介绍也要核验企业和劳务资质，先收费安排出境风险很高。", ["出境前收费", "边境集合出境"], refs_cross),
        ("CASE_HEALTH_PRODUCT_2026_002", "养老保健品诈骗", "建立信任阶段", "销售人员冒充专家称检测指标异常，推荐购买能替代药物的养生仪器。", "假专家 + 恐吓病情 + 替代药物。", "医疗判断要去正规医院，不能让销售讲座替代诊疗。", ["假专家背书", "夸大治疗功效"], refs_health),
        ("CASE_HEALTH_PRODUCT_2026_003", "养老保健品诈骗", "已损失阶段", "老人被要求预存年度调理套餐并不要告诉子女，后来商家关门无法退款。", "高价预存 + 隐瞒家人 + 商家失联。", "大额消费要让家人陪同并索取正规票据。", ["高价预存套餐", "诱导隐瞒家人"], refs_health),
        ("CASE_NATIONAL_PROJECT_2026_002", "民族资产解冻/虚假国家项目诈骗", "建立信任阶段", "群管理员发布伪造央企授权书，称报名越早分红越高，并要求成员继续拉人。", "伪造授权 + 巨额分红 + 拉人头。", "国家和央企项目不会靠群聊拉人缴费发放分红。", ["伪造红头文件", "拉人头扩散"], refs_manual),
        ("CASE_NATIONAL_PROJECT_2026_003", "民族资产解冻/虚假国家项目诈骗", "已损失阶段", "用户多次缴纳会员费、激活费后，群内又要求缴税才能领取资产解冻款。", "多次缴费 + 资产解冻 + 税费加码。", "为领取不存在的大额资金继续缴费只会扩大损失。", ["缴费领取补贴", "巨额分红承诺"], refs_manual),
        ("CASE_MEDICARE_2026_002", "医保骗保/医保卡倒卖诈骗", "已损失阶段", "用户将慢病药品按他人要求多开后转卖，医保记录出现异常。", "虚假购药 + 药品回收 + 医保异常。", "医保购药必须真实自用，倒卖药品可能造成医保和法律风险。", ["倒卖医保药品", "虚假诊疗购药"], refs_nhsa),
        ("CASE_MEDICARE_2026_003", "医保骗保/医保卡倒卖诈骗", "身份信息暴露阶段", "有人承诺刷电子医保码可返钱，要求用户提供医保码和身份证信息。", "医保码 + 身份信息 + 返钱诱导。", "医保码等同本人医保凭证，不能交给他人使用。", ["医保身份信息泄露", "刷医保返钱"], refs_nhsa),
        ("CASE_VIRTUAL_CURRENCY_2026_002", "虚拟货币洗钱跑分诈骗", "资金转账前阶段", "用户被拉入兼职群，按指令用自己的银行卡收款并转到指定虚拟币钱包。", "兼职群 + 银行卡收款 + 虚拟币钱包。", "代收陌生资金再转虚拟币可能成为电诈资金链条。", ["出借账户收付款", "虚拟币转移资金"], refs_court),
        ("CASE_VIRTUAL_CURRENCY_2026_003", "虚拟货币洗钱跑分诈骗", "已损失阶段", "用户收到佣金后账户被司法冻结，对方又让其找中介付费解冻。", "高佣金 + 司法冻结 + 解冻中介。", "账户冻结要找银行和公安核实，不要相信付费解冻。", ["账户被冻结", "资金来源不明"], refs_court),
        ("CASE_LIVE_PRIVATE_TRADE_2026_002", "直播带货/私域交易诈骗", "资金转账前阶段", "主播称平台库存不足，要求用户加微信扫码支付才能保留低价名额。", "直播限时 + 私域加微信 + 扫码付款。", "平台外付款会失去订单保障，不要为低价跳出平台。", ["引导私域下单", "私下扫码付款"], [SRC_MARKET_HEALTH, SRC_2025_MANUAL]),
        ("CASE_LIVE_PRIVATE_TRADE_2026_003", "直播带货/私域交易诈骗", "已损失阶段", "用户在福利群购买所谓品牌尾货，付款后收到劣质商品，商家拒绝退款。", "福利群 + 品牌尾货 + 货不对板。", "明显低价和私域付款常伴随货不对板和售后失联。", ["明显低价诱导", "虚假授权背书"], [SRC_MARKET_HEALTH, SRC_2025_MANUAL]),
    ]
    new_cases.extend(
        case(cid, fraud_type, stage, summary, pattern, lesson, use_when, refs)
        for cid, fraud_type, stage, summary, pattern, lesson, use_when, refs in extra_case_specs
    )
    upsert(cases, "case_id", new_cases)

    new_reports = [
        report_guide("REPORT_CROSS_BORDER_RECRUIT_001", "跨境高薪招工诱骗诈骗", "recruitment_ad", ["广告照片或截图", "联系方式", "聊天记录", "收费要求", "集合/出境安排"], "用户看到境外高薪招工信息 {content}，对方要求私聊、交费或提交证件，疑似跨境高薪招工诱骗。", ["墙面广告/网页截图", "电话微信QQ账号", "转账或收费截图", "证件提交记录", "出境集合信息"], ["停止联系并告知家人", "不要提交证件或出境", "向公安机关或人社部门核实"], refs_cross),
        report_guide("REPORT_HEALTH_PRODUCT_001", "养老保健品诈骗", "offline_sale", ["商家名称", "活动地点", "产品名称", "付款凭证", "宣传材料"], "用户参加健康讲座或义诊后被诱导购买 {product}，宣传疑似夸大疗效或高价预存。", ["宣传单和讲座照片", "产品包装和批准文号", "收据发票", "付款记录", "销售人员联系方式"], ["停止继续付款", "联系家人陪同处理", "向市场监管或消协投诉"], refs_health),
        report_guide("REPORT_NATIONAL_PROJECT_001", "民族资产解冻/虚假国家项目诈骗", "group_message", ["群名称", "项目名称", "伪造文件", "收款账号", "拉人要求"], "用户在群内看到所谓国家项目/资产解冻信息，要求缴费领取补贴，疑似民族资产解冻诈骗。", ["群公告", "伪造红头文件", "收款码", "管理员账号", "拉人返利规则"], ["停止缴费", "提醒亲友不要扩散", "向公安机关举报"], refs_manual),
        report_guide("REPORT_MEDICARE_FUND_001", "医保骗保/医保卡倒卖诈骗", "medical_insurance", ["医保消费记录", "使用人信息", "药店/诊所名称", "返钱或倒卖话术"], "用户被诱导外借医保凭证、刷医保返钱或倒卖药品，疑似医保骗保/医保卡倒卖风险。", ["医保消费明细", "聊天记录", "药品票据", "返钱记录", "对方账号"], ["停止外借医保凭证", "通过医保平台核查记录", "向医保部门反映"], refs_nhsa),
        report_guide("REPORT_VIRTUAL_CURRENCY_LAUNDERING_001", "虚拟货币洗钱跑分诈骗", "fund_flow", ["任务群记录", "银行卡/支付账户", "虚拟币钱包地址", "资金流水", "佣金说明"], "用户被诱导参与高佣金跑分或虚拟币代收代付，疑似帮助电诈资金转移。", ["收付款流水", "钱包地址", "交易哈希", "任务群聊天", "佣金记录"], ["停止交易", "联系银行或支付平台", "保留证据并配合公安核查"], refs_court),
        report_guide("REPORT_LIVE_PRIVATE_TRADE_001", "直播带货/私域交易诈骗", "online_order", ["直播间/主播账号", "商品链接", "私下收款码", "聊天记录", "售后记录"], "用户在直播或福利群被引导私下付款购物，出现货不对板、拒不退款或失联，疑似直播带货/私域交易诈骗。", ["直播间截图", "商品宣传", "私下付款凭证", "物流和收货照片", "售后沟通记录"], ["保留证据", "联系平台官方客服", "向市场监管或消协投诉"], [SRC_MARKET_HEALTH, SRC_2025_MANUAL]),
    ]
    upsert(reports, "guide_id", new_reports)

    new_evidence = [
        evidence_guide("EVIDENCE_CROSS_BORDER_RECRUIT_001", "跨境高薪招工诱骗诈骗", "接触引流阶段", ["广告照片", "电话/微信/QQ", "聊天记录", "收费要求", "证件提交记录", "集合或出境安排"], ["拍清广告位置和联系方式", "保存对方让你保密、交钱、提交证件的原话", "记录介绍人和集合地点"], "先停止联系和出行，不要为了取证继续交钱或靠近边境集合点。", refs_cross),
        evidence_guide("EVIDENCE_HEALTH_PRODUCT_001", "养老保健品诈骗", "资金转账前阶段", ["宣传材料", "产品包装", "批准文号", "收据发票", "付款记录", "销售人员联系方式"], ["拍摄产品外包装和宣传承诺", "保存讲座邀请、签到、收据", "让家人陪同联系售后"], "不要因销售人员催促继续购买或放弃正规治疗。", refs_health),
        evidence_guide("EVIDENCE_NATIONAL_PROJECT_001", "民族资产解冻/虚假国家项目诈骗", "资金转账前阶段", ["群名称", "群公告", "伪造文件", "收款码", "管理员账号", "拉人返利规则"], ["完整截图文件落款和转账要求", "保存群成员和管理员账号", "记录缴费名目和金额"], "不要继续拉亲友入群，也不要转发伪造文件。", refs_manual),
        evidence_guide("EVIDENCE_MEDICARE_FUND_001", "医保骗保/医保卡倒卖诈骗", "身份信息暴露阶段", ["医保消费明细", "医保码外借记录", "药品票据", "返钱聊天", "对方账号"], ["通过国家医保服务平台或当地医保渠道查询异常记录", "保存药店/诊所名称和时间", "保留返钱或套现话术"], "不要继续外借医保凭证或参与虚假购药。", refs_nhsa),
        evidence_guide("EVIDENCE_VIRTUAL_CURRENCY_LAUNDERING_001", "虚拟货币洗钱跑分诈骗", "已损失阶段", ["银行卡流水", "支付流水", "钱包地址", "交易哈希", "任务群聊天", "佣金记录"], ["导出银行或支付平台官方流水", "保存钱包地址和链上交易截图", "记录对方要求代收代付的原话"], "不要删除聊天记录，不要继续帮助转账或购买虚拟币。", refs_court),
        evidence_guide("EVIDENCE_LIVE_PRIVATE_TRADE_001", "直播带货/私域交易诈骗", "已损失阶段", ["直播间截图", "主播账号", "商品宣传", "私下付款凭证", "物流记录", "售后聊天"], ["保存从直播间跳转到私域的路径", "拍摄收到商品和宣传差异", "保存退款拒绝或失联证据"], "不要为退款再补邮费、保证金或继续私下付款。", [SRC_MARKET_HEALTH, SRC_2025_MANUAL]),
    ]
    upsert(evidence, "guide_id", new_evidence)

    new_laws = [
        law("LAW_CROSS_BORDER_FRAUD_2026_001", "跨境电诈招募与出境风险处置", ["跨境电诈", "境外高薪招工", "限制人身自由", "偷越国边境"], "跨境电诈相关违法犯罪可能同时涉及诈骗、组织偷越国边境、非法拘禁、帮助信息网络犯罪活动等风险。发现境外高薪招工诱骗，应停止联系并尽快向公安机关或人社部门核实。", ["停止联系招工方", "不要出境或赴边境集合", "保存广告、聊天和收费证据", "向公安机关、人社部门或学校就业中心核实"], ["广告截图", "聊天记录", "收费凭证", "证件提交记录", "集合地点"], ["跨境高薪招工诱骗诈骗", "求职实习招聘诈骗"], [SRC_CROSS_BORDER, SRC_COURT_2026], "cross_border_official_opinion"),
        law("LAW_AI_DEEPFAKE_CASH_PICKUP_2026_001", "AI拟声换脸与上门取现风险", ["AI拟声", "AI换脸", "上门取现", "冒充熟人"], "冒充熟人、客服或工作人员并要求大额转账、交现金或上门取现时，即使声音或视频相似，也应通过原号码、线下见面或共同熟人二次核验。", ["停止转账或交现金", "用原联系方式回拨核验", "保存语音、视频、聊天和取现人员信息", "必要时报警"], ["语音视频记录", "聊天记录", "取现人员照片或信息", "转账凭证"], ["AI换脸冒充熟人诈骗", "冒充领导或熟人借钱诈骗"], [SRC_COURT_2026, SRC_2025_MANUAL], "court_typical_case_guidance"),
        law("LAW_HEALTH_PRODUCT_CONSUMER_2026_001", "保健品夸大宣传和老年消费维权", ["保健品虚假宣传", "老年消费", "免费讲座", "高价预存"], "保健食品不能替代药品，宣称治疗疾病、虚构专家背书或诱导老年人高价购买的，可向市场监管、消协或公安机关反映。", ["停止继续购买", "保存宣传材料、票据和产品包装", "联系家人陪同维权", "向市场监管或消协投诉"], ["宣传单", "产品包装", "付款凭证", "讲座照片", "销售人员信息"], ["养老保健品诈骗"], [SRC_MARKET_HEALTH], "consumer_protection_guidance"),
        law("LAW_MEDICARE_FUND_2026_001", "医保凭证外借与骗保风险", ["医保骗保", "医保卡套现", "倒卖医保药品", "医保信息泄露"], "医保凭证、电子医保码和医保身份信息应由本人合规使用，外借套现、虚假就医购药或倒卖药品可能造成账户损失并承担相应责任。", ["停止外借医保凭证", "查询医保消费明细", "向医保部门反映异常", "保存返钱或套现证据"], ["医保消费记录", "聊天记录", "药品票据", "返钱记录"], ["医保骗保/医保卡倒卖诈骗"], [SRC_NHSA], "medical_insurance_fund_guidance"),
        law("LAW_VIRTUAL_CURRENCY_LAUNDERING_2026_001", "虚拟货币跑分与帮助犯罪风险", ["跑分洗钱", "虚拟币转移", "出借银行卡", "帮助信息网络犯罪活动"], "出借银行卡、支付账户、收款码或虚拟币钱包代收代付陌生资金，可能帮助电信网络诈骗资金转移，面临账户冻结和刑事法律风险。", ["停止代收代付", "不要再购买或转出虚拟币", "保存流水、钱包地址和聊天记录", "配合银行和公安核查"], ["银行流水", "支付流水", "钱包地址", "交易哈希", "任务群聊天"], ["虚拟货币洗钱跑分诈骗", "两卡出租出借与跑分诈骗"], [SRC_COURT_2026], "court_typical_case_guidance"),
        law("LAW_NATIONAL_ASSET_PROJECT_2026_001", "虚假国家项目和民族资产解冻风险", ["民族资产解冻", "虚假国家项目", "伪造公文", "拉人头"], "打着国家项目、资产解冻、内部补贴旗号收取会员费、激活费或要求拉人扩散的，应停止缴费并向公安机关举报。", ["停止缴费", "不要转发伪造文件", "保存群公告和收款信息", "提醒亲友不要参与"], ["群公告", "伪造文件", "收款码", "管理员账号", "拉人规则"], ["民族资产解冻/虚假国家项目诈骗"], [SRC_2025_MANUAL], "official_warning_guidance"),
        law("LAW_LIVE_COMMERCE_PRIVATE_TRADE_2026_001", "直播私域交易消费维权和反诈处置", ["直播购物", "私域交易", "私下转账", "货不对板"], "直播购物应保留在平台订单和售后体系内，私下扫码付款、货不对板或拒不退款时，应保存证据并联系平台、市场监管或消费者协会。", ["停止继续付款", "保存直播和付款证据", "联系平台官方客服", "向市场监管或消协投诉"], ["直播间截图", "商品宣传", "付款凭证", "物流记录", "售后聊天"], ["直播带货/私域交易诈骗"], [SRC_MARKET_HEALTH, SRC_2025_MANUAL], "consumer_protection_guidance"),
    ]
    upsert(laws, "law_id", new_laws)

    new_policies = [
        policy("KDP_CROSS_BORDER_HIGH_SALARY_V1", "跨境高薪招工诱骗诈骗", "scam_cross_border_high_salary", ["境外高薪", "出国高工资", "海外客服招聘", "电诈园区诱骗"], "境外高薪招工只要让你私下联系、交钱、交证件或秘密出境，就先按高危处理。", refs_cross),
        policy("KDP_ELDERLY_HEALTH_PRODUCT_V1", "养老保健品诈骗", "scam_elderly_health_product", ["保健品诈骗", "免费讲座", "专家义诊", "包治百病"], "保健品不是药，宣称治病并催促高价购买就是高危信号。", refs_health),
        policy("KDP_NATIONAL_ASSET_PROJECT_V1", "民族资产解冻/虚假国家项目诈骗", "scam_national_asset_project", ["民族资产解冻", "国家项目", "缴费领补贴"], "国家项目不会通过群聊让你先交钱领巨额补贴。", refs_manual),
        policy("KDP_MEDICARE_FUND_V1", "医保骗保/医保卡倒卖诈骗", "scam_medical_insurance_fund", ["医保骗保", "医保卡套现", "刷医保返钱"], "医保凭证不能外借、套现或倒卖药品，异常记录要及时核实。", refs_nhsa),
        policy("KDP_VIRTUAL_CURRENCY_LAUNDERING_V1", "虚拟货币洗钱跑分诈骗", "scam_virtual_currency_laundering", ["虚拟币跑分", "USDT代买", "刷流水", "代收代付"], "出借账户或用虚拟币转移陌生资金，可能是在帮电诈资金洗钱。", refs_court),
        policy("KDP_LIVE_PRIVATE_TRADE_V1", "直播带货/私域交易诈骗", "scam_live_commerce_private_trade", ["直播购物诈骗", "私域下单", "低价抢购", "私下转账购物"], "直播购物只走平台订单，私下转账会失去售后保障。", [SRC_MARKET_HEALTH, SRC_2025_MANUAL]),
    ]
    upsert(policies, "policy_id", new_policies)

    # Normalize older feature rows so statistics, search and admin views can group by fraud_type.
    scam_id_to_name = {row.get("scam_id"): row.get("name") for row in scam_types}
    for row in scam_features:
        if row.get("scam_id") and not row.get("fraud_type"):
            row["fraud_type"] = scam_id_to_name.get(row.get("scam_id"), "")
            row["updated_at"] = NOW
            row["knowledge_version"] = row.get("knowledge_version") or VERSION

    dump("scam_types", scam_types)
    dump("scam_features", scam_features)
    dump("risk_rules", risk_rules)
    dump("prevention_advice", prevention)
    dump("typical_cases", cases)
    dump("report_guides", reports)
    dump("evidence_guides", evidence)
    dump("law_clauses", laws)
    dump("knowledge_dialogue_policy", policies)


if __name__ == "__main__":
    main()
