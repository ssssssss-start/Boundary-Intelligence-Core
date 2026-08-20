"""Rebuild the anti-fraud knowledge database from curated seed data.

This script intentionally clears the configured MongoDB database and rebuilds
the Milvus anti_fraud_knowledge collection. It also writes the runtime seed
files used by the existing app:
- data/anti_fraud_knowledge_v2.json
- app/query_process/rules/anti_fraud_rules.json
- app/game_process/data/seed_game_levels.json
- data/test_cases/risk_cases.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List

from bson import ObjectId
from dotenv import load_dotenv
from pymongo import ASCENDING, DESCENDING, MongoClient


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
KNOWLEDGE_PATH = PROJECT_ROOT / "data" / "anti_fraud_knowledge_v2.json"
RULES_PATH = PROJECT_ROOT / "app" / "query_process" / "rules" / "anti_fraud_rules.json"
GAME_LEVELS_PATH = PROJECT_ROOT / "app" / "game_process" / "data" / "seed_game_levels.json"
TEST_CASES_PATH = PROJECT_ROOT / "data" / "test_cases" / "risk_cases.json"
STRUCTURED_SEED_PATH = PROJECT_ROOT / "data" / "anti_fraud_structured_seed.json"
BACKUP_ROOT = PROJECT_ROOT / "output" / "mongo_backups"

BUILD_DATE = "2026-05-19"
SOURCE_TEXT = "自建反诈知识库 2026-05-19：基于公开反诈提示、法律法规和项目规则人工整理"

VALID_RISK_FEATURES = {
    "陌生人引导",
    "任务返佣",
    "要求垫付资金",
    "承诺返利",
    "小额返利",
    "大额垫付",
    "无法提现",
    "诱导下载陌生APP",
    "高收益诱导",
    "保本稳赚承诺",
    "陌生投资平台",
    "索要验证码",
    "索要银行卡或身份信息",
    "点击陌生链接",
    "私下交易",
    "低价代充",
    "账号密码索取",
    "贷款前收费",
    "校园贷包装",
    "要求继续补单",
    "已发生转账",
    "要求缴纳解冻费",
    "要求删除证据",
    "冒充客服",
    "冒充公检法",
    "屏幕共享",
    "远程控制",
}

SOURCE_REFERENCES: List[Dict[str, Any]] = [
    {
        "source_id": "SRC_CUSTOM_KB_20260519",
        "title": "自建反诈知识库规则与案例集",
        "publisher": "项目组人工整理",
        "source_type": "knowledge_seed",
        "url": "",
        "publish_date": BUILD_DATE,
        "retrieved_at": BUILD_DATE,
        "credibility_level": "internal_reviewed",
        "review_status": "reviewed",
        "note": "用于比赛原型和业务演示，用户举报内容入库前必须脱敏和人工审核。",
    },
    {
        "source_id": "SRC_PUBLIC_ANTIFRAUD_TIPS",
        "title": "公安机关和国家反诈中心公开反诈提示",
        "publisher": "公安机关/国家反诈中心",
        "source_type": "public_safety_notice",
        "url": "https://www.mps.gov.cn/",
        "publish_date": "",
        "retrieved_at": BUILD_DATE,
        "credibility_level": "official_public",
        "review_status": "reviewed",
        "note": "用于归纳常见诈骗类型、风险信号和止损建议。",
    },
    {
        "source_id": "SRC_ANTI_TELECOM_FRAUD_LAW",
        "title": "中华人民共和国反电信网络诈骗法",
        "publisher": "全国人民代表大会常务委员会",
        "source_type": "law",
        "url": "https://www.npc.gov.cn/c2/c30834/202209/t20220902_319186.html",
        "publish_date": "2022-09-02",
        "retrieved_at": BUILD_DATE,
        "credibility_level": "official_law",
        "review_status": "reviewed",
        "note": "用于反诈治理、风险提示、涉诈工具治理和账户治理相关解释。",
    },
    {
        "source_id": "SRC_PIPL",
        "title": "中华人民共和国个人信息保护法",
        "publisher": "全国人民代表大会常务委员会",
        "source_type": "law",
        "url": "https://www.npc.gov.cn/npc/c2/c30834/202108/t20210820_313088.html",
        "publish_date": "2021-08-20",
        "retrieved_at": BUILD_DATE,
        "credibility_level": "official_law",
        "review_status": "reviewed",
        "note": "用于用户举报、聊天记录、截图和敏感信息处理的合规提示。",
    },
    {
        "source_id": "SRC_DATA_SECURITY_LAW",
        "title": "中华人民共和国数据安全法",
        "publisher": "全国人民代表大会常务委员会",
        "source_type": "law",
        "url": "https://www.gov.cn/xinwen/2021-06/11/content_5616919.htm",
        "publish_date": "2021-06-10",
        "retrieved_at": BUILD_DATE,
        "credibility_level": "official_law",
        "review_status": "reviewed",
        "note": "用于知识库、日志和用户举报数据安全管理说明。",
    },
    {
        "source_id": "SRC_CYBERSECURITY_LAW",
        "title": "中华人民共和国网络安全法及后续修正公开资料",
        "publisher": "全国人民代表大会常务委员会/中国政府网",
        "source_type": "law",
        "url": "https://www.gov.cn/",
        "publish_date": "",
        "retrieved_at": BUILD_DATE,
        "credibility_level": "official_law",
        "review_status": "review_required",
        "note": "用于网络运营安全、实名与个人信息保护的通用合规提示；具体条文以现行官方版本为准。",
    },
    {
        "source_id": "SRC_CRIMINAL_LAW",
        "title": "中华人民共和国刑法相关条款",
        "publisher": "全国人民代表大会",
        "source_type": "law",
        "url": "https://www.npc.gov.cn/",
        "publish_date": "",
        "retrieved_at": BUILD_DATE,
        "credibility_level": "official_law",
        "review_status": "review_required",
        "note": "用于诈骗罪、帮助信息网络犯罪活动罪等风险解释；具体适用以司法机关认定为准。",
    },
]

SOURCE_REFERENCES.extend(
    [
        {
            "source_id": "SRC_MPS_TOP10_2024",
            "title": "2024年十大高发电信网络诈骗类型典型案例",
            "publisher": "公安部公开发布，中国新闻网转载",
            "source_type": "police_case_notice",
            "url": "https://www.chinanews.com.cn/gn/2024/06-25/10240001.shtml",
            "publish_date": "2024-06-25",
            "retrieved_at": BUILD_DATE,
            "credibility_level": "official_release_reposted",
            "review_status": "reviewed",
            "note": "用于绑定刷单返利、虚假投资、虚假购物、冒充客服、虚假贷款、虚假征信、冒充熟人、冒充公检法、网络婚恋交友、游戏交易等公开案例。",
        },
        {
            "source_id": "SRC_SZ_POLICE_ETC_PHISHING",
            "title": "警惕短信钓鱼链接诈骗",
            "publisher": "深圳市公安局",
            "source_type": "police_case_notice",
            "url": "https://www.sz.gov.cn/hdjl/ywzsk/gaj/xz/content/post_10222452.html",
            "publish_date": "2022-11-04",
            "retrieved_at": BUILD_DATE,
            "credibility_level": "official_police",
            "review_status": "reviewed",
            "note": "用于绑定钓鱼链接、银行卡信息和短信验证码盗刷风险案例。",
        },
        {
            "source_id": "SRC_FJ_POLICE_SCREEN_SHARE",
            "title": "屏幕共享？你共享的是自己的钱包！",
            "publisher": "福建省公安厅",
            "source_type": "police_case_notice",
            "url": "https://gat.fj.gov.cn/ztzl/fjjffpzxrx/dxal/202309/t20230913_6255898.htm",
            "publish_date": "2023-09-13",
            "retrieved_at": BUILD_DATE,
            "credibility_level": "official_police",
            "review_status": "reviewed",
            "note": "用于绑定屏幕共享、远程会议和资金转走风险案例。",
        },
        {
            "source_id": "SRC_MIIT_ANTI_TELECOM_FRAUD_LAW",
            "title": "中华人民共和国反电信网络诈骗法",
            "publisher": "工业和信息化部法律法规库",
            "source_type": "law",
            "url": "https://www.miit.gov.cn/jgsj/zfs/fl/art/2022/art_d30139b442a141f48f05775d8c0b3cee.html",
            "publish_date": "2022-09-02",
            "retrieved_at": BUILD_DATE,
            "credibility_level": "official_law",
            "review_status": "reviewed",
            "note": "用于精确条文级入库，补齐反诈法原文条款。",
        },
        {
            "source_id": "SRC_GJBMJ_CYBERSECURITY_LAW_2026",
            "title": "中华人民共和国网络安全法（2025年修正，2026年1月1日起施行）",
            "publisher": "国家保密局",
            "source_type": "law",
            "url": "https://www.gjbmj.gov.cn/n1/2026/0421/c409088-40705863.html",
            "publish_date": "2026-04-21",
            "retrieved_at": BUILD_DATE,
            "credibility_level": "official_law",
            "review_status": "reviewed",
            "note": "用于网络安全法现行有效版本的条文级合规说明。",
        },
    ]
)

ADDITIONAL_LAW_CLAUSES: List[Dict[str, Any]] = [
        {
            "law_id": "LAW_ANTI_TELECOM_FRAUD_025_FULL",
            "law_name": "中华人民共和国反电信网络诈骗法",
            "article_no": "第二十五条",
            "original_text_excerpt": "任何单位和个人不得为他人实施电信网络诈骗活动提供支持或者帮助。",
            "original_text": "任何单位和个人不得为他人实施电信网络诈骗活动提供下列支持或者帮助：（一）出售、提供个人信息；（二）帮助他人通过虚拟货币交易等方式洗钱；（三）其他为电信网络诈骗活动提供支持或者帮助的行为。电信业务经营者、银行业金融机构、非银行支付机构、互联网服务提供者应当依照国家有关规定，履行合理注意义务，对利用下列业务从事涉诈支持、帮助活动进行监测识别和处置：（一）提供互联网接入、服务器托管、网络存储、通讯传输、线路出租、域名解析等网络资源服务；（二）提供信息发布或者搜索、广告推广、引流推广等网络推广服务；（三）提供应用程序、网站等网络技术、产品的制作、维护服务；（四）提供支付结算服务。",
            "plain_summary": "出租账号、卖个人信息、为涉诈链接引流、帮助洗钱或提供支付结算支持，都可能成为涉诈帮助行为。",
            "related_scam_types": ["刷单返利诈骗", "虚假投资理财诈骗", "钓鱼链接诈骗", "网络贷款诈骗"],
            "related_behaviors": ["引流推广", "出售个人信息", "跑分洗钱", "支付结算支持"],
            "effective_date": "2022-12-01",
            "source_id": "SRC_MIIT_ANTI_TELECOM_FRAUD_LAW",
            "caution": "系统只能做风险提示，具体违法犯罪认定以执法司法机关为准。",
        },
        {
            "law_id": "LAW_ANTI_TELECOM_FRAUD_030_FULL",
            "law_name": "中华人民共和国反电信网络诈骗法",
            "article_no": "第三十条",
            "original_text_excerpt": "公安机关会同有关部门建立预警劝阻系统，对预警发现的潜在被害人及时采取劝阻措施。",
            "original_text": "公安机关会同有关部门建立完善电信网络诈骗预警劝阻系统，根据电信网络诈骗案件侦办、电信网络诈骗活动监测等信息，及时发现、识别、预警潜在被害人，根据情况采取相应劝阻措施。对电信网络诈骗前科人员、涉诈异常电话卡、银行卡、互联网账号等，可以依照国家有关规定记入信用记录，采取限制其有关卡、账户、账号等功能和停止非柜面业务、暂停新业务、限制入网等措施。对上述认定和措施有异议的，可以提出申诉，有关部门应当建立健全申诉渠道、信用修复和救济制度。",
            "plain_summary": "反诈系统做预警、劝阻和风险提示，与国家反诈治理思路一致；但限制账号功能必须依法依规并提供申诉救济。",
            "related_scam_types": ["冒充公检法诈骗", "刷单返利诈骗", "冒充客服诈骗", "虚假投资理财诈骗"],
            "related_behaviors": ["风险预警", "劝阻", "涉诈账户治理", "申诉救济"],
            "effective_date": "2022-12-01",
            "source_id": "SRC_MIIT_ANTI_TELECOM_FRAUD_LAW",
            "caution": "项目原型只能提示风险，不应自行作出强制性账户处置。",
        },
        {
            "law_id": "LAW_ANTI_TELECOM_FRAUD_031_FULL",
            "law_name": "中华人民共和国反电信网络诈骗法",
            "article_no": "第三十一条",
            "original_text_excerpt": "不得非法买卖、出租、出借电话卡、物联网卡、电信线路、短信端口、银行账户、支付账户、互联网账号等。",
            "original_text": "任何单位和个人不得非法买卖、出租、出借电话卡、物联网卡、电信线路、短信端口、银行账户、支付账户、互联网账号等，不得提供实名核验帮助；不得假冒他人身份或者虚构代理关系开立上述卡、账户、账号等。对经设区的市级以上公安机关认定的实施前款行为的单位、个人和相关组织者，以及因从事电信网络诈骗活动或者关联犯罪受过刑事处罚的人员，可以按照国家有关规定记入信用记录，采取限制其有关卡、账户、账号等功能和停止非柜面业务、暂停新业务、限制入网等措施。",
            "plain_summary": "不要出租出借银行卡、电话卡、支付账户、实名账号，也不要帮陌生人代认证、代收款或刷流水。",
            "related_scam_types": ["网络贷款诈骗", "校园贷/培训贷诈骗", "刷单返利诈骗", "虚假投资理财诈骗"],
            "related_behaviors": ["出租银行卡", "出借电话卡", "代实名", "刷流水", "跑分"],
            "effective_date": "2022-12-01",
            "source_id": "SRC_MIIT_ANTI_TELECOM_FRAUD_LAW",
            "caution": "学生、兼职人员和急需贷款用户尤其要避免把账户交给陌生人使用。",
        },
        {
            "law_id": "LAW_ANTI_TELECOM_FRAUD_034_FULL",
            "law_name": "中华人民共和国反电信网络诈骗法",
            "article_no": "第三十四条",
            "original_text_excerpt": "公安机关应当依法及时查处电信网络诈骗案件，并会同有关部门加强追赃挽损。",
            "original_text": "公安机关应当依法及时查处电信网络诈骗案件，并会同有关部门加强追赃挽损，完善涉案资金处置制度，及时返还被害人的合法财产。电信网络诈骗的涉案资金及其产生的收益，应当依法追缴、没收。电信网络诈骗案件办理过程中，应当保护被害人的合法权益，尊重和保障人权。",
            "plain_summary": "已转账时应尽快报警、联系银行或支付机构止付，并保存聊天、账户、链接、App、转账凭证等证据。",
            "related_scam_types": ["刷单返利诈骗", "冒充客服诈骗", "冒充公检法诈骗", "虚假投资理财诈骗"],
            "related_behaviors": ["报警", "止付冻结", "追赃挽损", "证据保存"],
            "effective_date": "2022-12-01",
            "source_id": "SRC_MIIT_ANTI_TELECOM_FRAUD_LAW",
            "caution": "止付和追回存在时效性，系统应优先提示尽快联系银行、支付平台和公安机关。",
        },
        {
            "law_id": "LAW_PIPL_005_FULL",
            "law_name": "中华人民共和国个人信息保护法",
            "article_no": "第五条",
            "original_text_excerpt": "处理个人信息应当遵循合法、正当、必要和诚信原则。",
            "original_text": "处理个人信息应当遵循合法、正当、必要和诚信原则，不得通过误导、欺诈、胁迫等方式处理个人信息。",
            "plain_summary": "用户举报、聊天记录、截图、手机号、身份证号、银行卡号等不能靠诱导或强迫收集，必须有明确合法用途。",
            "related_scam_types": ["钓鱼链接诈骗", "验证码/账户盗刷诈骗", "冒充客服诈骗"],
            "related_behaviors": ["个人信息处理", "合法正当必要", "反欺诈", "用户举报"],
            "effective_date": "2021-11-01",
            "source_id": "SRC_PIPL",
            "caution": "反诈系统应最小化采集敏感信息，不应把原始隐私内容直接沉淀进知识库。",
        },
        {
            "law_id": "LAW_PIPL_006_FULL",
            "law_name": "中华人民共和国个人信息保护法",
            "article_no": "第六条",
            "original_text_excerpt": "处理个人信息应当具有明确、合理的目的，并限于实现处理目的的最小范围。",
            "original_text": "处理个人信息应当具有明确、合理的目的，并应当与处理目的直接相关，采取对个人权益影响最小的方式。收集个人信息，应当限于实现处理目的的最小范围，不得过度收集个人信息。",
            "plain_summary": "举报库只保存判断和止损必要的信息；进入典型案例或训练数据前必须脱敏、去标识化和人工审核。",
            "related_scam_types": ["未知"],
            "related_behaviors": ["最小必要", "过度收集", "脱敏审核", "举报数据治理"],
            "effective_date": "2021-11-01",
            "source_id": "SRC_PIPL",
            "caution": "不要把验证码、完整身份证、完整银行卡、原始手机号作为知识库公开字段。",
        },
        {
            "law_id": "LAW_PIPL_028_FULL",
            "law_name": "中华人民共和国个人信息保护法",
            "article_no": "第二十八条",
            "original_text_excerpt": "敏感个人信息包括生物识别、金融账户、行踪轨迹等信息。",
            "original_text": "敏感个人信息是一旦泄露或者非法使用，容易导致自然人的人格尊严受到侵害或者人身、财产安全受到危害的个人信息，包括生物识别、宗教信仰、特定身份、医疗健康、金融账户、行踪轨迹等信息，以及不满十四周岁未成年人的个人信息。只有在具有特定的目的和充分的必要性，并采取严格保护措施的情形下，个人信息处理者方可处理敏感个人信息。",
            "plain_summary": "银行卡、支付账户、人脸识别、身份证照片、定位轨迹等属于高敏感信息，反诈系统应提示用户不要提供给陌生人。",
            "related_scam_types": ["验证码/账户盗刷诈骗", "屏幕共享/远程控制诈骗", "冒充客服诈骗"],
            "related_behaviors": ["敏感个人信息", "金融账户", "人脸识别", "严格保护措施"],
            "effective_date": "2021-11-01",
            "source_id": "SRC_PIPL",
            "caution": "系统展示和日志中应对敏感字段做遮罩或摘要化处理。",
        },
        {
            "law_id": "LAW_DATA_SECURITY_027_FULL",
            "law_name": "中华人民共和国数据安全法",
            "article_no": "第二十七条",
            "original_text_excerpt": "开展数据处理活动应当建立健全全流程数据安全管理制度。",
            "original_text": "开展数据处理活动应当依照法律、法规的规定，建立健全全流程数据安全管理制度，组织开展数据安全教育培训，采取相应的技术措施和其他必要措施，保障数据安全。利用互联网等信息网络开展数据处理活动，应当在网络安全等级保护制度的基础上，履行上述数据安全保护义务。重要数据的处理者应当明确数据安全负责人和管理机构，落实数据安全保护责任。",
            "plain_summary": "知识库、举报库、日志库都应有权限控制、审计、备份、删除和数据分级策略。",
            "related_scam_types": ["未知"],
            "related_behaviors": ["数据安全制度", "访问控制", "审计日志", "备份恢复"],
            "effective_date": "2021-09-01",
            "source_id": "SRC_DATA_SECURITY_LAW",
            "caution": "比赛原型也应避免把隐私明文长期保存到日志和演示数据里。",
        },
        {
            "law_id": "LAW_CYBERSECURITY_044_FULL",
            "law_name": "中华人民共和国网络安全法",
            "article_no": "第四十四条",
            "original_text_excerpt": "任何个人和组织不得窃取或者以其他非法方式获取个人信息。",
            "original_text": "任何个人和组织不得窃取或者以其他非法方式获取个人信息，不得非法出售或者非法向他人提供个人信息。",
            "plain_summary": "钓鱼链接、假客服、验证码盗刷和倒卖用户资料，都与非法获取或提供个人信息风险高度相关。",
            "related_scam_types": ["钓鱼链接诈骗", "验证码/账户盗刷诈骗", "冒充客服诈骗"],
            "related_behaviors": ["非法获取个人信息", "倒卖个人信息", "钓鱼链接", "验证码盗刷"],
            "effective_date": "2026-01-01",
            "source_id": "SRC_GJBMJ_CYBERSECURITY_LAW_2026",
            "caution": "网络安全法已修正，具体引用应以现行官方公布版本为准。",
        },
]

OFFICIAL_CASES: List[Dict[str, Any]] = [
    {
        "case_id": "CASE_BRUSH_MPS_2024_001",
        "prefix": "brush",
        "scam_type_id": "scam_brush_rebate",
        "title": "刷单返利诈骗警方公开案例：小额返利后诱导连续垫付",
        "victim_group": "网购平台用户",
        "amount_loss": 420000,
        "amount_note": "警方公开案例披露约42万元",
        "channel": "购物平台评论区引流",
        "timeline": ["被评论区信息引流到兼职刷单", "完成小额任务并获得返利", "下载指定App后继续做大额任务", "以账户冻结、解冻费等理由多次转账"],
        "lesson": "小额返利不能证明平台真实，一旦出现垫付、补单、解冻费，应立即停止。",
        "source_ids": ["SRC_MPS_TOP10_2024"],
        "source_case_no": "典型案例一",
    },
    {
        "case_id": "CASE_GAME_MPS_2024_001",
        "prefix": "game",
        "scam_type_id": "scam_game_trade",
        "title": "游戏交易诈骗警方公开案例：私下买卖游戏账号后被拉黑",
        "victim_group": "游戏玩家",
        "amount_loss": 6000,
        "amount_note": "警方公开案例披露6000元",
        "channel": "游戏玩家交流群",
        "timeline": ["群内看到低价出售游戏账号信息", "脱离正规平台联系卖家", "按要求支付账号交易费用", "付款后无法取得账号且对方失联"],
        "lesson": "游戏账号、装备、点券交易应坚持官方平台担保，不要私下转账。",
        "source_ids": ["SRC_MPS_TOP10_2024"],
        "source_case_no": "典型案例十",
    },
    {
        "case_id": "CASE_INVEST_MPS_2024_001",
        "prefix": "invest",
        "scam_type_id": "scam_fake_investment",
        "title": "虚假投资理财警方公开案例：荐股群诱导下载陌生平台入金",
        "victim_group": "投资者",
        "amount_loss": 1400000,
        "amount_note": "警方公开案例披露先后转入100万余元和40万余元",
        "channel": "股票推荐群",
        "timeline": ["被拉入股票推荐群并接受老师荐股", "点击群内链接下载陌生投资App", "平台显示盈利后被诱导继续入金", "提现受阻并被要求继续缴费"],
        "lesson": "陌生投资平台、高收益承诺、导师荐股和提现收费同时出现，应按极高风险处理。",
        "source_ids": ["SRC_MPS_TOP10_2024"],
        "source_case_no": "典型案例二",
    },
    {
        "case_id": "CASE_LOAN_MPS_2024_001",
        "prefix": "loan",
        "scam_type_id": "scam_online_loan",
        "title": "虚假贷款警方公开案例：放款前先交解冻费和认证费",
        "victim_group": "贷款申请人",
        "amount_loss": 60000,
        "amount_note": "警方公开案例披露被骗6万元",
        "channel": "贷款广告和陌生贷款App",
        "timeline": ["看到低息贷款广告并下载指定App", "App显示额度审批通过但不能提现", "客服以银行卡异常、认证失败等理由收费", "多次转账后仍无法获得贷款"],
        "lesson": "正规贷款不会在放款前收取保证金、刷流水费、解冻费或认证金。",
        "source_ids": ["SRC_MPS_TOP10_2024"],
        "source_case_no": "典型案例五",
    },
    {
        "case_id": "CASE_CAMPUS_LOAN_MPS_2024_001",
        "prefix": "campus_loan",
        "scam_type_id": "scam_campus_loan",
        "title": "虚假征信警方公开案例：冒充金融客服诱导贷款转账",
        "victim_group": "年轻用户",
        "amount_loss": 140000,
        "amount_note": "警方公开案例披露被骗14万元",
        "channel": "陌生来电",
        "timeline": ["接到自称金融平台客服的来电", "对方称账户或征信存在异常需要处理", "诱导用户贷款并转入所谓安全账户", "转账后发现被骗"],
        "lesson": "声称影响征信、要求贷款转账或屏幕操作的，不要继续配合。",
        "source_ids": ["SRC_MPS_TOP10_2024"],
        "source_case_no": "典型案例六",
    },
    {
        "case_id": "CASE_SERVICE_MPS_2024_001",
        "prefix": "service",
        "scam_type_id": "scam_customer_service",
        "title": "冒充客服警方公开案例：快递理赔引导下载会议软件",
        "victim_group": "网购用户",
        "amount_loss": 0,
        "amount_note": "来源未披露具体损失金额",
        "channel": "陌生来电",
        "timeline": ["接到自称快递或平台客服的电话", "对方称快递丢失可以理赔", "诱导下载会议软件或进入理赔页面", "要求填写银行卡、验证码或配合屏幕操作"],
        "lesson": "退款理赔只应通过官方订单入口办理，不要点陌生链接或共享屏幕。",
        "source_ids": ["SRC_MPS_TOP10_2024"],
        "source_case_no": "典型案例四",
    },
    {
        "case_id": "CASE_POLICE_MPS_2024_001",
        "prefix": "police",
        "scam_type_id": "scam_fake_police",
        "title": "冒充公检法警方公开案例：涉案恐吓后诱导转入安全账户",
        "victim_group": "普通市民",
        "amount_loss": 150000,
        "amount_note": "警方公开案例披露至少涉及15万元贷款转账",
        "channel": "陌生电话",
        "timeline": ["接到自称公安机关来电并被告知涉案", "被要求保密并配合资金审查", "对方诱导贷款或集中资金", "资金转入所谓安全账户后被骗"],
        "lesson": "公检法不存在安全账户，不会电话办案、远程办案或要求转账自证清白。",
        "source_ids": ["SRC_MPS_TOP10_2024"],
        "source_case_no": "典型案例八",
    },
    {
        "case_id": "CASE_ROMANCE_MPS_2024_001",
        "prefix": "romance",
        "scam_type_id": "scam_romance",
        "title": "杀猪盘警方公开案例：网络交友后诱导投资转账",
        "victim_group": "婚恋交友用户",
        "amount_loss": 1600000,
        "amount_note": "警方公开案例披露被骗160余万元",
        "channel": "网络婚恋交友平台",
        "timeline": ["通过婚恋或社交平台结识网友", "对方长期聊天建立亲密关系", "引导进入投资、博彩或理财平台", "持续加仓后不能提现或被拉黑"],
        "lesson": "网恋对象推荐投资平台、声称内部渠道或代操作时，应立即停止转账。",
        "source_ids": ["SRC_MPS_TOP10_2024"],
        "source_case_no": "典型案例九",
    },
    {
        "case_id": "CASE_PHISHING_SZ_2022_001",
        "prefix": "phishing",
        "scam_type_id": "scam_phishing",
        "title": "钓鱼链接警方公开案例：ETC短信诱导填写银行卡信息",
        "victim_group": "车主",
        "amount_loss": 6500,
        "amount_note": "警方公开案例披露银行卡被转走6500元",
        "channel": "短信链接",
        "timeline": ["收到所谓ETC异常短信", "点击短信中的陌生链接", "在仿冒页面填写银行卡、身份信息和验证码", "银行卡资金被盗刷"],
        "lesson": "短信中的认证、升级、过期链接不要点，应从官方App或官网入口核实。",
        "source_ids": ["SRC_SZ_POLICE_ETC_PHISHING"],
        "source_case_no": "ETC短信钓鱼案例",
    },
    {
        "case_id": "CASE_CODE_SZ_2022_001",
        "prefix": "code",
        "scam_type_id": "scam_code_theft",
        "title": "验证码盗刷警方公开案例：钓鱼页面索要动态码后盗刷",
        "victim_group": "银行卡用户",
        "amount_loss": 6500,
        "amount_note": "与深圳公安公开ETC钓鱼案例同源",
        "channel": "短信钓鱼页面",
        "timeline": ["用户进入仿冒认证页面", "页面要求输入银行卡和短信验证码", "验证码被用于完成扣款或盗刷", "用户收到银行扣款提醒后发现异常"],
        "lesson": "验证码等同于资金操作授权，不要提供给任何陌生页面或陌生客服。",
        "source_ids": ["SRC_SZ_POLICE_ETC_PHISHING"],
        "source_case_no": "ETC短信钓鱼案例",
    },
    {
        "case_id": "CASE_SCREEN_FJ_2023_001",
        "prefix": "screen",
        "scam_type_id": "scam_screen_share",
        "title": "屏幕共享警方公开案例：会议软件暴露资金操作后被骗",
        "victim_group": "平台用户",
        "amount_loss": 50000,
        "amount_note": "福建省公安厅公开案例披露5万元",
        "channel": "陌生来电和会议软件",
        "timeline": ["接到自称平台或客服人员来电", "按要求打开会议软件并共享屏幕", "银行卡、验证码或支付操作被对方实时看到", "账户资金被转走"],
        "lesson": "屏幕共享不是普通沟通，对方能看到验证码、余额和支付操作，应立即退出。",
        "source_ids": ["SRC_FJ_POLICE_SCREEN_SHARE"],
        "source_case_no": "屏幕共享案例",
    },
    {
        "case_id": "CASE_ACQUAINTANCE_MPS_2024_001",
        "prefix": "acquaintance",
        "scam_type_id": "scam_acquaintance",
        "title": "冒充熟人警方公开案例：盗用亲友账号后借钱",
        "victim_group": "社交软件用户",
        "amount_loss": 0,
        "amount_note": "来源未披露具体损失金额",
        "channel": "社交软件账号",
        "timeline": ["收到亲友或熟人账号发来的借钱请求", "对方以急事、不方便电话等理由催促转账", "用户未通过电话或线下方式核验", "转账后发现账号被盗或身份被冒充"],
        "lesson": "熟人账号也可能被盗，涉及借钱转账必须电话或当面核验。",
        "source_ids": ["SRC_MPS_TOP10_2024"],
        "source_case_no": "典型案例七",
    },
    {
        "case_id": "CASE_SHOPPING_MPS_2024_001",
        "prefix": "shopping",
        "scam_type_id": "scam_fake_shopping",
        "title": "虚假购物服务警方公开案例：低价门票诱导私下转账",
        "victim_group": "票务消费者",
        "amount_loss": 13000,
        "amount_note": "警方公开案例披露支付订金1.3万元，后续还被索要保证金",
        "channel": "票务或社交平台私聊",
        "timeline": ["看到低价稀缺门票或商品信息", "卖家要求脱离平台私聊交易", "用户先支付定金或全款", "对方继续索要保证金或直接失联"],
        "lesson": "低价稀缺商品和私下转账组合风险很高，应坚持平台担保交易。",
        "source_ids": ["SRC_MPS_TOP10_2024"],
        "source_case_no": "典型案例三",
    },
]

OFFICIAL_CASE_BY_PREFIX = {case["prefix"]: case for case in OFFICIAL_CASES}

LAW_CLAUSES: List[Dict[str, Any]] = [
    {
        "law_id": "LAW_ANTI_TELECOM_FRAUD_001",
        "law_name": "中华人民共和国反电信网络诈骗法",
        "article_no": "总则及综合治理相关条款",
        "original_text_excerpt": "国家治理电信网络诈骗活动，保护公民和组织合法权益。",
        "plain_summary": "系统做反诈提醒、风险识别、举报入口和涉诈行为预警，有明确的公共安全和反诈治理价值。",
        "related_scam_types": ["刷单返利诈骗", "冒充公检法诈骗", "虚假投资理财诈骗", "网络贷款诈骗"],
        "related_behaviors": ["电信网络诈骗", "涉诈引流", "账户异常交易", "风险预警"],
        "effective_date": "2022-12-01",
        "source_id": "SRC_ANTI_TELECOM_FRAUD_LAW",
        "caution": "仅作反诈科普和合规提示，不构成法律意见。",
    },
    {
        "law_id": "LAW_ANTI_TELECOM_FRAUD_002",
        "law_name": "中华人民共和国反电信网络诈骗法",
        "article_no": "电话卡、银行卡、互联网账号治理相关条款",
        "original_text_excerpt": "不得非法买卖、出租、出借电话卡、银行卡、支付账户、互联网账号。",
        "plain_summary": "出租出借银行卡、电话卡、支付账户可能被用于跑分洗钱或转移赃款，学生用户尤其要避免帮人收款、刷流水、代实名。",
        "related_scam_types": ["网络贷款诈骗", "校园贷/培训贷诈骗", "虚假投资理财诈骗"],
        "related_behaviors": ["出租银行卡", "刷流水", "代收款", "出借支付账户"],
        "effective_date": "2022-12-01",
        "source_id": "SRC_ANTI_TELECOM_FRAUD_LAW",
        "caution": "具体责任需由执法司法机关结合事实认定。",
    },
    {
        "law_id": "LAW_PIPL_001",
        "law_name": "中华人民共和国个人信息保护法",
        "article_no": "个人信息处理原则相关条款",
        "original_text_excerpt": "处理个人信息应当遵循合法、正当、必要和诚信原则。",
        "plain_summary": "举报、聊天记录、截图、手机号、身份证号、银行卡号等信息入库前应最小化采集、脱敏处理、限制访问和明确用途。",
        "related_scam_types": ["钓鱼链接诈骗", "验证码/账户盗刷诈骗", "冒充客服诈骗"],
        "related_behaviors": ["个人信息收集", "敏感信息脱敏", "用户举报处理"],
        "effective_date": "2021-11-01",
        "source_id": "SRC_PIPL",
        "caution": "系统不得把用户提交的敏感信息直接公开展示或用于无关用途。",
    },
    {
        "law_id": "LAW_DATA_SECURITY_001",
        "law_name": "中华人民共和国数据安全法",
        "article_no": "数据处理安全管理相关条款",
        "original_text_excerpt": "开展数据处理活动应当依照法律法规建立健全全流程数据安全管理制度。",
        "plain_summary": "反诈知识库和举报库应有访问控制、审计日志、备份、数据分级和删除策略。",
        "related_scam_types": ["未知"],
        "related_behaviors": ["数据安全", "日志审计", "知识库管理", "举报数据治理"],
        "effective_date": "2021-09-01",
        "source_id": "SRC_DATA_SECURITY_LAW",
        "caution": "比赛原型也应避免明文长期保存身份证、银行卡、验证码等敏感数据。",
    },
    {
        "law_id": "LAW_CRIMINAL_266",
        "law_name": "中华人民共和国刑法",
        "article_no": "第二百六十六条",
        "original_text_excerpt": "诈骗公私财物，数额较大的，依法追究刑事责任。",
        "plain_summary": "刷单返利、虚假投资、冒充客服、公检法等以非法占有为目的骗取财物的行为，可能涉及诈骗犯罪。",
        "related_scam_types": ["刷单返利诈骗", "虚假投资理财诈骗", "冒充客服诈骗", "冒充公检法诈骗"],
        "related_behaviors": ["骗取财物", "虚构事实", "隐瞒真相"],
        "effective_date": "",
        "source_id": "SRC_CRIMINAL_LAW",
        "caution": "是否构成犯罪和具体罪名需以司法机关认定为准。",
    },
    {
        "law_id": "LAW_CRIMINAL_287_2",
        "law_name": "中华人民共和国刑法",
        "article_no": "第二百八十七条之二",
        "original_text_excerpt": "明知他人利用信息网络实施犯罪，为其提供帮助，情节严重的，依法追责。",
        "plain_summary": "为诈骗团伙提供银行卡、电话卡、支付账户、技术支持、推广引流等帮助，可能涉及帮助信息网络犯罪活动风险。",
        "related_scam_types": ["网络贷款诈骗", "刷单返利诈骗", "钓鱼链接诈骗"],
        "related_behaviors": ["跑分", "出借账户", "引流推广", "技术支持"],
        "effective_date": "",
        "source_id": "SRC_CRIMINAL_LAW",
        "caution": "不要帮助陌生人收款、转账、开户注册、代发链接或代做认证。",
    },
]

LAW_CLAUSES.extend(ADDITIONAL_LAW_CLAUSES)

SCAM_BLUEPRINTS: List[Dict[str, Any]] = [
    {
        "id": "scam_brush_rebate",
        "prefix": "brush",
        "name": "刷单返利诈骗",
        "operational_fraud_type": "刷单返利诈骗",
        "aliases": ["点赞返佣", "做任务返现", "兼职刷单", "补单返利", "关注赚钱"],
        "description": "以兼职做任务、点赞关注、垫付订单返佣为诱饵，先小额返利建立信任，再诱导大额垫付和补单。",
        "target_users": ["学生", "宝妈", "待业人员", "想做兼职的年轻用户"],
        "channels": ["QQ群", "微信群", "短视频私信", "兼职广告", "陌生App"],
        "risk_tags": ["陌生人引导", "任务返佣", "要求垫付资金", "承诺返利", "小额返利", "大额垫付", "无法提现", "要求继续补单", "要求缴纳解冻费", "已发生转账"],
        "core_trick": "先安排低门槛任务并返还小额佣金，随后要求垫付更大订单，最后用卡单、联单、提现失败、解冻费等理由继续要钱。",
        "danger_action": "垫付订单、继续补单、缴纳解冻费或向私人账户转账",
        "immediate_action": "立即停止补单和任何新增转账，退出对方指定App但保留截图。",
        "verification": "正规兼职不会要求先垫付本金；招聘信息应通过官方招聘平台和用工主体核验。",
        "evidence": ["群聊和客服聊天记录", "任务页面", "App名称和下载链接", "收款账户", "转账凭证", "提现失败截图"],
        "reporting": "已转账时尽快联系银行或支付平台止付，同时报警并说明刷单返利、垫付、不能提现和继续补单的时间线。",
        "primary_choice": "需要先垫付资金",
        "safe_choice": "停止补单并保存记录",
        "case_amount": 6800,
        "case_channel": "兼职群",
        "sample_user_text": "我在群里做刷单任务，前两单返了几十元，现在提现失败，客服让我再交1000元解冻费。",
        "rule": {"all": ["任务返佣", "要求垫付资金"], "any": ["承诺返利", "小额返利", "无法提现", "要求继续补单", "要求缴纳解冻费"], "min_any": 1, "score": 96, "goal": "stop_transfer"},
        "features": [
            ("任务返佣入口", "诱饵", ["刷单", "点赞", "关注", "做任务", "返佣"], ["对方说点赞关注就能日结佣金"], ["正规平台内的公开活动且不要求垫付"], 7, "引流诱导阶段", "任务返佣常是刷单诈骗前端引流。"),
            ("先垫付后返利", "资金", ["垫付", "充值", "先付", "本金佣金一起返"], ["客服要求先垫付订单再返本金和佣金"], ["线下正式劳动合同约定的合法薪酬结算"], 10, "资金转账阶段", "兼职不应要求求职者先垫钱完成任务。"),
            ("小额返利建立信任", "信任", ["试单", "小额返现", "先返"], ["前两单返了几十元后诱导做大单"], ["平台真实促销返券且无需转账"], 8, "建立信任阶段", "小额到账可能只是诈骗成本。"),
            ("提现失败继续补单", "收割", ["卡单", "联单", "补单", "解冻费", "保证金"], ["平台显示不能提现，要求继续补单解冻"], ["正规平台因风控要求补充合法身份材料"], 10, "提现受阻阶段", "提现受阻后继续收费是扩大损失的关键节点。"),
        ],
        "flow_steps": ["发布兼职返佣广告", "引导加群或下载任务App", "小额任务返利", "诱导大额垫付或联单", "提现失败后继续索要费用", "拉黑或继续拖延"],
        "psychology": ["贪利", "从众", "沉没成本", "限时压力"],
        "sample_dialogue": "客服：这单完成后本金和佣金一起返；用户：为什么不能提现？客服：你还差一单，补完才能解冻。",
        "badge": "刷单识别者",
    },
    {
        "id": "scam_game_trade",
        "prefix": "game",
        "name": "游戏交易诈骗",
        "operational_fraud_type": "游戏交易诈骗",
        "aliases": ["账号交易诈骗", "低价代充", "皮肤交易", "装备交易", "验号链接"],
        "description": "围绕游戏账号、点券、皮肤、装备、代练等虚拟资产，诱导用户脱离平台担保、私下付款或交出账号密码。",
        "target_users": ["学生", "游戏玩家", "未成年人", "二手交易用户"],
        "channels": ["游戏群", "贴吧论坛", "二手平台私信", "短视频评论区", "社交账号"],
        "risk_tags": ["陌生人引导", "私下交易", "低价代充", "账号密码索取", "点击陌生链接", "索要验证码", "要求垫付资金", "已发生转账"],
        "core_trick": "用低价、急售、包赔或担保客服伪装吸引用户，随后要求平台外付款、交账号密码、点击验号链接或缴纳保证金。",
        "danger_action": "私下付款、发送账号密码、点击验号链接或提供验证码",
        "immediate_action": "停止平台外交易，不交账号密码和验证码，关闭陌生验号链接。",
        "verification": "只使用官方交易、充值和找回渠道；第三方担保客服身份必须在原平台内核验。",
        "evidence": ["交易聊天记录", "对方游戏ID", "收款码", "验号链接", "账号登录提醒", "转账凭证"],
        "reporting": "通过游戏平台和支付平台投诉冻结账号交易，同时报警说明虚拟物品交易和资金流向。",
        "primary_choice": "脱离平台私下交易",
        "safe_choice": "使用官方或平台担保渠道",
        "case_amount": 2300,
        "case_channel": "游戏交易群",
        "sample_user_text": "有人说半价代充游戏点券，让我先转账到个人账户，还要把账号密码发给他验号。",
        "rule": {"all": ["私下交易"], "any": ["低价代充", "账号密码索取", "点击陌生链接", "索要验证码", "要求垫付资金"], "min_any": 1, "score": 88, "goal": "stop_transfer"},
        "features": [
            ("低价代充诱饵", "诱饵", ["半价充值", "低价代充", "点券", "皮肤"], ["陌生人承诺半价充值游戏点券"], ["官方平台限时促销"], 7, "引流诱导阶段", "低价代充常伴随私下付款和盗号风险。"),
            ("平台外私下交易", "交易", ["私下", "平台外", "个人收款", "担保客服"], ["对方要求绕开官方平台付款"], ["平台内担保订单"], 9, "资金转账阶段", "脱离平台后缺少交易保障。"),
            ("账号密码验号", "信息", ["验号", "账号密码", "登录密码", "密保"], ["买家要求先发账号密码验号"], ["平台官方授权登录且不泄露密码"], 10, "信息索取阶段", "账号密码可能被直接盗取或改绑。"),
            ("验号链接和验证码", "钓鱼", ["链接", "验证码", "绑定手机", "安全验证"], ["对方发链接要求输入验证码"], ["官方App内安全验证"], 9, "信息索取阶段", "验号链接可能是钓鱼页面。"),
        ],
        "flow_steps": ["发布低价或急售游戏资产", "诱导私聊", "提出平台外付款或验号", "索要账号密码/验证码", "盗号或收款后拉黑"],
        "psychology": ["低价诱惑", "稀缺焦虑", "交易便利", "未成年人防范弱"],
        "sample_dialogue": "卖家：走平台太慢，直接转我更便宜；客服：验号要账号密码和短信码。",
        "badge": "交易守门员",
    },
    {
        "id": "scam_fake_investment",
        "prefix": "invest",
        "name": "虚假投资理财诈骗",
        "operational_fraud_type": "虚假投资理财诈骗",
        "aliases": ["荐股诈骗", "虚拟币投资", "外汇平台", "导师带单", "AI量化理财"],
        "description": "用投资群、老师带单、内部消息、高收益截图包装虚假平台，诱导充值、加仓，提现时继续收费。",
        "target_users": ["有理财需求用户", "大学生", "中老年人", "有一定积蓄的个人"],
        "channels": ["投资群", "婚恋社交", "短视频直播", "财经课程", "陌生App"],
        "risk_tags": ["陌生人引导", "高收益诱导", "保本稳赚承诺", "陌生投资平台", "诱导下载陌生APP", "要求垫付资金", "无法提现", "要求缴纳解冻费", "已发生转账"],
        "core_trick": "通过群内角色配合和虚假盈利截图制造可信度，引导用户到非正规平台入金，后续用税费、保证金、风控解除等名义阻止提现。",
        "danger_action": "向陌生投资平台充值、加仓、缴税费或交保证金",
        "immediate_action": "停止入金和缴费，保存平台页面、导师话术、充值地址和转账记录。",
        "verification": "投资平台应核验金融业务资质、官方渠道和资金托管，不相信保本稳赚和内部消息。",
        "evidence": ["投资群聊天", "老师和助理账号", "平台网址/App", "充值地址", "交易流水", "提现失败页面"],
        "reporting": "已入金时同时联系银行/支付平台止付并报警，说明平台名称、充值账户、诱导人员和提现受阻经过。",
        "primary_choice": "陌生平台承诺高收益",
        "safe_choice": "停止入金并核实资质",
        "case_amount": 35800,
        "case_channel": "投资交流群",
        "sample_user_text": "群里老师说有内部消息，让我下载一个投资App，保证三天20%收益，现在盈利不能提现，要先交税费。",
        "rule": {"all": ["陌生投资平台", "高收益诱导"], "any": ["保本稳赚承诺", "无法提现", "要求缴纳解冻费", "诱导下载陌生APP", "要求垫付资金"], "min_any": 1, "score": 95, "goal": "stop_transfer"},
        "features": [
            ("高收益保本承诺", "诱饵", ["稳赚", "保本", "翻倍", "内部消息"], ["导师承诺三天收益20%"], ["合规产品披露风险且不承诺收益"], 9, "引流诱导阶段", "保本高收益与投资风险常识冲突。"),
            ("陌生投资平台", "平台", ["交易平台", "量化App", "虚拟币平台", "开户链接"], ["要求下载非应用商店投资App"], ["持牌机构官方App"], 9, "资金转账前阶段", "虚假平台可操控余额和盈亏。"),
            ("群内角色配合", "信任", ["老师", "助理", "学员", "晒收益"], ["群里多人晒盈利截图"], ["公开透明的合规投教社群"], 7, "建立信任阶段", "群内热闹可能是团伙话术。"),
            ("提现缴费", "收割", ["税费", "保证金", "风控", "解冻"], ["盈利后提现需先缴税"], ["合规平台按规则扣缴且不转私人账户"], 10, "提现受阻阶段", "提现前额外转账是高危信号。"),
        ],
        "flow_steps": ["拉入投资群", "老师讲课晒收益", "引导下载平台", "小额盈利诱导加仓", "提现受阻要求缴费", "继续收割或失联"],
        "psychology": ["贪利", "权威", "从众", "错失恐惧"],
        "sample_dialogue": "老师：这是内部席位，保本收益；客服：提现需先补缴税费，到账后返还。",
        "badge": "投资冷静者",
    },
    {
        "id": "scam_online_loan",
        "prefix": "loan",
        "name": "网络贷款诈骗",
        "operational_fraud_type": "网络贷款诈骗",
        "aliases": ["低息贷款", "无抵押秒批", "刷流水贷款", "解冻费贷款", "会员费放款"],
        "description": "以快速放款、低息、无抵押为诱饵，诱导下载虚假贷款App，再以保证金、会员费、刷流水、解冻费收费。",
        "target_users": ["急需资金用户", "学生", "小微经营者", "征信较弱用户"],
        "channels": ["短信广告", "网页弹窗", "短视频广告", "陌生贷款App", "电话推销"],
        "risk_tags": ["陌生人引导", "贷款前收费", "诱导下载陌生APP", "索要银行卡或身份信息", "索要验证码", "要求垫付资金", "要求缴纳解冻费", "无法提现", "已发生转账"],
        "core_trick": "先显示额度已批或放款成功，再编造银行卡错误、流水不足、账户冻结、会员等级不够等理由要求先交钱。",
        "danger_action": "放款前缴纳保证金、会员费、解冻费或刷流水",
        "immediate_action": "停止缴费，不再提交身份证、银行卡、验证码和人脸识别。",
        "verification": "只通过持牌金融机构官方渠道申请贷款；贷款未到账前收费应直接拒绝。",
        "evidence": ["贷款App截图", "客服聊天", "合同页面", "银行卡号错误提示", "收款账户", "转账凭证"],
        "reporting": "说明未实际放款却被要求缴纳费用，保存App和客服资料后报警并联系银行保护账户。",
        "primary_choice": "放款前收费",
        "safe_choice": "拒绝缴费并通过正规渠道咨询",
        "case_amount": 5200,
        "case_channel": "贷款短信链接",
        "sample_user_text": "贷款App说额度批了，但银行卡号填错资金被冻结，要我先交解冻费和刷流水才能放款。",
        "rule": {"all": ["贷款前收费"], "any": ["要求垫付资金", "诱导下载陌生APP", "索要银行卡或身份信息", "要求缴纳解冻费", "无法提现"], "min_any": 1, "score": 92, "goal": "stop_transfer"},
        "features": [
            ("低息秒批诱导", "诱饵", ["秒批", "低息", "无抵押", "不看征信"], ["短信称无抵押当天放款"], ["持牌机构明确资质和费率"], 6, "引流诱导阶段", "过度宽松的贷款承诺需要核实。"),
            ("陌生贷款App", "平台", ["贷款App", "下载", "开户链接"], ["客服要求安装非官方贷款App"], ["应用商店内持牌机构官方App"], 8, "信息索取阶段", "陌生App可能收集敏感信息。"),
            ("放款前收费", "资金", ["保证金", "会员费", "刷流水", "认证费"], ["未到账先交会员费"], ["贷款到账后按合同还本付息"], 10, "资金转账阶段", "放款前收费是网络贷款诈骗核心信号。"),
            ("银行卡错误解冻", "收割", ["卡号错误", "冻结", "解冻费", "银监"], ["平台说银行卡号错了要交解冻费"], ["银行官方渠道核验卡号"], 10, "提现受阻阶段", "卡号错误解冻费常用于二次收费。"),
        ],
        "flow_steps": ["发布贷款广告", "展示预审批额度", "要求下载App并填资料", "放款前收费", "制造冻结继续收费", "失联或继续威胁征信"],
        "psychology": ["急需资金", "低门槛诱惑", "征信焦虑", "法律威胁"],
        "sample_dialogue": "客服：额度已批，但账户被冻结；用户：怎么办？客服：先交解冻费，到账一起退。",
        "badge": "贷前防线",
    },
    {
        "id": "scam_campus_loan",
        "prefix": "campus_loan",
        "name": "校园贷/培训贷诈骗",
        "operational_fraud_type": "网络贷款诈骗",
        "aliases": ["校园贷包装", "培训贷", "注销校园贷", "学生贷款", "资料包装费"],
        "description": "针对学生群体，以包装资料、低息助学、培训分期、注销校园贷账户为名索取费用或身份信息。",
        "target_users": ["大学生", "刚毕业学生", "职业培训学员", "急需生活费的学生"],
        "channels": ["校园群", "兼职群", "培训机构销售", "陌生电话", "社交平台私信"],
        "risk_tags": ["陌生人引导", "贷款前收费", "校园贷包装", "诱导下载陌生APP", "索要银行卡或身份信息", "索要验证码", "要求垫付资金", "要求缴纳解冻费", "已发生转账"],
        "core_trick": "用学生身份、补贴名额、培训就业、注销历史贷款记录等理由制造压力，要求交资料费、保证金、刷流水或远程认证。",
        "danger_action": "交资料包装费、培训分期首付、注销账户保证金或交出身份银行卡信息",
        "immediate_action": "暂停签约和付款，不上传身份证、学生证、银行卡和验证码。",
        "verification": "通过学校资助中心、正规银行、官方客服或培训机构合同备案核验，不相信私聊办理。",
        "evidence": ["宣传截图", "合同或分期页面", "销售聊天", "付款二维码", "身份证/学生证提交记录", "客服账号"],
        "reporting": "如已付款或被诱导分期，联系学校、贷款/支付平台和警方，说明是否存在培训贷、包装费或注销校园贷话术。",
        "primary_choice": "包装学生资料并先收费",
        "safe_choice": "通过学校或正规金融渠道核实",
        "case_amount": 9800,
        "case_channel": "校园兼职群",
        "sample_user_text": "有人说能包装学生资料办贷款，要先交资料费，还让我发身份证、学生证和银行卡验证码。",
        "rule": {"all": ["校园贷包装", "贷款前收费"], "any": ["索要银行卡或身份信息", "索要验证码", "要求垫付资金", "诱导下载陌生APP"], "min_any": 1, "score": 90, "goal": "stop_transfer"},
        "features": [
            ("学生身份包装", "诱饵", ["学生贷款", "校园贷", "助学", "资料包装"], ["对方称可包装学生资料提高额度"], ["学校官方助学贷款流程"], 8, "引流诱导阶段", "学生身份被包装成贷款入口时要谨慎。"),
            ("培训贷分期压力", "合同", ["培训贷", "就业保障", "分期", "先学后付"], ["培训机构诱导签分期并承诺就业"], ["正规培训合同充分告知费用和退费"], 8, "资金转账前阶段", "培训贷可能让学生背负不透明债务。"),
            ("贷前资料费", "资金", ["资料费", "保证金", "包装费", "刷流水"], ["办贷款前先交资料费"], ["正规贷款不收包装资料费"], 10, "资金转账阶段", "贷前收费和包装资料是高危组合。"),
            ("索取学生证和验证码", "信息", ["学生证", "身份证", "银行卡", "验证码"], ["要求发学生证和银行卡验证码"], ["官方窗口核验且不索要验证码"], 9, "信息索取阶段", "身份材料可能被用于冒名贷款。"),
        ],
        "flow_steps": ["通过校园渠道接触学生", "承诺贷款/就业/注销账户", "索取身份材料", "要求资料费或分期", "以审核失败或征信风险继续施压"],
        "psychology": ["急需用钱", "就业焦虑", "权威压力", "经验不足"],
        "sample_dialogue": "顾问：学生资料可以包装，交资料费就能下款；客服：验证码给我才能认证。",
        "badge": "校园贷防线",
    },
    {
        "id": "scam_customer_service",
        "prefix": "service",
        "name": "冒充客服诈骗",
        "operational_fraud_type": "冒充客服诈骗",
        "aliases": ["退款理赔诈骗", "快递理赔", "取消会员", "百万保障扣费", "退改签客服"],
        "description": "冒充电商、物流、支付、航空等客服，以退款、理赔、取消扣费为由索要验证码、共享屏幕或诱导转账。",
        "target_users": ["网购用户", "快递收件人", "支付平台用户", "学生和家长"],
        "channels": ["陌生来电", "短信", "社交软件", "会议软件", "钓鱼链接"],
        "risk_tags": ["冒充客服", "点击陌生链接", "诱导下载陌生APP", "索要验证码", "索要银行卡或身份信息", "屏幕共享", "远程控制", "要求垫付资金"],
        "core_trick": "先说出部分订单或快递信息取得信任，再引导点击链接、下载会议软件、共享屏幕或转账验证。",
        "danger_action": "点击理赔链接、提供验证码、共享屏幕、转账验证或下载会议软件",
        "immediate_action": "挂断陌生客服，停止共享屏幕和验证码发送，通过官方订单入口核实。",
        "verification": "只在官方App订单页、官网客服电话或平台内客服核实退款理赔，不使用对方提供的链接和电话。",
        "evidence": ["来电号码", "短信", "理赔链接", "会议号", "聊天记录", "验证码短信", "转账记录"],
        "reporting": "如验证码或屏幕信息已泄露，先冻结账户和修改密码，再向平台投诉并报警。",
        "primary_choice": "索要验证码或共享屏幕",
        "safe_choice": "挂断并从官方App核实",
        "case_amount": 12600,
        "case_channel": "陌生来电",
        "sample_user_text": "自称快递客服说包裹丢了要理赔，发链接让我填银行卡和验证码，还让我开会议软件共享屏幕。",
        "rule": {"all": ["冒充客服"], "any": ["索要验证码", "屏幕共享", "点击陌生链接", "索要银行卡或身份信息", "远程控制", "要求垫付资金"], "min_any": 1, "score": 91, "goal": "stop_code_leak"},
        "features": [
            ("订单信息包装身份", "身份", ["客服", "订单", "快递", "理赔"], ["对方能说出快递信息并自称客服"], ["用户主动从官方App联系的客服"], 7, "初步接触阶段", "知道部分订单信息不代表身份真实。"),
            ("退款理赔链接", "链接", ["退款链接", "理赔入口", "二维码"], ["客服发链接要求填写银行卡"], ["官方订单页退款"], 9, "信息索取阶段", "陌生链接可能窃取账户信息。"),
            ("验证码和银行卡", "信息", ["验证码", "银行卡", "身份证", "支付密码"], ["理赔要求提供验证码"], ["银行本人在官方渠道操作"], 10, "信息索取阶段", "验证码可完成登录、绑卡或转账。"),
            ("会议软件共享屏幕", "控制", ["会议软件", "共享屏幕", "远程协助"], ["客服要求共享屏幕取消扣费"], ["企业内可信会议且不操作支付"], 10, "信息索取阶段", "共享屏幕会暴露验证码和支付过程。"),
        ],
        "flow_steps": ["陌生客服来电", "说出订单信息", "发理赔链接或会议号", "索要验证码/共享屏幕", "诱导转账或盗刷"],
        "psychology": ["信任官方", "退款期待", "时间压力", "信息不对称"],
        "sample_dialogue": "客服：不处理会自动扣费；用户：怎么取消？客服：打开会议软件，我指导你操作。",
        "badge": "客服识别者",
    },
    {
        "id": "scam_fake_police",
        "prefix": "police",
        "name": "冒充公检法诈骗",
        "operational_fraud_type": "冒充公检法诈骗",
        "aliases": ["安全账户", "涉案洗钱", "通缉令", "资金清查", "保密办案"],
        "description": "冒充公安、检察院、法院，以涉案、洗钱、通缉等制造恐惧，要求保密、共享屏幕或转入安全账户。",
        "target_users": ["学生", "中老年人", "独居用户", "银行卡资金较多用户"],
        "channels": ["陌生电话", "视频会议", "聊天软件", "伪造文书", "远程控制软件"],
        "risk_tags": ["冒充公检法", "要求垫付资金", "索要银行卡或身份信息", "索要验证码", "屏幕共享", "远程控制", "要求删除证据", "已发生转账"],
        "core_trick": "利用权威和恐惧控制用户，伪造警官证、通缉令和保密要求，切断用户与家人、银行、派出所的核实渠道。",
        "danger_action": "转入所谓安全账户、共享屏幕、提供银行卡密码或按对方要求保密",
        "immediate_action": "立即挂断电话，不转账，不共享屏幕，到就近派出所或拨打110核实。",
        "verification": "公检法不会电话远程办案，不存在安全账户，也不会要求保密转账或提供验证码。",
        "evidence": ["来电号码", "聊天账号", "伪造证件/文书", "会议记录", "转账账户", "威胁话术"],
        "reporting": "向110或派出所说明对方冒充公检法、要求保密、共享屏幕或安全账户转账。",
        "primary_choice": "所谓安全账户",
        "safe_choice": "挂断并到派出所核实",
        "case_amount": 52000,
        "case_channel": "陌生电话",
        "sample_user_text": "对方自称公安说我涉嫌洗钱，发了通缉令，让我保密并把钱转到安全账户。",
        "rule": {"all": ["冒充公检法"], "any": ["要求垫付资金", "屏幕共享", "远程控制", "索要银行卡或身份信息", "要求删除证据"], "min_any": 1, "score": 98, "goal": "stop_transfer"},
        "features": [
            ("涉案恐吓", "威胁", ["洗钱", "通缉", "涉案", "逮捕"], ["对方说用户涉嫌洗钱"], ["真实公安当面或正式程序通知"], 9, "初步接触阶段", "恐吓是冒充公检法的控制手段。"),
            ("保密办案", "隔离", ["保密", "不要告诉家人", "一直通话"], ["要求不能告诉任何人"], ["依法保密但不阻止向本地机关核实"], 10, "建立信任阶段", "保密要求用于切断外界劝阻。"),
            ("安全账户", "资金", ["安全账户", "资金清查", "证明清白"], ["要求把钱转入安全账户"], ["司法机关依法冻结账户不会让个人转账"], 10, "资金转账阶段", "安全账户不存在。"),
            ("远程办案控制", "控制", ["屏幕共享", "远程控制", "会议软件"], ["要求共享屏幕配合调查"], ["线下依法办案"], 10, "信息索取阶段", "远程控制会暴露账户和验证码。"),
        ],
        "flow_steps": ["陌生电话冒充机关", "制造涉案恐惧", "发送伪造文书", "要求保密和远程控制", "安全账户转账", "继续威胁或失联"],
        "psychology": ["恐惧", "权威服从", "隔离", "急迫感"],
        "sample_dialogue": "警官：你涉嫌洗钱，不能告诉任何人；用户：怎么证明？警官：把资金转入安全账户审查。",
        "badge": "公检法识别者",
    },
    {
        "id": "scam_romance",
        "prefix": "romance",
        "name": "杀猪盘诈骗",
        "operational_fraud_type": "杀猪盘诈骗",
        "aliases": ["网恋投资诈骗", "情感投资", "交友带单", "虚拟币恋爱骗局"],
        "description": "通过长期情感经营建立信任，再以投资、博彩、数字货币或共同未来为名诱导转账和充值。",
        "target_users": ["单身用户", "婚恋平台用户", "社交软件用户", "有理财需求用户"],
        "channels": ["婚恋平台", "社交软件", "短视频私信", "海外聊天软件", "投资App"],
        "risk_tags": ["陌生人引导", "高收益诱导", "保本稳赚承诺", "陌生投资平台", "诱导下载陌生APP", "要求垫付资金", "无法提现", "要求缴纳解冻费", "已发生转账"],
        "core_trick": "用高质量人设和情感陪伴建立关系，随后引导用户到陌生投资或博彩平台，盈利后提现受阻并继续缴费。",
        "danger_action": "跟随网恋对象向陌生平台充值、转虚拟币或为提现继续缴费",
        "immediate_action": "暂停联系和充值，找现实亲友共同核实，不再因关系压力转账。",
        "verification": "网络亲密关系中的投资建议必须脱离对方单独核验平台资质和资金去向。",
        "evidence": ["聊天记录", "对方身份包装", "投资链接", "充值地址", "提现失败截图", "转账凭证"],
        "reporting": "向警方说明交友过程、投资引导、平台名称、充值方式和提现受阻情况。",
        "primary_choice": "网恋对象带去陌生投资平台",
        "safe_choice": "停止充值并让现实亲友帮忙核实",
        "case_amount": 86700,
        "case_channel": "婚恋平台",
        "sample_user_text": "网恋对象说带我做虚拟币投资，平台一直盈利但提现要交保证金，他还劝我继续转钱。",
        "rule": {"all": ["陌生人引导", "陌生投资平台"], "any": ["高收益诱导", "保本稳赚承诺", "无法提现", "要求垫付资金", "要求缴纳解冻费"], "min_any": 1, "score": 94, "goal": "stop_transfer"},
        "features": [
            ("快速亲密关系", "信任", ["网恋", "对象", "未来", "亲密"], ["刚认识就建立恋爱关系"], ["现实可核验的正常交往"], 6, "建立信任阶段", "过快亲密可能是筛选目标。"),
            ("情感包装投资", "诱导", ["带你赚钱", "共同未来", "副业"], ["对方以未来规划劝投资"], ["亲友建议但不指定陌生平台"], 8, "引流诱导阶段", "投资建议被情感关系包装后更难拒绝。"),
            ("陌生平台充值", "资金", ["投资App", "虚拟币", "充值地址"], ["要求向陌生平台充币"], ["持牌渠道自主投资"], 9, "资金转账阶段", "平台可能由团伙控制。"),
            ("提现继续缴费", "收割", ["保证金", "税费", "流水", "解冻"], ["提现前要交保证金"], ["正规平台依法扣费不转私人账户"], 10, "提现受阻阶段", "提现受阻后继续缴费通常无法追回本金。"),
        ],
        "flow_steps": ["社交平台接触", "长期陪伴建立信任", "透露投资机会", "引导平台注册充值", "提现受阻继续缴费", "关系施压或失联"],
        "psychology": ["情感依赖", "信任迁移", "共同未来", "沉没成本"],
        "sample_dialogue": "对象：我们以后一起生活，先把这轮行情做完；客服：提现要补保证金。",
        "badge": "情感防线",
    },
    {
        "id": "scam_phishing",
        "prefix": "phishing",
        "name": "钓鱼链接诈骗",
        "operational_fraud_type": "钓鱼链接诈骗",
        "aliases": ["短信链接", "仿冒官网", "积分兑换", "ETC认证", "二维码钓鱼"],
        "description": "通过短信、私信、二维码或仿冒网页诱导点击，窃取账号密码、银行卡、身份证和验证码。",
        "target_users": ["网银用户", "车主", "快递用户", "社保用户", "所有移动端用户"],
        "channels": ["短信", "邮件", "二维码", "社交私信", "搜索广告"],
        "risk_tags": ["点击陌生链接", "索要验证码", "索要银行卡或身份信息", "诱导下载陌生APP", "冒充客服", "已发生转账"],
        "core_trick": "用积分过期、账户异常、补贴领取、ETC认证、快递理赔等紧急理由，让用户在仿冒页面提交敏感信息。",
        "danger_action": "点击陌生链接并输入银行卡、密码、身份证、验证码或下载安装包",
        "immediate_action": "关闭链接，不提交信息；如已填写，立即改密、冻结银行卡和关闭免密支付。",
        "verification": "通过官方App、官网手动输入域名或官方客服电话核实，不从短信链接进入。",
        "evidence": ["短信原文", "链接URL", "页面截图", "填写信息时间", "异常登录/扣款记录"],
        "reporting": "保留链接和页面证据，向平台、运营商或警方举报；涉及资金时立即联系银行。",
        "primary_choice": "陌生链接索要敏感信息",
        "safe_choice": "从官方App进入核实",
        "case_amount": 7600,
        "case_channel": "短信短链接",
        "sample_user_text": "短信说银行卡积分到期，链接进去要填身份证、银行卡和短信验证码。",
        "rule": {"all": ["点击陌生链接"], "any": ["索要验证码", "索要银行卡或身份信息", "诱导下载陌生APP"], "min_any": 1, "score": 90, "goal": "stop_code_leak"},
        "features": [
            ("紧急短信链接", "入口", ["积分到期", "账户异常", "ETC", "短链接"], ["短信称积分过期要点击链接"], ["官方App内通知"], 7, "初步接触阶段", "短信链接真实去向不透明。"),
            ("仿冒官网页面", "伪装", ["login", "verify", "security", "认证"], ["页面像银行官网但域名异常"], ["手动输入官网域名"], 8, "信息索取阶段", "仿冒页面常复制官方样式。"),
            ("敏感信息表单", "信息", ["身份证", "银行卡", "支付密码", "验证码"], ["页面要求填银行卡验证码"], ["官方安全环境内必要验证"], 10, "信息索取阶段", "敏感信息组合可直接盗刷。"),
            ("诱导安装包", "控制", ["安装包", "安全控件", "认证App"], ["链接下载所谓安全控件"], ["应用商店官方App"], 9, "信息索取阶段", "恶意App可能读取短信和控制设备。"),
        ],
        "flow_steps": ["发送短信/二维码", "仿冒官方页面", "诱导填写信息", "索要验证码或下载App", "盗刷/改密/二次诈骗"],
        "psychology": ["紧迫感", "官方信任", "福利诱惑", "技术迷惑"],
        "sample_dialogue": "短信：积分今日清零，请立即认证；页面：请输入银行卡和验证码完成领取。",
        "badge": "链接侦探",
    },
    {
        "id": "scam_code_theft",
        "prefix": "code",
        "name": "验证码/账户盗刷诈骗",
        "operational_fraud_type": "验证码/账户盗刷诈骗",
        "aliases": ["短信码诈骗", "动态码盗刷", "登录码索取", "人脸识别盗用"],
        "description": "以退款、验证身份、解除限制、账号核验等理由索要验证码、动态码、人脸识别或支付确认，进而登录、改密、绑卡或盗刷。",
        "target_users": ["支付平台用户", "网购用户", "学生", "游戏账号用户"],
        "channels": ["电话", "社交软件", "钓鱼页面", "冒充客服", "远程会议"],
        "risk_tags": ["索要验证码", "索要银行卡或身份信息", "点击陌生链接", "冒充客服", "屏幕共享", "远程控制", "已发生转账"],
        "core_trick": "把验证码伪装成退款确认、身份验证或账户安全码，诱导用户在短时间内发送或在共享屏幕下展示。",
        "danger_action": "把短信验证码、支付动态码、人脸识别或支付确认信息交给对方",
        "immediate_action": "不要发送任何验证码；如已发送，立即修改密码、解绑异常设备并冻结支付和银行卡。",
        "verification": "验证码只给本人在官方渠道使用，任何人以任何身份索要验证码都应拒绝。",
        "evidence": ["验证码短信", "索要验证码聊天", "异常登录提醒", "交易记录", "设备登录记录"],
        "reporting": "联系平台客服冻结账户、关闭快捷支付并报警说明验证码泄露时间和对方身份。",
        "primary_choice": "任何人索要验证码",
        "safe_choice": "绝不转发验证码",
        "case_amount": 9800,
        "case_channel": "冒充客服私聊",
        "sample_user_text": "陌生人说要验证我的账号信誉，催我60秒内把短信验证码发过去，还让我按要求做人脸识别。",
        "rule": {"all": ["索要验证码"], "any": ["冒充客服", "点击陌生链接", "索要银行卡或身份信息", "屏幕共享", "远程控制"], "min_any": 0, "score": 86, "goal": "stop_code_leak"},
        "features": [
            ("验证码索取", "信息", ["验证码", "短信码", "动态码"], ["对方要求把验证码发给他"], ["本人在官方App输入验证码"], 10, "信息索取阶段", "验证码可能直接授权登录或转账。"),
            ("倒计时催促", "施压", ["60秒", "过期", "马上", "超时"], ["客服催促验证码即将过期"], ["正常系统提示但不要求转发"], 7, "信息索取阶段", "倒计时让用户来不及核实。"),
            ("人脸识别远程指导", "身份", ["人脸识别", "眨眼", "张嘴", "认证"], ["对方指导做人脸识别"], ["本人自主在官方App认证"], 9, "信息索取阶段", "人脸识别可能用于开通账户或贷款。"),
            ("异常设备登录", "后果", ["异地登录", "设备绑定", "改密"], ["验证码后出现异地登录"], ["本人新设备登录"], 9, "信息泄露阶段", "验证码泄露后应立即封控账户。"),
        ],
        "flow_steps": ["冒充身份或发链接", "解释验证码用途", "倒计时催促", "获取验证码/人脸", "登录改密或盗刷"],
        "psychology": ["权威信任", "时间压力", "技术不熟悉", "退款期待"],
        "sample_dialogue": "客服：验证码只是退款确认，不会扣钱；用户：能给吗？客服：60秒内发来。",
        "badge": "验证码守门员",
    },
    {
        "id": "scam_screen_share",
        "prefix": "screen",
        "name": "屏幕共享/远程控制诈骗",
        "operational_fraud_type": "屏幕共享/远程控制诈骗",
        "aliases": ["会议软件诈骗", "远程协助", "共享屏幕盗刷", "远程控制手机"],
        "description": "以客服指导、贷款审核、账户修复、退款取消扣费等为名，诱导开启屏幕共享或远程控制以获取验证码和操作支付。",
        "target_users": ["网购用户", "贷款用户", "中老年人", "手机支付用户"],
        "channels": ["会议软件", "远程协助App", "电话指导", "冒充客服", "冒充公检法"],
        "risk_tags": ["屏幕共享", "远程控制", "索要验证码", "索要银行卡或身份信息", "诱导下载陌生APP", "冒充客服", "冒充公检法", "已发生转账"],
        "core_trick": "让用户以为对方只是在指导操作，实际通过共享屏幕看到验证码、银行卡余额、支付密码输入和交易确认。",
        "danger_action": "开启共享屏幕、允许远程控制或在共享状态下操作银行和支付软件",
        "immediate_action": "立即断开会议和远程控制，关闭支付App，修改密码并检查异常交易。",
        "verification": "官方客服不会要求用户共享屏幕操作银行卡、支付App或贷款App。",
        "evidence": ["会议号", "远程控制软件", "通话记录", "聊天记录", "验证码短信", "异常交易记录"],
        "reporting": "如已共享屏幕，联系银行和支付平台临时管控账户，并报警说明对方远程控制经过。",
        "primary_choice": "共享屏幕会暴露账户操作",
        "safe_choice": "立即停止共享并联系官方客服",
        "case_amount": 18400,
        "case_channel": "会议软件",
        "sample_user_text": "对方让我下载会议软件共享屏幕，说要帮我处理账户异常，我已经打开银行App了。",
        "rule": {"all": ["屏幕共享"], "any": ["远程控制", "索要验证码", "索要银行卡或身份信息", "冒充客服", "冒充公检法"], "min_any": 0, "score": 87, "goal": "stop_screen_share"},
        "features": [
            ("会议软件共享", "控制", ["共享屏幕", "会议软件", "屏幕共享"], ["对方要求打开会议软件共享屏幕"], ["可信会议中不展示敏感信息"], 10, "信息索取阶段", "共享屏幕可暴露全部操作。"),
            ("远程控制权限", "控制", ["远程控制", "远程协助", "控制手机"], ["允许对方远程控制电脑或手机"], ["企业IT内部授权维护"], 10, "信息索取阶段", "远程控制可能直接操作转账。"),
            ("共享中打开支付软件", "资金", ["银行App", "支付软件", "余额"], ["共享时打开银行App"], ["本人私下查看账户"], 9, "资金转账前阶段", "对方可看到余额和验证码。"),
            ("指导取消扣费", "身份", ["取消扣费", "会员", "保障", "退款"], ["客服指导取消百万保障"], ["官方App内自主关闭服务"], 8, "信息索取阶段", "取消扣费常被用作共享屏幕理由。"),
        ],
        "flow_steps": ["冒充客服或技术人员", "要求下载会议/远程软件", "引导共享屏幕", "指导打开支付/银行App", "查看验证码或诱导转账"],
        "psychology": ["技术依赖", "客服信任", "恐惧扣费", "远程便利"],
        "sample_dialogue": "客服：我远程帮你关闭扣费；用户：要打开银行App吗？客服：对，按我说的点。",
        "badge": "屏幕守护者",
    },
    {
        "id": "scam_acquaintance",
        "prefix": "acquaintance",
        "name": "冒充熟人诈骗",
        "operational_fraud_type": "冒充熟人诈骗",
        "aliases": ["冒充领导", "冒充老师", "冒充亲友", "盗号借钱", "AI换脸借钱"],
        "description": "盗用或仿冒领导、老师、亲友、同学身份，利用关系压力要求转账、代付或提供验证码。",
        "target_users": ["学生", "家长", "职场新人", "财务人员", "亲友关系用户"],
        "channels": ["社交软件", "短信", "邮箱", "群聊", "视频通话"],
        "risk_tags": ["陌生人引导", "要求垫付资金", "索要验证码", "索要银行卡或身份信息", "要求删除证据", "已发生转账"],
        "core_trick": "伪装成熟人或盗用账号，以开会、手机坏、急事、垫付款、住院等理由拒绝电话核验并催促转账。",
        "danger_action": "未通过原号码或当面核实就转账、代付或提供验证码",
        "immediate_action": "先通过原手机号、视频、共同联系人或当面核实身份，未核实前不转账。",
        "verification": "熟人转账必须使用已知联系方式二次确认，不接受新账号文字催促作为核验。",
        "evidence": ["新账号资料", "聊天记录", "转账截图", "对方收款账户", "拒绝通话理由"],
        "reporting": "联系真实本人确认账号是否被盗，已付款则保存证据报警并联系支付平台。",
        "primary_choice": "转账前未二次核验身份",
        "safe_choice": "通过原手机号或视频核实",
        "case_amount": 15000,
        "case_channel": "社交软件新账号",
        "sample_user_text": "领导新加我好友，说正在开会不方便电话，让我先给客户垫付一笔钱。",
        "rule": {"all": ["要求垫付资金"], "any": ["陌生人引导", "索要验证码", "索要银行卡或身份信息", "要求删除证据"], "min_any": 0, "score": 78, "goal": "stop_transfer"},
        "features": [
            ("新账号冒充熟人", "身份", ["新号", "领导", "老师", "亲友"], ["领导用新账号加好友"], ["真实熟人通过原渠道沟通"], 7, "初步接触阶段", "新账号身份必须核实。"),
            ("拒绝语音视频", "核验", ["开会", "手机坏", "不方便", "别打电话"], ["对方拒绝电话核实"], ["客观可验证的不便且可稍后核验"], 8, "建立信任阶段", "拒绝核验又催转账很危险。"),
            ("紧急垫付", "资金", ["垫付", "转给客户", "住院", "急用"], ["要求先垫付客户款"], ["已核实身份后的真实借款"], 9, "资金转账阶段", "关系压力会降低警惕。"),
            ("伪造到账截图", "欺骗", ["转账截图", "延迟到账", "备注错误"], ["发截图称已给你转账但未到账"], ["银行实际到账记录"], 8, "资金转账阶段", "截图不能代替真实到账。"),
        ],
        "flow_steps": ["新账号或盗号接触", "寒暄建立身份", "制造紧急事项", "拒绝电话核验", "要求代付转账", "继续催款或失联"],
        "psychology": ["熟人信任", "职务压力", "亲情压力", "不好意思核实"],
        "sample_dialogue": "领导：我在开会不方便电话，你先帮我转给客户；用户：稍后确认？领导：很急。",
        "badge": "身份核验者",
    },
    {
        "id": "scam_fake_shopping",
        "prefix": "shopping",
        "name": "虚假购物服务诈骗",
        "operational_fraud_type": "虚假购物服务诈骗",
        "aliases": ["低价购物", "虚假票务", "二手交易", "民宿预订", "维修服务保证金"],
        "description": "以低价商品、稀缺票务、二手交易、代购、民宿或服务为诱饵，诱导私下付款并不断追加费用。",
        "target_users": ["学生", "追星用户", "二手交易用户", "旅游用户", "低价购物用户"],
        "channels": ["二手平台", "社交群", "短视频评论", "票务群", "私域商家"],
        "risk_tags": ["陌生人引导", "要求垫付资金", "点击陌生链接", "私下交易", "无法提现", "要求缴纳解冻费", "已发生转账"],
        "core_trick": "利用低价和稀缺诱导脱离平台担保，先收定金、保证金、运费或实名费，付款后不发货或继续收费。",
        "danger_action": "脱离平台向个人账户付定金、保证金、手续费或解冻费",
        "immediate_action": "停止私下付款，坚持平台担保交易，核实商家资质和订单状态。",
        "verification": "商品、票务、民宿和服务交易优先走正规平台，付款前核验主体、评价和担保机制。",
        "evidence": ["商品/票务页面", "私聊记录", "收款码", "付款凭证", "物流/出票承诺", "对方身份信息"],
        "reporting": "通过交易平台投诉并报警，说明私下转账、未发货或继续收费过程。",
        "primary_choice": "私下转账缺少担保",
        "safe_choice": "坚持平台担保交易",
        "case_amount": 4200,
        "case_channel": "二手交易平台私聊",
        "sample_user_text": "卖家说演唱会票很便宜，但要我加私聊先转定金和保证金，不能走平台。",
        "rule": {"all": ["要求垫付资金"], "any": ["私下交易", "点击陌生链接", "陌生人引导", "无法提现", "要求缴纳解冻费"], "min_any": 1, "score": 78, "goal": "stop_transfer"},
        "features": [
            ("明显低价稀缺", "诱饵", ["低价", "内部票", "最后一张", "急出"], ["低价卖稀缺演唱会票"], ["正规平台活动折扣"], 6, "引流诱导阶段", "低价稀缺容易诱导冲动付款。"),
            ("脱离平台交易", "交易", ["私聊", "平台外", "微信转账", "个人账户"], ["卖家要求加私聊转定金"], ["平台担保订单"], 9, "资金转账阶段", "私下付款缺少保障。"),
            ("追加保证金", "资金", ["保证金", "实名费", "运费险", "解冻"], ["付款后又要保证金"], ["平台明确展示的合理费用"], 8, "资金转账阶段", "不断追加费用是收割信号。"),
            ("不发货不出票", "后果", ["不发货", "延迟", "系统冻结", "不能提现"], ["付款后称系统冻结要补款"], ["物流客观延迟可在平台查证"], 9, "损失发生阶段", "继续补款不会提高追回概率。"),
        ],
        "flow_steps": ["发布低价商品/票务", "诱导私聊", "要求定金或全款", "追加保证金/手续费", "不发货或拉黑"],
        "psychology": ["低价诱惑", "稀缺焦虑", "冲动决策", "平台规则不了解"],
        "sample_dialogue": "卖家：平台手续费高，私下便宜；用户：能走平台吗？卖家：不走，先转定金保留。",
        "badge": "交易守门员",
    },
]


def json_safe(value: Any) -> Any:
    if isinstance(value, ObjectId):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat(timespec="seconds")
    if isinstance(value, list):
        return [json_safe(item) for item in value]
    if isinstance(value, dict):
        return {key: json_safe(item) for key, item in value.items()}
    return value


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def feature_id(prefix: str, index: int) -> str:
    return f"FEA_{prefix.upper()}_{index:03d}"


def validate_tags(tags: Iterable[str], owner: str) -> None:
    invalid = sorted(set(tags) - VALID_RISK_FEATURES)
    if invalid:
        raise ValueError(f"{owner} contains invalid risk tags: {invalid}")


def build_scam_types() -> List[Dict[str, Any]]:
    records = []
    for item in SCAM_BLUEPRINTS:
        validate_tags(item["risk_tags"], item["id"])
        records.append(
            {
                "scam_type_id": item["id"],
                "name": item["name"],
                "operational_fraud_type": item["operational_fraud_type"],
                "aliases": item["aliases"],
                "description": item["description"],
                "target_users": item["target_users"],
                "common_channels": item["channels"],
                "default_risk_level": "高风险",
                "core_trick": item["core_trick"],
                "risk_tags": item["risk_tags"],
                "source_ids": ["SRC_CUSTOM_KB_20260519", "SRC_PUBLIC_ANTIFRAUD_TIPS"],
                "enabled": True,
                "created_at": BUILD_DATE,
                "updated_at": BUILD_DATE,
            }
        )
    return records


def build_scam_features() -> List[Dict[str, Any]]:
    records = []
    for item in SCAM_BLUEPRINTS:
        for index, spec in enumerate(item["features"], start=1):
            name, feature_type, keywords, examples, negative_examples, weight, stage, explanation = spec
            records.append(
                {
                    "feature_id": feature_id(item["prefix"], index),
                    "scam_type_id": item["id"],
                    "operational_fraud_type": item["operational_fraud_type"],
                    "feature_name": name,
                    "feature_type": feature_type,
                    "keywords": keywords,
                    "semantic_examples": examples,
                    "negative_examples": negative_examples,
                    "risk_weight": weight,
                    "stage": stage,
                    "explanation": explanation,
                    "source_ids": ["SRC_CUSTOM_KB_20260519", "SRC_PUBLIC_ANTIFRAUD_TIPS"],
                    "enabled": True,
                    "created_at": BUILD_DATE,
                    "updated_at": BUILD_DATE,
                }
            )
    return records


def build_scam_techniques(features: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    feature_map: Dict[str, List[str]] = {}
    for feature in features:
        feature_map.setdefault(feature["scam_type_id"], []).append(feature["feature_id"])

    records = []
    for item in SCAM_BLUEPRINTS:
        records.append(
            {
                "technique_id": f"TECH_{item['prefix'].upper()}_001",
                "scam_type_id": item["id"],
                "operational_fraud_type": item["operational_fraud_type"],
                "technique_name": f"{item['name']}标准推进流程",
                "flow_steps": item["flow_steps"],
                "psychology": item["psychology"],
                "related_features": feature_map[item["id"]],
                "intervention_points": [
                    "首次要求转账/充值/垫付时",
                    "首次索要验证码、银行卡、账号密码或人脸识别时",
                    "首次要求下载陌生App、共享屏幕或远程控制时",
                    "出现提现失败、解冻费、补单、保证金等继续收费理由时",
                ],
                "sample_dialogue": item["sample_dialogue"],
                "explanation": item["core_trick"],
                "source_ids": ["SRC_CUSTOM_KB_20260519", "SRC_PUBLIC_ANTIFRAUD_TIPS"],
                "enabled": True,
                "created_at": BUILD_DATE,
                "updated_at": BUILD_DATE,
            }
        )
    return records


def build_prevention_advice() -> List[Dict[str, Any]]:
    records = []
    for item in SCAM_BLUEPRINTS:
        records.append(
            {
                "advice_id": f"PREV_{item['prefix'].upper()}_HIGH_001",
                "scam_type_id": item["id"],
                "operational_fraud_type": item["operational_fraud_type"],
                "risk_level": "高风险",
                "stage": "资金转账前阶段/信息索取阶段/提现受阻阶段",
                "immediate_action": item["immediate_action"],
                "do_not": [
                    "不要继续转账、充值、补单、缴纳保证金或解冻费",
                    "不要提供验证码、支付密码、银行卡、身份证照片或人脸识别",
                    "不要开启屏幕共享、远程控制或下载对方指定App",
                    "不要按对方要求删除聊天记录或退出群聊",
                ],
                "verification_method": item["verification"],
                "evidence_to_keep": item["evidence"],
                "reporting_advice": item["reporting"],
                "response_template": f"这是{item['name']}的高风险场景。{item['immediate_action']}核实方式：{item['verification']}",
                "source_ids": ["SRC_CUSTOM_KB_20260519", "SRC_PUBLIC_ANTIFRAUD_TIPS"],
                "enabled": True,
                "created_at": BUILD_DATE,
                "updated_at": BUILD_DATE,
            }
        )
    return records


def build_typical_cases(features: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    feature_map: Dict[str, List[str]] = {}
    for feature in features:
        feature_map.setdefault(feature["scam_type_id"], []).append(feature["feature_name"])

    records = []
    blueprint_map = {item["prefix"]: item for item in SCAM_BLUEPRINTS}
    source_map = {source["source_id"]: source for source in SOURCE_REFERENCES}
    for case in OFFICIAL_CASES:
        item = blueprint_map[case["prefix"]]
        first_source = source_map[case["source_ids"][0]]
        records.append(
            {
                "case_id": case["case_id"],
                "title": case["title"],
                "scam_type_id": item["id"],
                "operational_fraud_type": item["operational_fraud_type"],
                "victim_profile": {
                    "group": case["victim_group"],
                    "privacy": "警方公开案例已按项目规则摘要化，不保存姓名、手机号、身份证、银行卡等直接身份信息",
                },
                "amount_loss": case["amount_loss"],
                "amount_note": case["amount_note"],
                "channel": case["channel"],
                "timeline": [
                    {"step": index + 1, "event": event}
                    for index, event in enumerate(case["timeline"])
                ],
                "matched_features": feature_map[item["id"]],
                "lesson": case["lesson"],
                "source_ids": case["source_ids"],
                "source_case_no": case["source_case_no"],
                "source_title": first_source["title"],
                "source_url": first_source["url"],
                "source_publisher": first_source["publisher"],
                "source_publish_date": first_source["publish_date"],
                "authenticity_level": "official_public_case",
                "public_status": "public_official_summary",
                "created_at": BUILD_DATE,
                "updated_at": BUILD_DATE,
            }
        )
    return records


def make_knowledge(
    item: Dict[str, Any],
    suffix: str,
    knowledge_type: str,
    route: str,
    case_type: int,
    goals: List[str],
    fraud_stage: str,
    title: str,
    summary: str,
    content: str,
    user_stage: str,
    use_when: str,
    do_not_use_when: str,
    answer_role: str,
    priority: int,
    risk_level: str = "高风险",
) -> Dict[str, Any]:
    return {
        "knowledge_id": f"{item['prefix']}_{suffix}",
        "knowledge_type": knowledge_type,
        "fraud_type": item["operational_fraud_type"],
        "fraud_stage": fraud_stage,
        "title": title,
        "summary": summary,
        "content": content,
        "risk_tags": item["risk_tags"],
        "applicable_routes": [route],
        "applicable_case_types": [case_type],
        "intervention_goals": goals,
        "user_stage": user_stage,
        "use_when": use_when,
        "do_not_use_when": do_not_use_when,
        "answer_role": answer_role,
        "priority": priority,
        "risk_level": risk_level,
        "source": SOURCE_TEXT,
    }


def build_anti_fraud_knowledge() -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    for item in SCAM_BLUEPRINTS:
        name = item["name"]
        official_case = OFFICIAL_CASE_BY_PREFIX.get(item["prefix"])
        records.extend(
            [
                make_knowledge(
                    item,
                    "definition_001",
                    "fraud_definition",
                    "education",
                    3,
                    ["educate"],
                    "科普学习",
                    f"什么是{name}",
                    f"{name}的定义、入口和核心风险。",
                    f"{name}通常通过{', '.join(item['channels'][:3])}等渠道接触用户。它的核心套路是：{item['core_trick']}识别时不要只看对方身份包装，而要看是否要求用户{item['danger_action']}。",
                    "用户没有具体正在发生的风险，只是学习概念",
                    f"用户问什么是{name}、有哪些套路、为什么危险。",
                    "用户正在被催促转账、给验证码或共享屏幕时，应优先使用劝阻和止损知识。",
                    "解释诈骗定义和核心机制。",
                    76,
                    "不适用",
                ),
                make_knowledge(
                    item,
                    "process_001",
                    "fraud_process",
                    "education",
                    3,
                    ["educate"],
                    "科普学习",
                    f"{name}的一般流程",
                    "从接触、建立信任、提出危险动作到收割的完整流程。",
                    "常见流程包括：" + "；".join(item["flow_steps"]) + f"。每一步都可能包装成合理业务，但只要进入{item['danger_action']}，就应按高风险处理。",
                    "用户想理解完整骗局阶段",
                    f"用户问{name}一般如何推进、每一步有什么信号。",
                    "用户已经受损时，应先给银行止付、证据保存和报警指引。",
                    "帮助用户理解诈骗推进路径。",
                    74,
                    "不适用",
                ),
                make_knowledge(
                    item,
                    "risk_signal_001",
                    "risk_signal",
                    "prevention_consult",
                    1,
                    [item["rule"]["goal"]],
                    "资金转账前阶段",
                    f"{name}的高危识别信号",
                    f"命中{item['primary_choice']}等信号时，应立即暂停。",
                    f"{name}的高危信号包括：{', '.join(item['risk_tags'])}。其中最需要立即阻断的是{item['danger_action']}。如果对方同时制造限时、恐吓、保本、退款、资质包装或熟人关系压力，不应继续跟着对方操作。",
                    "尚未确认损失，但已经出现危险要求",
                    "用户正在判断对方要求是否安全，或准备进行下一步危险操作。",
                    "用户已经明确转账或泄露信息时，应补充止损流程。",
                    "指出命中的风险特征并阻断下一步动作。",
                    94,
                    "高风险",
                ),
                make_knowledge(
                    item,
                    "prevention_advice_001",
                    "prevention_advice",
                    "prevention_consult",
                    1,
                    [item["rule"]["goal"]],
                    "资金转账前阶段",
                    f"{name}的防范建议",
                    item["immediate_action"],
                    f"当前最稳妥的动作是：{item['immediate_action']}核验方式：{item['verification']}不要因为对方承诺返利、理赔、放款、收益、身份权威或关系压力就继续操作。",
                    "用户还在判断是否继续",
                    "用户尚未受损，需要一组马上能执行的防范动作。",
                    "用户已经转账后，不应只给一般防范。",
                    "给出明确、可执行的防范动作。",
                    92,
                    "高风险",
                ),
                make_knowledge(
                    item,
                    "intervention_action_001",
                    "intervention_action",
                    "loss_response",
                    2,
                    ["call_police", "preserve_evidence", "call_bank"],
                    "损失发生阶段",
                    f"{name}已发生后的止损动作",
                    "已经转账、泄露或无法提现时，第一步是停止新增操作。",
                    f"如果已经发生转账、泄露验证码/账户信息、开启过屏幕共享或遇到不能提现，立即停止和对方继续沟通，不再补交任何费用。{item['reporting']}同时保留证据：{', '.join(item['evidence'])}。",
                    "用户已经转账、泄露信息或资金可能受损",
                    "用户问已经被骗怎么办、钱还能不能追回、是否继续缴费。",
                    "用户只是学习或尚未操作时，不应渲染已经受损。",
                    "给出第一优先级止损动作。",
                    98,
                    "高风险",
                ),
                make_knowledge(
                    item,
                    "evidence_guide_001",
                    "evidence_guide",
                    "loss_response",
                    2,
                    ["preserve_evidence", "call_police"],
                    "止损报警阶段",
                    f"{name}证据保存清单",
                    "证据越完整，越有利于止付、冻结和报案。",
                    f"建议保存：{', '.join(item['evidence'])}。保存时尽量保留原始聊天、完整截图、时间线、账号ID和转账流水，不要按对方要求删除记录、退群或清空App。",
                    "用户准备报警、投诉或联系银行",
                    "用户已经受损或可能泄露信息，需要知道保存哪些材料。",
                    "用户只是泛泛学习时可以简化。",
                    "列出证据清单。",
                    94,
                    "高风险",
                ),
                make_knowledge(
                    item,
                    "police_report_guide_001",
                    "police_report_guide",
                    "loss_response",
                    2,
                    ["call_police", "preserve_evidence"],
                    "止损报警阶段",
                    f"{name}报警时怎么说",
                    "报警时按时间线说明接触方式、对方要求、付款方式和证据。",
                    f"可以这样说：我疑似遭遇{name}，通过{item['case_channel']}接触对方，对方要求我{item['danger_action']}。我现在保存了{', '.join(item['evidence'][:4])}等证据，请帮我登记并协助止付。说明时按时间顺序讲清金额、账户、链接、App和对方身份。",
                    "用户准备报警或需要报案话术",
                    "用户问报警怎么讲、需要准备什么。",
                    "用户尚未受损时，不要把报警作为唯一动作。",
                    "提供报案表达和案情整理框架。",
                    95,
                    "高风险",
                ),
                make_knowledge(
                    item,
                    "bank_stop_guide_001",
                    "bank_stop_guide",
                    "loss_response",
                    2,
                    ["call_bank", "call_police"],
                    "止损报警阶段",
                    f"{name}银行或支付止付指引",
                    "资金刚转出或账户信息泄露时，应同步联系银行和支付平台。",
                    f"如果刚发生付款或验证码、银行卡、屏幕信息可能泄露，马上联系银行、支付平台或发卡行，说明疑似{name}，提供转账时间、金额、收款账户、交易流水号，并请求止付、冻结、限额、挂失或关闭快捷支付。银行处理不能替代报警，两边应同时进行。",
                    "用户刚转账或账户可能被盗刷",
                    "用户问如何止损、银行卡是否安全、钱能不能拦截。",
                    "用户没有资金或账户风险时，不应要求无谓冻结全部账户。",
                    "指导联系银行和支付平台保护账户。",
                    93,
                    "高风险",
                ),
                make_knowledge(
                    item,
                    "persuasion_script_001",
                    "persuasion_script",
                    "prevention_consult",
                    1,
                    [item["rule"]["goal"]],
                    "资金转账前阶段",
                    f"{name}劝阻话术",
                    "用于帮助用户拒绝对方继续诱导。",
                    f"可以直接回复：我不会继续{item['danger_action']}，也不会提供验证码、银行卡、身份证、人脸识别或屏幕共享。我要通过官方渠道或线下方式核实，核实前不要再联系我。若对方继续催促、威胁、承诺返还或要求删除记录，我会保留证据并报警咨询。",
                    "用户仍在被对方催促或需要拒绝话术",
                    "用户问该怎么回复对方、怎么劝家人停手。",
                    "用户已经受损时，话术不能替代止付和报警。",
                    "提供可直接使用的拒绝表达。",
                    86,
                    "高风险",
                ),
                make_knowledge(
                    item,
                    "case_001",
                    "fraud_case",
                    "education",
                    3,
                    ["educate"],
                    "科普学习",
                    f"{name}警方公开案例复盘",
                    "警方公开案例说明骗局如何从普通接触升级为资金或信息风险。",
                    (
                        f"{official_case['title']}。案例来源：{official_case['source_case_no']}，{official_case['amount_note']}。"
                        f"过程包括：{'；'.join(official_case['timeline'])}。复盘重点是：{official_case['lesson']}"
                        if official_case
                        else f"某{item['target_users'][0]}通过{item['case_channel']}接触到对方。对方先用{item['primary_choice']}降低警惕，随后要求{item['danger_action']}，最终造成约{item['case_amount']}元损失或账户风险。复盘重点是：只要对方开始要求资金、验证码、账号密码、屏幕共享或陌生App操作，就应停止并核实。"
                    ),
                    "用户希望通过案例学习",
                    "用户问有没有类似案例、这种骗局怎么发生。",
                    "用户正在被催促操作时，应优先劝阻。",
                    "用案例增强理解和说服力。",
                    72,
                    "不适用",
                ),
                make_knowledge(
                    item,
                    "education_summary_001",
                    "education_summary",
                    "education",
                    3,
                    ["educate"],
                    "科普学习",
                    f"{name}学习总结",
                    "总结识别口诀、核验方式和底线动作。",
                    f"记住三条底线：第一，凡是让你{item['danger_action']}的，都先停；第二，凡是索要验证码、银行卡、身份证、人脸识别、账号密码或屏幕共享的，都拒绝；第三，凡是绕开官方平台、要求保密、删除证据、继续补费解冻的，都按高风险处理。核验方式是：{item['verification']}",
                    "用户完成学习或需要简短总结",
                    "用户问如何记住、防范重点是什么。",
                    "用户已经受损时应优先止损。",
                    "形成可迁移的防骗原则。",
                    70,
                    "不适用",
                ),
            ]
        )
    return records


def build_risk_rules() -> List[Dict[str, Any]]:
    records = []
    for item in SCAM_BLUEPRINTS:
        rule = item["rule"]
        validate_tags(rule["all"] + rule["any"], f"rule:{item['id']}")
        rule_id = f"RULE_{item['prefix'].upper()}_CORE_001"
        records.append(
            {
                "rule_id": rule_id,
                "rule_name": f"{item['name']}核心高危规则",
                "fraud_type": item["operational_fraud_type"],
                "stages": ["引流诱导阶段", "信息索取阶段", "资金转账前阶段", "资金转账阶段", "提现受阻阶段", "损失发生阶段"],
                "conditions": {"all": rule["all"], "any": rule["any"], "min_any": rule["min_any"]},
                "risk_score": rule["score"],
                "score": rule["score"],
                "risk_level": "高风险",
                "intervention_goal": rule["goal"],
                "explanation": f"同时命中{item['name']}的核心条件：{', '.join(rule['all'])}，并出现{', '.join(rule['any'])}中的至少{rule['min_any']}项。",
                "suggested_action": item["immediate_action"],
                "enabled": True,
                "source": SOURCE_TEXT,
                "created_at": BUILD_DATE,
                "updated_at": BUILD_DATE,
            }
        )

    extra_rules = [
        {
            "rule_id": "RULE_COMMON_WITHDRAWAL_FEE_001",
            "rule_name": "提现受阻继续收费规则",
            "fraud_type": "虚假投资理财诈骗",
            "stages": ["提现受阻阶段", "损失发生阶段"],
            "conditions": {"all": ["无法提现", "要求缴纳解冻费"], "any": ["高收益诱导", "陌生投资平台", "要求垫付资金"], "min_any": 1},
            "risk_score": 97,
            "score": 97,
            "risk_level": "高风险",
            "intervention_goal": "stop_transfer",
            "explanation": "不能提现后要求继续缴纳税费、保证金、解冻费，是虚假平台扩大损失的典型节点。",
            "suggested_action": "不要再为提现缴纳任何费用，保存平台页面和转账记录，尽快止付并报警。",
            "enabled": True,
            "source": SOURCE_TEXT,
            "created_at": BUILD_DATE,
            "updated_at": BUILD_DATE,
        },
        {
            "rule_id": "RULE_COMMON_CODE_SCREEN_001",
            "rule_name": "验证码叠加屏幕共享规则",
            "fraud_type": "屏幕共享/远程控制诈骗",
            "stages": ["信息索取阶段", "信息泄露阶段"],
            "conditions": {"all": ["索要验证码"], "any": ["屏幕共享", "远程控制", "冒充客服", "点击陌生链接"], "min_any": 1},
            "risk_score": 90,
            "score": 90,
            "risk_level": "高风险",
            "intervention_goal": "stop_code_leak",
            "explanation": "验证码与屏幕共享或远程指导同时出现，可能导致登录、绑卡、盗刷或转账授权。",
            "suggested_action": "立即停止共享屏幕，不提供验证码，修改密码并检查账户异常。",
            "enabled": True,
            "source": SOURCE_TEXT,
            "created_at": BUILD_DATE,
            "updated_at": BUILD_DATE,
        },
        {
            "rule_id": "RULE_BRUSH_LOSS_POLICE_001",
            "rule_name": "刷单已转账仍被要求补单规则",
            "fraud_type": "刷单返利诈骗",
            "stages": ["提现受阻阶段", "损失发生阶段", "止损报警阶段"],
            "conditions": {"all": ["已发生转账", "要求继续补单"], "any": ["任务返佣", "要求垫付资金", "无法提现", "要求缴纳解冻费"], "min_any": 1},
            "risk_score": 98,
            "score": 98,
            "risk_level": "高风险",
            "intervention_goal": "call_police",
            "explanation": "刷单场景中已发生转账后又被要求继续补单，说明已经进入损失扩大阶段，应立即止付并报警。",
            "suggested_action": "不要继续补单或缴费，保留聊天、App、转账凭证和收款账户，马上联系银行/支付平台止付并报警。",
            "enabled": True,
            "source": SOURCE_TEXT,
            "created_at": BUILD_DATE,
            "updated_at": BUILD_DATE,
        },
        {
            "rule_id": "RULE_COMMON_DELETE_EVIDENCE_001",
            "rule_name": "要求删除证据或保密规则",
            "fraud_type": "冒充公检法诈骗",
            "stages": ["建立信任阶段", "资金转账阶段", "止损报警阶段"],
            "conditions": {"all": ["要求删除证据"], "any": ["冒充公检法", "要求垫付资金", "已发生转账"], "min_any": 1},
            "risk_score": 93,
            "score": 93,
            "risk_level": "高风险",
            "intervention_goal": "preserve_evidence",
            "explanation": "要求保密、删除记录或不报警，通常是阻断外界劝阻和证据保存。",
            "suggested_action": "不要删除任何记录，截图保存证据，立即通过官方渠道核实或报警。",
            "enabled": True,
            "source": SOURCE_TEXT,
            "created_at": BUILD_DATE,
            "updated_at": BUILD_DATE,
        },
    ]
    records.extend(extra_rules)
    return records


def build_game_levels() -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    level_id = 1
    for item in SCAM_BLUEPRINTS:
        specs = [
            (
                f"{item['name']}识别",
                item["sample_user_text"],
                "这段场景中最关键的风险点是什么？",
                [item["primary_choice"], "对方说话很礼貌", "金额看起来不大", "只是普通咨询"],
                item["primary_choice"],
                f"关键风险点是{item['primary_choice']}，它会把普通沟通升级为资金或账户风险。",
            ),
            (
                f"{item['name']}处置",
                f"你正在遇到类似场景，对方催你继续{item['danger_action']}。",
                "现在最安全的处理方式是什么？",
                [item["safe_choice"], "继续按对方说的做", "先转小额试试", "删除聊天记录"],
                item["safe_choice"],
                item["immediate_action"],
            ),
            (
                f"{item['name']}证据",
                f"你已经发现异常，准备求助。可保存的关键证据包括：{', '.join(item['evidence'][:3])}。",
                "为什么要先保存证据？",
                ["便于止付、投诉和报警研判", "为了继续和对方谈判", "为了证明自己胆子大", "保存证据没有用"],
                "便于止付、投诉和报警研判",
                "完整证据能帮助银行、平台和警方确认时间线、账号和资金流向。",
            ),
        ]
        for title, scenario, question, options, answer, explanation in specs:
            records.append(
                {
                    "level_id": level_id,
                    "title": title,
                    "scenario": scenario,
                    "question": question,
                    "options": options,
                    "answer": answer,
                    "points": 10,
                    "badge": item["badge"],
                    "explanation": explanation,
                    "scam_type_id": item["id"],
                    "fraud_type": item["operational_fraud_type"],
                    "enabled": True,
                }
            )
            level_id += 1
    return records


def build_test_cases() -> List[Dict[str, Any]]:
    records = []
    for index, item in enumerate(SCAM_BLUEPRINTS, start=1):
        records.append(
            {
                "case_id": f"RISK_CASE_{index:03d}",
                "user_text": item["sample_user_text"],
                "expected_scam_type": item["operational_fraud_type"],
                "expected_features_any": item["rule"]["all"] + item["rule"]["any"],
                "expected_risk_score_min": min(80, item["rule"]["score"] - 10),
                "expected_intervention_goal": item["rule"]["goal"],
                "source": SOURCE_TEXT,
                "enabled": True,
            }
        )
    records.extend(
        [
            {
                "case_id": "RISK_CASE_COMMON_014",
                "user_text": "我还没转钱，但对方一直催我共享屏幕看验证码。",
                "expected_scam_type": "屏幕共享/远程控制诈骗",
                "expected_features_any": ["屏幕共享", "索要验证码"],
                "expected_risk_score_min": 80,
                "expected_intervention_goal": "stop_screen_share",
                "source": SOURCE_TEXT,
                "enabled": True,
            },
            {
                "case_id": "RISK_CASE_COMMON_015",
                "user_text": "我已经给刷单平台转了3000元，现在客服说必须继续补单才能退本金。",
                "expected_scam_type": "刷单返利诈骗",
                "expected_features_any": ["已发生转账", "要求继续补单", "任务返佣", "要求垫付资金"],
                "expected_risk_score_min": 90,
                "expected_intervention_goal": "call_police",
                "source": SOURCE_TEXT,
                "enabled": True,
            },
        ]
    )
    return records


def build_rag_docs_and_chunks(
    knowledge: List[Dict[str, Any]],
    laws: List[Dict[str, Any]],
    cases: List[Dict[str, Any]],
) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    docs: List[Dict[str, Any]] = []
    chunks: List[Dict[str, Any]] = []
    for item in knowledge:
        doc_id = f"DOC_{item['knowledge_id']}"
        text = "\n".join(
            [
                f"标题：{item['title']}",
                f"诈骗类型：{item['fraud_type']}",
                f"阶段：{item['fraud_stage']}",
                f"摘要：{item['summary']}",
                f"内容：{item['content']}",
                f"风险标签：{', '.join(item['risk_tags'])}",
            ]
        )
        docs.append(
            {
                "doc_id": doc_id,
                "title": item["title"],
                "doc_type": item["knowledge_type"],
                "source_id": "SRC_CUSTOM_KB_20260519",
                "full_text": text,
                "tags": item["risk_tags"],
                "related_scam_type": item["fraud_type"],
                "created_at": BUILD_DATE,
                "updated_at": BUILD_DATE,
            }
        )
        chunks.append(
            {
                "chunk_id": f"CHUNK_{item['knowledge_id']}_001",
                "document_id": doc_id,
                "chunk_index": 1,
                "chunk_text": text,
                "related_scam_type": item["fraud_type"],
                "related_features": item["risk_tags"],
                "summary": item["summary"],
                "embedding_status": "mirrored_to_milvus_via_anti_fraud_knowledge",
                "created_at": BUILD_DATE,
                "updated_at": BUILD_DATE,
            }
        )
    for law in laws:
        doc_id = f"DOC_{law['law_id']}"
        original_text = law.get("original_text") or law.get("original_text_excerpt") or ""
        text = "\n".join(
            [
                f"法律：{law['law_name']} {law['article_no']}",
                f"原文：{original_text}",
                f"摘要：{law['plain_summary']}",
                f"相关行为：{', '.join(law['related_behaviors'])}",
                f"注意：{law['caution']}",
            ]
        )
        docs.append(
            {
                "doc_id": doc_id,
                "title": f"{law['law_name']} {law['article_no']}",
                "doc_type": "law_clause",
                "source_id": law["source_id"],
                "full_text": text,
                "tags": law["related_behaviors"],
                "related_scam_type": law["related_scam_types"],
                "created_at": BUILD_DATE,
                "updated_at": BUILD_DATE,
            }
        )
        chunks.append(
            {
                "chunk_id": f"CHUNK_{law['law_id']}_001",
                "document_id": doc_id,
                "chunk_index": 1,
                "chunk_text": text,
                "related_scam_type": law["related_scam_types"],
                "related_features": law["related_behaviors"],
                "summary": law["plain_summary"],
                "embedding_status": "metadata_only",
                "created_at": BUILD_DATE,
                "updated_at": BUILD_DATE,
            }
        )
    for case in cases:
        doc_id = f"DOC_{case['case_id']}"
        timeline_text = "\n".join(
            f"{item['step']}. {item['event']}" for item in case.get("timeline", [])
        )
        text = "\n".join(
            [
                f"标题：{case['title']}",
                f"诈骗类型：{case['operational_fraud_type']}",
                f"公开来源：{case.get('source_title', '')}",
                f"来源链接：{case.get('source_url', '')}",
                f"案例编号：{case.get('source_case_no', '')}",
                f"损失金额：{case.get('amount_note', case.get('amount_loss', ''))}",
                f"接触渠道：{case.get('channel', '')}",
                f"过程：\n{timeline_text}",
                f"防范教训：{case.get('lesson', '')}",
            ]
        )
        docs.append(
            {
                "doc_id": doc_id,
                "title": case["title"],
                "doc_type": "official_case",
                "source_id": case["source_ids"][0],
                "full_text": text,
                "tags": case["matched_features"],
                "related_scam_type": case["operational_fraud_type"],
                "created_at": BUILD_DATE,
                "updated_at": BUILD_DATE,
            }
        )
        chunks.append(
            {
                "chunk_id": f"CHUNK_{case['case_id']}_001",
                "document_id": doc_id,
                "chunk_index": 1,
                "chunk_text": text,
                "related_scam_type": case["operational_fraud_type"],
                "related_features": case["matched_features"],
                "summary": case["lesson"],
                "embedding_status": "official_case_rag",
                "created_at": BUILD_DATE,
                "updated_at": BUILD_DATE,
            }
        )
    return docs, chunks


def build_seed_bundle() -> Dict[str, List[Dict[str, Any]]]:
    source_references: List[Dict[str, Any]] = []
    for ref in SOURCE_REFERENCES:
        doc = dict(ref)
        if not doc.get("url"):
            doc["url"] = "internal://anti-fraud-knowledge"
        if not doc.get("publish_date"):
            doc["publish_date"] = "various"
        raw = json.dumps(doc, ensure_ascii=False, sort_keys=True)
        doc["content_hash"] = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        source_references.append(doc)

    law_clauses: List[Dict[str, Any]] = []
    for law in LAW_CLAUSES:
        doc = dict(law)
        if not doc.get("effective_date"):
            doc["effective_date"] = "现行有效，具体以官方公布版本为准"
        law_clauses.append(doc)

    scam_types = build_scam_types()
    scam_features = build_scam_features()
    scam_techniques = build_scam_techniques(scam_features)
    prevention_advice = build_prevention_advice()
    typical_cases = build_typical_cases(scam_features)
    knowledge = build_anti_fraud_knowledge()
    risk_rules = build_risk_rules()
    game_levels = build_game_levels()
    test_cases = build_test_cases()
    rag_documents, rag_chunks = build_rag_docs_and_chunks(knowledge, law_clauses, typical_cases)

    return {
        "source_references": source_references,
        "scam_types": scam_types,
        "scam_features": scam_features,
        "scam_techniques": scam_techniques,
        "prevention_advice": prevention_advice,
        "typical_cases": typical_cases,
        "law_clauses": law_clauses,
        "rag_documents": rag_documents,
        "rag_chunks": rag_chunks,
        "anti_fraud_knowledge": knowledge,
        "risk_rules": risk_rules,
        "game_levels": game_levels,
        "test_cases": test_cases,
    }


def backup_mongo(db, backup_dir: Path) -> None:
    backup_dir.mkdir(parents=True, exist_ok=True)
    for name in sorted(db.list_collection_names()):
        docs = list(db[name].find({}))
        write_json(backup_dir / f"{name}.json", json_safe(docs))


def reset_mongo(db) -> None:
    for name in sorted(db.list_collection_names()):
        db.drop_collection(name)


def create_indexes(db) -> None:
    db["source_references"].create_index([("source_id", ASCENDING)], unique=True)
    db["scam_types"].create_index([("scam_type_id", ASCENDING)], unique=True)
    db["scam_types"].create_index([("operational_fraud_type", ASCENDING)])
    db["scam_features"].create_index([("feature_id", ASCENDING)], unique=True)
    db["scam_features"].create_index([("scam_type_id", ASCENDING), ("risk_weight", DESCENDING)])
    db["scam_techniques"].create_index([("technique_id", ASCENDING)], unique=True)
    db["scam_techniques"].create_index([("scam_type_id", ASCENDING)])
    db["prevention_advice"].create_index([("advice_id", ASCENDING)], unique=True)
    db["prevention_advice"].create_index([("scam_type_id", ASCENDING), ("risk_level", ASCENDING)])
    db["typical_cases"].create_index([("case_id", ASCENDING)], unique=True)
    db["typical_cases"].create_index([("scam_type_id", ASCENDING), ("amount_loss", DESCENDING)])
    db["law_clauses"].create_index([("law_id", ASCENDING)], unique=True)
    db["law_clauses"].create_index([("related_scam_types", ASCENDING)])
    db["rag_documents"].create_index([("doc_id", ASCENDING)], unique=True)
    db["rag_documents"].create_index([("doc_type", ASCENDING), ("related_scam_type", ASCENDING)])
    db["rag_chunks"].create_index([("chunk_id", ASCENDING)], unique=True)
    db["rag_chunks"].create_index([("document_id", ASCENDING), ("chunk_index", ASCENDING)])
    db["anti_fraud_knowledge"].create_index([("knowledge_id", ASCENDING)], unique=True)
    db["anti_fraud_knowledge"].create_index([("fraud_type", ASCENDING), ("knowledge_type", ASCENDING)])
    db["anti_fraud_knowledge"].create_index([("risk_level", ASCENDING), ("priority", DESCENDING)])
    db["risk_rules"].create_index([("rule_id", ASCENDING)], unique=True)
    db["risk_rules"].create_index([("fraud_type", ASCENDING), ("enabled", ASCENDING)])
    db["game_levels"].create_index([("level_id", ASCENDING)], unique=True)
    db["test_cases"].create_index([("case_id", ASCENDING)], unique=True)
    db["audit_logs"].create_index([("created_at", DESCENDING)])
    db["chat_message"].create_index([("session_id", ASCENDING), ("created_at", ASCENDING)])
    db["anti_fraud_case_state"].create_index([("session_id", ASCENDING)], unique=True, sparse=True)
    db["report_tickets"].create_index([("report_id", ASCENDING)], unique=True)
    db["user_profiles"].create_index([("user_id", ASCENDING)], unique=True)
    db["user_game_progress"].create_index([("user_id", ASCENDING)], unique=True)
    db["badge_records"].create_index([("user_id", ASCENDING), ("badge", ASCENDING)], unique=True)


def insert_bundle(db, bundle: Dict[str, List[Dict[str, Any]]]) -> Dict[str, int]:
    create_indexes(db)
    counts: Dict[str, int] = {}
    for collection, docs in bundle.items():
        if docs:
            db[collection].insert_many(docs, ordered=False)
        counts[collection] = len(docs)

    empty_runtime_collections = [
        "report_tickets",
        "user_profiles",
        "user_game_progress",
        "badge_records",
        "audit_logs",
        "chat_message",
        "anti_fraud_case_state",
    ]
    for name in empty_runtime_collections:
        db[name].insert_one({"_created_marker": True, "created_at": BUILD_DATE})
        db[name].delete_many({"_created_marker": True})
        counts.setdefault(name, 0)
    return counts


def write_seed_files(bundle: Dict[str, List[Dict[str, Any]]]) -> None:
    write_json(KNOWLEDGE_PATH, bundle["anti_fraud_knowledge"])
    write_json(RULES_PATH, bundle["risk_rules"])
    write_json(GAME_LEVELS_PATH, bundle["game_levels"])
    write_json(TEST_CASES_PATH, bundle["test_cases"])
    write_json(STRUCTURED_SEED_PATH, bundle)


def validate_runtime_knowledge(records: List[Dict[str, Any]]) -> None:
    from app.anti_fraud.schema import (
        FRAUD_STAGES,
        FRAUD_TYPES,
        INTERVENTION_GOALS,
        KNOWLEDGE_TYPES,
        REQUIRED_KNOWLEDGE_FIELDS,
        RISK_FEATURES,
        RISK_LEVELS,
        ROUTES,
    )

    seen = set()
    for index, item in enumerate(records, start=1):
        missing = [field for field in REQUIRED_KNOWLEDGE_FIELDS if item.get(field) in (None, "", [])]
        if missing:
            raise ValueError(f"knowledge record {index} missing fields: {missing}")
        if item["knowledge_id"] in seen:
            raise ValueError(f"duplicate knowledge_id: {item['knowledge_id']}")
        seen.add(item["knowledge_id"])
        if item["knowledge_type"] not in KNOWLEDGE_TYPES:
            raise ValueError(f"invalid knowledge_type: {item['knowledge_type']}")
        if item["fraud_type"] not in FRAUD_TYPES:
            raise ValueError(f"invalid fraud_type: {item['fraud_type']}")
        if item["fraud_stage"] not in FRAUD_STAGES:
            raise ValueError(f"invalid fraud_stage: {item['fraud_stage']}")
        if item["risk_level"] not in RISK_LEVELS:
            raise ValueError(f"invalid risk_level: {item['risk_level']}")
        if any(tag not in RISK_FEATURES for tag in item["risk_tags"]):
            raise ValueError(f"invalid risk_tags in {item['knowledge_id']}")
        if any(route not in ROUTES for route in item["applicable_routes"]):
            raise ValueError(f"invalid route in {item['knowledge_id']}")
        if any(goal not in INTERVENTION_GOALS for goal in item["intervention_goals"]):
            raise ValueError(f"invalid intervention goal in {item['knowledge_id']}")


def rebuild_milvus(batch_size: int = 32) -> Dict[str, Any]:
    """Rebuild Milvus in small batches to avoid large CPU-memory spikes."""
    from app.clients.milvus_utils import get_milvus_client
    from app.conf.milvus_config import milvus_config
    from app.import_process.agent.nodes.node_import_fraud_knowledge_milvus import (
        _create_collection,
        _to_milvus_rows,
    )
    from app.lm.embedding_utils import generate_embeddings

    records: List[Dict[str, Any]] = json.loads(KNOWLEDGE_PATH.read_text(encoding="utf-8"))
    if not records:
        raise ValueError("No anti-fraud knowledge records to import into Milvus")

    client = get_milvus_client()
    if client is None:
        raise RuntimeError("Milvus client initialization failed")

    collection_name = (
        os.getenv("ANTI_FRAUD_COLLECTION")
        or os.getenv("FRAUD_KNOWLEDGE_COLLECTION")
        or milvus_config.anti_fraud_collection
        or "anti_fraud_knowledge"
    )
    if client.has_collection(collection_name=collection_name):
        client.drop_collection(collection_name=collection_name)

    imported_count = 0
    created = False
    embedding_backends: set[str] = set()
    for start in range(0, len(records), batch_size):
        raw_batch = records[start:start + batch_size]
        batch: List[Dict[str, Any]] = []
        texts: List[str] = []
        for item in raw_batch:
            doc = dict(item)
            risk_tags = "、".join(doc.get("risk_tags") or [])
            doc["embedding_text"] = "\n".join(
                [
                    f"标题：{doc.get('title', '')}",
                    f"诈骗类型：{doc.get('fraud_type', '')}",
                    f"知识类型：{doc.get('knowledge_type', '')}",
                    f"摘要：{doc.get('summary', '')[:160]}",
                    f"风险标签：{risk_tags}",
                    f"适用条件：{doc.get('use_when', '')[:120]}",
                ]
            )
            doc["risk_tags_text"] = ",".join(doc.get("risk_tags") or [])
            doc["applicable_routes_text"] = ",".join(doc.get("applicable_routes") or [])
            doc["case_types_text"] = ",".join(str(value) for value in doc.get("applicable_case_types") or [])
            doc["intervention_goals_text"] = ",".join(doc.get("intervention_goals") or [])
            batch.append(doc)
            texts.append(doc["embedding_text"])

        vectors = generate_embeddings(texts)
        embedding_backends.add(str(vectors.get("embedding_backend") or "unknown"))
        dense_vectors = vectors.get("dense") or []
        sparse_vectors = vectors.get("sparse") or []
        if len(dense_vectors) != len(batch) or len(sparse_vectors) != len(batch):
            raise ValueError("Embedding count does not match Milvus import batch size")

        for index, doc in enumerate(batch):
            doc["dense_vector"] = dense_vectors[index]
            doc["sparse_vector"] = sparse_vectors[index]

        if not created:
            _create_collection(client, collection_name, len(dense_vectors[0]))
            created = True

        rows = _to_milvus_rows(batch)
        client.insert(collection_name=collection_name, data=rows)
        imported_count += len(rows)
        print(f"Milvus batch imported: {imported_count}/{len(records)}")

    try:
        client.flush(collection_name=collection_name)
    except Exception:
        pass

    stats = client.get_collection_stats(collection_name) if client.has_collection(collection_name) else {}
    return {
        "collection_name": collection_name,
        "imported_count": imported_count,
        "row_count": stats.get("row_count"),
        "batch_size": batch_size,
        "embedding_backends": sorted(embedding_backends),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Clear and rebuild anti-fraud MongoDB and Milvus seed data.")
    parser.add_argument("--skip-milvus", action="store_true", help="Only rebuild MongoDB and seed files.")
    parser.add_argument("--no-backup", action="store_true", help="Do not export existing MongoDB collections before reset.")
    parser.add_argument("--milvus-batch-size", type=int, default=16, help="Milvus embedding/import batch size.")
    args = parser.parse_args()

    load_dotenv(PROJECT_ROOT / ".env")
    os.environ.setdefault("PYTHONPATH", str(PROJECT_ROOT))
    mongo_url = os.getenv("MONGO_URL")
    db_name = os.getenv("MONGO_DB_NAME")
    if not mongo_url or not db_name:
        raise RuntimeError("MONGO_URL or MONGO_DB_NAME is not configured")

    bundle = build_seed_bundle()
    validate_runtime_knowledge(bundle["anti_fraud_knowledge"])
    write_seed_files(bundle)

    client = MongoClient(mongo_url)
    db = client[db_name]
    backup_dir = BACKUP_ROOT / datetime.now().strftime("%Y%m%d_%H%M%S")
    if not args.no_backup:
        backup_mongo(db, backup_dir)

    reset_mongo(db)
    counts = insert_bundle(db, bundle)

    milvus_result: Dict[str, Any] = {"skipped": True}
    if not args.skip_milvus:
        milvus_result = rebuild_milvus(batch_size=args.milvus_batch_size)

    print("Anti-fraud knowledge database rebuilt.")
    print(f"Mongo database: {db_name}")
    if not args.no_backup:
        print(f"Mongo backup: {backup_dir}")
    print("Mongo collections:")
    for name in sorted(counts):
        print(f"- {name}: {counts[name]}")
    print(f"Seed file: {KNOWLEDGE_PATH}")
    print(f"Rules file: {RULES_PATH}")
    print(f"Game levels file: {GAME_LEVELS_PATH}")
    print(f"Test cases file: {TEST_CASES_PATH}")
    print(f"Structured seed file: {STRUCTURED_SEED_PATH}")
    print(f"Milvus result: {milvus_result}")


if __name__ == "__main__":
    main()
