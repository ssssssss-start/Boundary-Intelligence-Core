"""Unified configurable anti-fraud rule engine.

This service is the single deterministic risk-evaluation entry point used by:
- the compact LangGraph risk workflow,
- the legacy ``node_rule_engine`` wrapper,
- the public ``/risk/check`` service.

It keeps the old JSON/Mongo ``risk_rules`` format, and additionally supports
local Scam Package JSON files under ``app/query_process/rules/scam_packages``.
No dynamic expression evaluation is used; rule conditions stay as safe
``all/any/min_any`` feature sets.
"""

from __future__ import annotations

import json
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from app.anti_fraud.schema import (
    RISK_FEATURE_ALIASES,
    RISK_FEATURES,
    RISK_FEATURE_SYNONYMS,
    normalize_risk_features,
)
from app.anti_fraud.taxonomy import canonicalize_fraud_types, fraud_type_metadata, standard_name_for
from app.core.logger import logger
from app.query_process.agent.nodes.node_rule_engine import _load_rules
from app.query_process.services.input_normalizer import (
    build_context_text,
    extract_amounts,
    extract_urls,
    normalize_text,
)


CORE_FRAUD_TYPE_ALIASES: List[Tuple[str, List[str]]] = [
    ("杀猪盘诈骗", ["网恋", "交友", "恋爱", "对象", "情感", "婚恋"]),
    ("屏幕共享/远程控制诈骗", ["屏幕共享", "共享屏幕", "会议软件", "远程控制", "远程协助", "控制手机", "控制电脑"]),
    ("验证码/账户盗刷诈骗", ["验证码", "短信码", "动态码", "登录码", "支付码", "人脸识别"]),
    ("冒充熟人诈骗", ["领导", "亲友", "同学", "同事", "室友", "舍友", "朋友借钱", "熟人借钱", "亲戚借钱", "换号", "新账号", "新微信号", "新的微信号", "不方便电话"]),
    ("虚假中奖/免费礼品诈骗", ["中奖", "领奖", "兑奖", "免费领", "抽中", "福利礼品"]),
    ("虚假购物服务诈骗", ["卖家", "演唱会票", "门票", "二手", "低价", "定金", "订金", "加私聊", "不能走平台", "不走平台"]),
    ("刷单返利诈骗", ["刷单", "做任务", "返佣", "垫付", "补单", "兼职", "点赞任务"]),
    ("游戏交易诈骗", ["游戏", "游戏装备", "游戏账号", "装备给", "账号给", "虚拟资产", "代充", "皮肤", "账号交易", "低价充值", "代练", "点券"]),
    ("冒充公检法诈骗", ["公安", "警察", "检察院", "法院", "公检法", "安全账户", "涉案", "洗钱", "违法物品", "违禁品", "涉案物品", "违法包裹", "涉嫌违法"]),
    ("虚假投资理财诈骗", ["投资", "理财", "稳赚", "高收益", "内幕", "虚拟币"]),
    ("网络贷款诈骗", ["贷款", "借款", "放款", "刷流水", "包装费", "会员费", "校园贷", "学生贷款", "资料费"]),
    ("冒充客服诈骗", ["自称客服", "平台客服", "快递客服", "电商客服", "客服来电", "退款", "理赔", "快递", "售后", "取消会员", "百万保障"]),
    ("钓鱼链接诈骗", ["链接", "网址", "二维码", "login", "verify", "security"]),
]

# The source datasets often describe a scene without naming the scam.  These
# behaviour anchors are deliberately kept separate from broad aliases so a
# generic word such as ``客服`` cannot hide the more specific scene.
BEHAVIOR_TYPE_PATTERNS: List[Tuple[str, str]] = [
    (
        "求职实习招聘诈骗",
        r"(?=.*(?:招聘|求职|实习|岗位|入职|招聘专员|应聘|高薪)).{0,160}(?=.*(?:培训费|培训押金|报名费|证书|会员费|资料费|保证金|服务费|手续费|下载(?:陌生)?App|交费|缴费))",
    ),
    (
        "刷单返利诈骗",
        r"(派单客服|组合任务|店铺冲销量|数据异常.{0,20}(补单|继续完成)|继续完成.{0,12}(组合任务|任务).{0,12}(本金|结算|提现))",
    ),
    (
        "AI换脸冒充熟人诈骗",
        r"(仿冒亲友|仿冒亲属|视频里.{0,8}(像|亲友|亲属)|视频通话.{0,16}(相似|像|面孔|声音)|声音.{0,8}(像|亲友|孙子)|视频只说几句话|亲属委托.{0,16}(取钱|借钱)|急需.{0,8}(手术费|医药费).{0,12}(视频|语音))",
    ),
    (
        "两卡出租出借与跑分诈骗",
        r"(收卡人员|收卡中介|收卡中介|实名办卡.{0,16}(交给|刷流水|走账)|租借.{0,12}(银行卡|电话卡)|银行卡.{0,12}(电话卡|POS).{0,18}(租金|绑定|走账)|公司走账.{0,12}(银行卡|电话卡)|代收代付|代购上线|跑腿取现)",
    ),
    (
        "征信修复/注销账户诈骗",
        r"(征信处理专员|金融平台客服.{0,24}(征信|注销|关闭|清零|影响|年费|额度)|(?=.*金融平台客服)(?=.*(?:征信|注销|关闭|清零|额度|转回|清除不良记录))|征信.{0,12}(修复|异常|影响|处理)|修复征信|影响.{0,4}征信|注销.{0,12}(校园贷|网贷|账户|会员)|关闭.{0,12}(网贷|贷款|账户).{0,12}(年费|征信)|清零验证|认证对接账户|贷款额度转出)",
    ),
    (
        "机票火车票退改签诈骗",
        r"(?=.*(?:航班|机票|火车票|车次|航司))(?=.*(?:取消|延误|退票|改签|补偿|理赔|支付验证码|银行卡))",
    ),
    (
        "验证码/账户盗刷诈骗",
        r"(?=.*(?:账号验证客服|二次认证|登录后|账户登录|账号登录|验证客服))(?=.*(?:验证码|支付验证码|短信码|动态码|登录码))(?=.*(?:输入|填写|提供|完成验证|验证))",
    ),
    (
        "情感交友诱导投资诈骗",
        r"((网恋|恋爱|交友|暧昧|对象|每天关心).{0,48}(投资|理财|虚拟币|博彩|刷单|平台|入金|提现|充值|解冻费)|(?=.*(?:网恋|恋爱|交友|暧昧|对象|每天关心))(?=.*(?:投资|理财|虚拟币|博彩|刷单|平台|入金|提现|充值|解冻费|共同理财|晒收益|指定账户)))",
    ),
    (
        "机票火车票退改签诈骗",
        r"(?=.*(?:航班|机票|火车票|车次|航司|退改签))(?=.*(?:取消|延误|退票|改签|补偿|理赔|验证码|银行卡|客服))",
    ),
    (
        "奖助学金/学费退费诈骗",
        r"(助学金|奖学金|补贴|资助金|教育部门|教育局|学费退费|国家补助).{0,32}(到账|发放|通知|异常|过期|名额|激活|退费|获得|领取|二维码|链接).{0,48}(银行卡|身份证|支付密码|验证码|网银|ATM|链接|二维码|税费|保证金|转账|开通|账户)",
    ),
    (
        "租房合租押金诈骗",
        r"((租房|房源|房东|中介|公寓|租客).{0,36}(押金|定金|租金|看房|合同|产权|钥匙|照片).{0,36}(先付|先交|先转|转账|支付|付款|私下|低于市场|拒绝|没空|外地|不签|不出示|失联|快递)|((租房|房源|房东|中介|公寓|租客).{0,36}(先付|先交|先转|转账|支付|付款|私下|低于市场|拒绝|没空|外地|不签|不出示|失联|快递).{0,36}(押金|定金|租金|看房|合同|产权|钥匙|照片))|(精装修照片|照片).{0,24}(拒绝|不让|没空).{0,16}(视频|实地|看房).{0,24}(房东|中介))",
    ),
    (
        "裸聊敲诈勒索诈骗",
        r"((裸聊|不雅视频|隐私视频|隐私照片|偷拍视频|裸照|交友.{0,8}App|敲诈者).{0,40}(通讯录|联系人|家人|朋友|群发|公开|威胁|转账|删视频|封口费|不付款|不转|删除费|管理费|买断视频)|(通讯录|联系人).{0,40}(裸聊|不雅视频|隐私视频|隐私照片|隐私照片|偷拍视频|裸照|交友.{0,8}App|威胁|转账|删视频|封口费|不付款|不转))",
    ),
    (
        "游戏交易诈骗",
        r"(?=.*(?:游戏|游戏账号|游戏装备|皮肤|点券|虚拟资产))(?=.*(?:买家|卖家|交易|账号|装备|道具|充值|保证金|解冻费|冻结|验货|担保|客服|平台|二维码|扫码|填写信息|免费领取|领取|聊天框|福利))",
    ),
    (
        "虚假中奖/免费礼品诈骗",
        r"(中奖|领奖|抽奖|免费领|免费手机|福利礼品|盲盒).{0,40}(税费|所得税|税|运费|保证金|激活费|银行卡|验证码|链接|二维码|限时|过期|马上填|转账)",
    ),
    (
        "冒充客服诈骗",
        r"(?=.*(?:物流客服|快递客服|电商客服|网店客服|平台客服|冒充平台客服|商品质量|订单|包裹|会员))(?=.*(?:退款|理赔|银行卡|验证码|链接|二维码|下载|屏幕共享|会议软件|转账|先交|补运费|个人账户|关闭|三倍赔付))",
    ),
    (
        "校园二手/票务交易诈骗",
        r"(?=.*(?:演唱会|音乐节|赛事|景区|门票|电子票|黄牛|内部票|票务|二手票|票务卖家))(?=.*(?:验票|验票链接|点击.{0,8}链接|填写身份证|填写银行卡|身份证和银行卡))",
    ),
    (
        "钓鱼链接诈骗",
        r"(?=.*(?:链接|网址|二维码|网页|领奖页面))(?=.*(?:身份证|银行卡|验证码|支付密码|授权通讯录|短信权限))",
    ),
    (
        "冒充老师辅导员收费诈骗",
        r"(?=.*(?:老师|班主任|辅导员|班级群|家长群|教务))(?=.*(?:资料费|培训费|考试费|报名费|补课费|教材费|收款码|扫码缴费))(?=.*(?:马上|截止|催促|付款|缴费|个人账户|截图接龙|拒绝电话|不让核实|通知|群公告|头像|换成老师头像))",
    ),
    (
        "校园二手/票务交易诈骗",
        r"(?=.*(?:演唱会|音乐节|赛事|景区|门票|电子票|黄牛|内部票|票务|二手票))(?=.*(?:加微信|私聊|私下|平台外|不走平台|先付|先款|付款|全款|定金|订金|补差价|转账|银行卡|担保费|实名))",
    ),
    (
        "虚假购物服务诈骗",
        r"(?=.*(?:商品|购物|订单|白酒|手机|代购|卖家|厂家直销|私家侦探|定位骗子))(?=.*(?:低价|内部价|私人账户|私下|转账|付款|劳务费|高额|发货|退款|拉黑|不走平台|先交))",
    ),
    (
        "冒充公检法诈骗",
        r"(?=.*(?:民警|公安|警察|检察院|法院|办案人员|办案民警))(?=.*(?:涉嫌洗钱|涉案|法律文书|通缉令|保密|调查|安全账户|视频做笔录|无人房间|银行卡|资金审查))",
    ),
    (
        "虚假投资理财诈骗",
        r"(证券公司|证券顾问|股票|投资群).{0,40}(推荐股票|盈利截图|内部通道|非本人账户|社交平台链接|交易|投资款|群).{0,40}(转|入金|账户|平台|链接|缴费)?",
    ),
    (
        "校园二手/票务交易诈骗",
        r"(演唱会|音乐节|赛事|景区|门票|电子票|黄牛|内部票|票务|二手票).{0,36}(加微信|私聊|平台外|不走平台|先付|定金|订金|转账|银行卡)",
    ),
    (
        "两卡出租出借与跑分诈骗",
        r"(闲置交易平台|购买名表|跑腿取现).{0,36}(脱离平台|银行卡号|收款|过账|转账)",
    ),
]


BEHAVIOR_COMBINATION_RULES: List[Dict[str, Any]] = [
    {
        "rule_id": "RULE_REALISTIC_POLICE_LIVE_FUNDS_001",
        "rule_name": "视频办案实时查看多卡资金",
        "fraud_type": "冒充公检法诈骗",
        "conditions": {
            "must_include_any": [
                ["视频会议", "线上做笔录", "飞书"],
                ["几张卡", "多张卡", "卡的余额", "归集"],
                ["共享", "不让我开", "不能有旁人", "一个人"],
            ]
        },
        "risk_score": 92,
        "risk_level": "高风险",
        "intervention_goal": "stop_screen_share",
        "explanation": "视频办案中实时查看多张银行卡并要求隔离或归集资金，已进入账户控制阶段。",
        "suggested_action": "立即退出会议、关闭共享，不归集资金或透露余额，拨打 110 或属地公安公开电话核验。",
        "source": "realistic_behavior_combinations_v1",
    },
    {
        "rule_id": "RULE_REALISTIC_SERVICE_FUNDS_CONTROL_001",
        "rule_name": "客服撤费后的借款转出或短信控制",
        "fraud_type": "冒充客服诈骗",
        "conditions": {
            "must_include_any": [
                ["银行售后", "商户保障", "赔付组", "保险专员"],
                ["短信数字", "借款页面", "银联清算户", "念过去", "借出来的钱"],
            ]
        },
        "risk_score": 92,
        "risk_level": "高风险",
        "intervention_goal": "stop_transfer",
        "explanation": "客服撤费或赔付话术已升级到读取短信、从借款页面提现或向清算户转出资金。",
        "suggested_action": "立即停止转账和短信披露，退出借款页面；如已付款，联系银行止付并从官方客服入口核验。",
        "source": "realistic_behavior_combinations_v1",
    },
    {
        "rule_id": "RULE_REALISTIC_ACQUAINTANCE_CONFIRMED_001",
        "rule_name": "熟人付款后被本人否认",
        "fraud_type": "冒充领导或熟人借钱诈骗",
        "conditions": {
            "must_include_any": [
                ["家族群", "表哥", "亲友", "朋友"],
                ["转了", "付款", "付尾款", "发的账户"],
                ["真表哥", "没这回事", "早结完", "不是他本人"],
            ]
        },
        "risk_score": 95,
        "risk_level": "高风险",
        "intervention_goal": "call_police",
        "explanation": "已按熟人指示付款，随后被熟人本人否认，损失事实与身份冒充均已确认。",
        "suggested_action": "立即联系银行或支付平台申请止付，保存群聊、账号与收款账户信息并报警。",
        "source": "realistic_behavior_combinations_v1",
    },
    {
        "rule_id": "RULE_REALISTIC_ACTIVE_ESCALATION_001",
        "rule_name": "已进入资金或账户控制的复合高危操作",
        "fraud_type": "",
        "conditions": {
            "must_include_any": [
                ["订单锁住", "远程看号", "信用担保", "保证份额", "器材分期", "清算卡", "银联清算户", "商户评分", "真表哥"],
                ["再付", "共享", "短信", "充值", "网贷", "撤合同", "转到", "转回", "退回", "扫出去", "没这回事", "早结完"],
            ]
        },
        "risk_score": 90,
        "risk_level": "高风险",
        "intervention_goal": "stop_transfer",
        "explanation": "已出现资金被占用、远程/短信控制、追加担保、清算转出或亲友否认等事中信号。",
        "suggested_action": "立即停止继续付款、共享、验证码或代转操作；如已付款，马上联系银行止付并保存证据报警。",
        "source": "realistic_behavior_combinations_v1",
    },
    {
        "rule_id": "RULE_REALISTIC_CROSS_CHANNEL_CONTROL_001",
        "rule_name": "原场景诱导叠加远程控制",
        "fraud_type": "",
        "conditions": {
            "must_include_any": [
                ["拍一单", "差评价", "游戏", "仓库", "赔付", "客服"],
                ["会议", "共享", "远程", "短信数字", "解绑短信", "验证码"],
            ]
        },
        "risk_score": 90,
        "risk_level": "高风险",
        "intervention_goal": "stop_screen_share",
        "explanation": "交易、任务或客服场景已升级为会议共享、远程控制或短信凭证交付。",
        "suggested_action": "立即断开会议和远程控制，不朗读短信或验证码，并在原平台和银行检查异常操作。",
        "source": "realistic_behavior_combinations_v1",
    },
    {
        "rule_id": "RULE_REALISTIC_BRUSH_CHAIN_001",
        "rule_name": "刷单任务升级与返款组合",
        "fraud_type": "刷单返利诈骗",
        "conditions": {
            "must_include_any": [
                ["养数据", "拍一单", "联单", "连单", "连淡", "三个单子绑", "订单锁住", "差评价"],
                ["本金", "工钱", "原路退", "再付", "补", "垫", "解锁", "倒计时"],
            ]
        },
        "risk_score": 75,
        "risk_level": "中风险",
        "intervention_goal": "stop_transfer",
        "explanation": "任务或评价行为叠加返本金、补差额、解锁订单等资金要求，构成刷单任务升级链。",
        "suggested_action": "停止拍单、补差额和解锁付款，不要因前款被占用继续投入，保留任务页面与收款记录。",
        "source": "realistic_behavior_combinations_v1",
    },
    {
        "rule_id": "RULE_REALISTIC_GAME_DELIVERY_001",
        "rule_name": "游戏资产交付与异常担保组合",
        "fraud_type": "游戏交易诈骗",
        "conditions": {
            "must_include_any": [
                ["公会", "游戏", "材料", "陪练", "比赛号", "仓库", "远程看号"],
                ["小号", "防跑单金", "押金", "二次认证", "解绑短信", "扫码", "远程看号", "邮给"],
            ]
        },
        "risk_score": 75,
        "risk_level": "中风险",
        "intervention_goal": "stop_transfer",
        "explanation": "游戏场景叠加先交资产、押金、扫码认证或远程验号，已脱离可追偿的官方交付流程。",
        "suggested_action": "不要交付材料、账号、押金或验证码，终止远程验号并回到游戏官方交易渠道。",
        "source": "realistic_behavior_combinations_v1",
    },
    {
        "rule_id": "RULE_REALISTIC_POLICE_ISOLATION_001",
        "rule_name": "线上办案隔离与资金处置组合",
        "fraud_type": "冒充公检法诈骗",
        "conditions": {
            "must_include_any": [
                ["线上做笔录", "协查员", "市局", "穿警服", "违禁卡", "资金清白", "做证物"],
                ["一个人", "酒店", "银行卡", "金条", "余额", "归集", "网贷", "飞书", "共享"],
            ]
        },
        "risk_score": 90,
        "risk_level": "高风险",
        "intervention_goal": "stop_transfer",
        "explanation": "办案身份或线上笔录叠加隔离、查看资金、购金取证、借贷归集等要求，是高危冒充公检法组合。",
        "suggested_action": "立即退出会议并停止购金、借贷、归集或展示账户，通过 110 或属地公安公开电话独立核验。",
        "source": "realistic_behavior_combinations_v1",
    },
    {
        "rule_id": "RULE_REALISTIC_INVESTMENT_FUNDING_001",
        "rule_name": "非官方投资载体与追加资金组合",
        "fraud_type": "虚假投资理财诈骗",
        "conditions": {
            "must_include_any": [
                ["量化内测", "行情插件", "商品子账户", "稳定币", "夜盘", "酒庄分红", "投进去"],
                ["入金", "装", "钱包", "充", "提现", "担保", "冻结", "保证份额", "网贷"],
            ]
        },
        "risk_score": 75,
        "risk_level": "中风险",
        "intervention_goal": "stop_transfer",
        "explanation": "非官方投资载体叠加安装插件、稳定币入金、担保充值或提现限制，形成封闭资金链。",
        "suggested_action": "不要安装对方插件、购买稳定币或追加担保资金，先核验机构牌照和资金托管账户。",
        "source": "realistic_behavior_combinations_v1",
    },
    {
        "rule_id": "RULE_REALISTIC_CAMPUS_CREDIT_001",
        "rule_name": "校园额度注销与借新还旧组合",
        "fraud_type": "征信修复/注销账户诈骗",
        "conditions": {
            "must_include_any": [
                ["学生分期", "学生身份", "校园贷", "教育金融中心", "校园额度"],
                ["清掉", "销户", "注销", "对冲", "旧记录", "管理费", "清算卡", "统一转"],
            ]
        },
        "risk_score": 75,
        "risk_level": "中风险",
        "intervention_goal": "stop_transfer",
        "explanation": "以学生身份、旧校园额度或年费为由要求借新额度并转入清算账户，符合注销账户诈骗链。",
        "suggested_action": "不要申请新贷款或把额度转出，直接通过原金融机构官方渠道查询账户和征信。",
        "source": "realistic_behavior_combinations_v1",
    },
    {
        "rule_id": "RULE_REALISTIC_CUSTOMER_OPERATION_001",
        "rule_name": "客服赔付与账户操作组合",
        "fraud_type": "冒充客服诈骗",
        "conditions": {
            "must_include_any": [
                ["批次有问题", "三倍补偿", "赔付组", "银行售后", "商户保障", "快递", "售后"],
                ["视频软件", "钱包编号", "短信数字", "借款页面", "清算户", "手机钱包", "看着我操作"],
            ]
        },
        "risk_score": 75,
        "risk_level": "中风险",
        "intervention_goal": "stop_sensitive_info",
        "explanation": "客服或赔付身份叠加安装软件、开钱包、读取短信、借款并转入清算户等账户操作。",
        "suggested_action": "挂断来电，不安装软件、不提供钱包或短信信息，也不要从借款页面提现转账；从订单官方入口核验。",
        "source": "realistic_behavior_combinations_v1",
    },
    {
        "rule_id": "RULE_REALISTIC_LOAN_OFFLINE_TRANSFER_001",
        "rule_name": "贷款放款前线下资产转移组合",
        "fraud_type": "网络贷款诈骗",
        "conditions": {
            "must_include_any": [
                ["贷款审核", "放款通过", "贷款平台", "中介", "器材分期", "学费周转"],
                ["购物卡", "卡密", "取现金", "跑腿", "包装费", "过一晚上", "公司", "店铺码", "撤合同"],
            ]
        },
        "risk_score": 75,
        "risk_level": "中风险",
        "intervention_goal": "stop_transfer",
        "explanation": "贷款或分期场景叠加购物卡、现金跑腿、包装流水、公司代收或撤合同收费，属于放款前异常资金操作。",
        "suggested_action": "停止购买购物卡、取现交付、刷流水或继续交费，向持牌机构官方渠道核验合同和放款状态。",
        "source": "realistic_behavior_combinations_v1",
    },
    {
        "rule_id": "RULE_REALISTIC_ACQUAINTANCE_VERIFY_001",
        "rule_name": "熟人异常联系与第三方收款组合",
        "fraud_type": "冒充领导或熟人借钱诈骗",
        "conditions": {
            "must_include_any": [
                ["室友", "导师", "表哥", "舅舅", "家族群", "新号", "亲友"],
                ["不方便视频", "不接电话", "充值卡", "卡密", "缴费单", "尾款", "暗号", "收款人", "发的账户"],
            ]
        },
        "risk_score": 75,
        "risk_level": "中风险",
        "intervention_goal": "stop_transfer",
        "explanation": "熟人身份叠加拒绝原渠道核验、充值卡付款或第三方收款，身份与资金对象不一致。",
        "suggested_action": "先不要付款或发送卡密，用原手机号、当面或共同联系人核验，并确认收款账户本人身份。",
        "source": "realistic_behavior_combinations_v1",
    },
    {
        "rule_id": "RULE_BRUSH_BEHAVIOR_001",
        "rule_name": "刷单返利行为组合规则",
        "fraud_type": "刷单返利诈骗",
        "conditions": {
            "must_include_any": [
                ["派单客服", "组合任务", "店铺冲销量", "继续完成组合任务", "数据异常"],
                ["补单", "返本金", "本金", "结算", "提现", "垫付"],
            ]
        },
        "risk_score": 92,
        "risk_level": "高风险",
        "intervention_goal": "stop_transfer",
        "explanation": "任务/冲销量/派单客服叠加补单、结算或提现要求，符合刷单返利的行为组合。",
        "suggested_action": "立即停止补单、充值和垫付，不要再交解冻费，保留聊天和转账记录。",
        "source": "behavior_combination_rules",
    },
    {
        "rule_id": "RULE_AI_FACE_BEHAVIOR_001",
        "rule_name": "AI拟声/视频冒充熟人行为组合规则",
        "fraud_type": "AI换脸冒充熟人诈骗",
        "conditions": {
            "must_include_any": [["视频", "语音", "声音"], ["亲友", "亲属", "孙子", "朋友", "委托"], ["借钱", "转账", "取钱", "收款"]]
        },
        "risk_score": 87,
        "risk_level": "高风险",
        "intervention_goal": "stop_transfer",
        "explanation": "视频/语音身份线索与亲友关系、借钱或取钱行为叠加，需通过原渠道二次核验。",
        "suggested_action": "不要按视频或语音直接转账，挂断后通过原手机号、当面或共同联系人独立核实。",
        "source": "behavior_combination_rules",
    },
    {
        "rule_id": "RULE_TWO_CARDS_BEHAVIOR_001",
        "rule_name": "两卡出租出借与跑分行为组合规则",
        "fraud_type": "两卡出租出借与跑分诈骗",
        "conditions": {
            "must_include_any": [["银行卡", "电话卡", "实名办卡", "收卡人员", "收卡中介", "POS"], ["出租", "出借", "刷流水", "走账", "租金", "收款", "转出去"]]
        },
        "risk_score": 96,
        "risk_level": "高风险",
        "intervention_goal": "stop_sensitive_info",
        "explanation": "要求提供实名卡、手机或收款权限并用于走账/刷流水，属于两卡出租出借或跑分风险。",
        "suggested_action": "不要出租、出借银行卡/电话卡、U盾、手机或收款码，保存招募和转账记录并联系银行及公安机关。",
        "source": "behavior_combination_rules",
    },
    {
        "rule_id": "RULE_CREDIT_REPAIR_BEHAVIOR_001",
        "rule_name": "征信修复/注销账户行为组合规则",
        "fraud_type": "征信修复/注销账户诈骗",
        "conditions": {
            "must_include_any": [["征信", "网贷", "贷款账户", "金融平台"], ["注销", "关闭", "修复", "清零", "认证对接", "影响征信", "影响个人征信", "贷款额度", "额度", "不良记录", "年费"], ["转账", "转到", "服务费", "下载", "年费", "验证码", "身份证", "清除"]]
        },
        "risk_score": 94,
        "risk_level": "高风险",
        "intervention_goal": "stop_transfer",
        "explanation": "以征信/注销/清零为由要求付费、转账、下载 App 或提交敏感资料，符合征信修复注销诈骗。",
        "suggested_action": "不要按来电要求转账、借贷或下载 App，通过官方金融机构渠道独立核验。",
        "source": "behavior_combination_rules",
    },
    {
        "rule_id": "RULE_TICKET_BEHAVIOR_001",
        "rule_name": "票务/二手交易平台外付款行为组合规则",
        "fraud_type": "校园二手/票务交易诈骗",
        "conditions": {
            "must_include_any": [["演唱会", "音乐节", "赛事", "景区", "门票", "票务", "黄牛", "二手票"], ["加微信", "私聊", "平台外", "不走平台", "先付", "先款", "付款", "全款", "定金", "订金", "转账", "银行卡", "实名"]]
        },
        "risk_score": 90,
        "risk_level": "高风险",
        "intervention_goal": "stop_transfer",
        "explanation": "票务/二手交易叠加脱离担保平台、加私聊或先付定金，属于高风险交易组合。",
        "suggested_action": "不要私下付款或先交定金，回到官方售票/平台担保流程核验票源。",
        "source": "behavior_combination_rules",
    },
    {
        "rule_id": "RULE_CASH_MULE_BEHAVIOR_001",
        "rule_name": "跑腿取现/代收代付行为组合规则",
        "fraud_type": "两卡出租出借与跑分诈骗",
        "conditions": {
            "must_include_any": [["跑腿取现", "代购上线", "购买名表", "闲置交易平台"], ["银行卡", "银行卡号", "收款", "转账", "过账", "脱离平台"]]
        },
        "risk_score": 94,
        "risk_level": "高风险",
        "intervention_goal": "preserve_evidence",
        "explanation": "被安排以代购、取现或平台外收款方式转移来路不明资金，存在洗钱工具人风险。",
        "suggested_action": "立即停止代收代付和取现，不要提供银行卡或收款码，保存委托、账户和交易记录并尽快咨询公安机关。",
        "source": "behavior_combination_rules",
    },
    {
        "rule_id": "RULE_RENTAL_DEPOSIT_BEHAVIOR_001",
        "rule_name": "租房押金行为组合规则",
        "fraud_type": "租房合租押金诈骗",
        "conditions": {
            "must_include_any": [
                ["租房", "房源", "房东", "中介", "公寓", "租客"],
                ["押金", "定金", "租金", "看房", "合同", "产权", "钥匙", "照片"],
                ["先付", "先交", "先转", "转账", "支付", "付款", "私下", "低于市场", "拒绝", "没空", "外地", "不签", "失联", "快递"],
            ]
        },
        "risk_score": 88,
        "risk_level": "高风险",
        "intervention_goal": "stop_transfer",
        "explanation": "房源或出租人线索叠加未核验看房/合同和先付押金、平台外付款等行为，属于租房押金高危组合。",
        "suggested_action": "未完成实地看房、产权和出租人核验前，不要支付押金或租金；保存房源、合同和收款记录。",
        "source": "behavior_combination_rules",
    },
    {
        "rule_id": "RULE_TRAVEL_REFUND_BEHAVIOR_001",
        "rule_name": "机票火车票退改签行为组合规则",
        "fraud_type": "机票火车票退改签诈骗",
        "conditions": {
            "must_include_any": [
                ["航班", "机票", "火车票", "车次", "航司", "退改签"],
                ["取消", "延误", "退票", "改签", "补偿", "理赔"],
                ["验证码", "银行卡", "链接", "下载", "屏幕共享", "会议软件", "手续费", "保证金", "先转", "ATM"],
            ]
        },
        "risk_score": 90,
        "risk_level": "高风险",
        "intervention_goal": "stop_transfer",
        "explanation": "航班/车票异常通知叠加退改签补偿话术和链接、验证码、屏幕共享或先付费用等行为，符合退改签诈骗。",
        "suggested_action": "不要点击短信链接、共享屏幕或提供验证码；通过航空公司/铁路官方入口独立核验并办理。",
        "source": "behavior_combination_rules",
    },
    {
        "rule_id": "RULE_SCHOLARSHIP_BEHAVIOR_001",
        "rule_name": "奖助学金/补贴行为组合规则",
        "fraud_type": "奖助学金/学费退费诈骗",
        "conditions": {
            "must_include_any": [
                ["助学金", "奖学金", "补贴", "资助金", "教育部门", "教育局", "学费退费", "国家补助"],
                ["到账", "发放", "通知", "异常", "过期", "名额", "激活", "退费"],
                ["银行卡", "验证码", "网银", "ATM", "链接", "二维码", "税费", "保证金", "转账", "开通", "账户"],
            ]
        },
        "risk_score": 90,
        "risk_level": "高风险",
        "intervention_goal": "stop_sensitive_info",
        "explanation": "补贴/助学金通知叠加开通网银、ATM 操作、提交银行卡验证码或先付激活费用，属于冒充资助发放风险。",
        "suggested_action": "不要按来电或链接操作 ATM、网银或转账，联系学校资助部门/官方平台核验并保存短信和号码。",
        "source": "behavior_combination_rules",
    },
    {
        "rule_id": "RULE_NUDE_EXTORTION_BEHAVIOR_001",
        "rule_name": "裸聊敲诈行为组合规则",
        "fraud_type": "裸聊敲诈勒索诈骗",
        "conditions": {
            "must_include_any": [
                ["裸聊", "隐私视频", "不雅视频", "偷拍视频", "裸照", "交友App"],
                ["通讯录", "联系人", "家人", "朋友", "群发", "公开", "威胁"],
                ["转账", "删视频", "封口费", "不付款", "不转", "删除费", "管理费", "继续要"],
            ]
        },
        "risk_score": 96,
        "risk_level": "极高风险",
        "intervention_goal": "preserve_evidence",
        "explanation": "隐私影像或交友 App 叠加通讯录威胁和删视频收费，是裸聊敲诈的典型行为组合。",
        "suggested_action": "不要继续付款或按要求删证据，立即保存聊天、视频威胁和收款信息，联系平台并报警。",
        "source": "behavior_combination_rules",
    },
    {
        "rule_id": "RULE_PRIZE_GIFT_BEHAVIOR_001",
        "rule_name": "中奖免费礼品行为组合规则",
        "fraud_type": "虚假中奖/免费礼品诈骗",
        "conditions": {
            "must_include_any": [
                ["中奖", "领奖", "抽奖", "免费领", "免费手机", "福利礼品", "盲盒"],
                ["税费", "运费", "保证金", "激活费", "银行卡", "验证码", "链接", "二维码", "限时", "过期", "马上填", "转账"],
            ]
        },
        "risk_score": 88,
        "risk_level": "高风险",
        "intervention_goal": "stop_sensitive_info",
        "explanation": "中奖/免费礼品诱导叠加收费、扫码链接或银行卡验证码要求，属于虚假领奖行为组合。",
        "suggested_action": "不要为领奖缴费或填写银行卡、验证码，关闭链接并通过活动主办方官方渠道核验。",
        "source": "behavior_combination_rules",
    },
    {
        "rule_id": "RULE_CAMPUS_FEE_BEHAVIOR_001",
        "rule_name": "冒充老师收费行为组合规则",
        "fraud_type": "冒充老师辅导员收费诈骗",
        "conditions": {
            "must_include_any": [
                ["老师", "班主任", "辅导员", "班级群", "家长群", "教务"],
                ["资料费", "培训费", "考试费", "报名费", "补课费", "教材费", "收款码", "扫码缴费"],
                ["马上", "截止", "催促", "付款", "缴费", "个人账户", "截图接龙", "拒绝电话", "不让核实"],
            ]
        },
        "risk_score": 86,
        "risk_level": "高风险",
        "intervention_goal": "stop_transfer",
        "explanation": "老师/班级身份包装叠加具体收费名目和群内催缴、个人收款或拒绝核验行为，属于校园收费冒充。",
        "suggested_action": "不要在群内直接扫码或向个人账户付款，先通过学校官网、班主任原号码或线下渠道核验。",
        "source": "behavior_combination_rules",
    },
    {
        "rule_id": "RULE_CUSTOMER_SERVICE_BEHAVIOR_001",
        "rule_name": "电商物流客服退款行为组合规则",
        "fraud_type": "冒充客服诈骗",
        "conditions": {
            "must_include_any": [
                ["物流客服", "快递客服", "电商客服", "网店客服", "平台客服", "客服", "订单", "包裹", "会员"],
                ["退款", "理赔", "商品质量", "包裹异常", "银行卡", "验证码", "链接", "下载", "屏幕共享", "会议软件", "转账", "先交"],
            ]
        },
        "risk_score": 88,
        "risk_level": "高风险",
        "intervention_goal": "stop_sensitive_info",
        "explanation": "客服身份包装叠加退款/理赔或账户操作要求，尤其出现链接、验证码、屏幕共享或先交费用时风险很高。",
        "suggested_action": "挂断并从官方订单或官网入口核验，不点击陌生链接、不共享屏幕、不提供验证码。",
        "source": "behavior_combination_rules",
    },
    {
        "rule_id": "RULE_FAKE_SHOPPING_BEHAVIOR_001",
        "rule_name": "虚假购物/服务行为组合规则",
        "fraud_type": "虚假购物服务诈骗",
        "conditions": {
            "must_include_any": [
                ["商品", "购物", "订单", "白酒", "手机", "代购", "卖家", "厂家直销", "私家侦探", "定位骗子"],
                ["低价", "内部价", "私人账户", "私下", "转账", "付款", "劳务费", "高额", "发货", "退款", "拉黑", "不走平台", "先交"],
            ]
        },
        "risk_score": 82,
        "risk_level": "高风险",
        "intervention_goal": "stop_transfer",
        "explanation": "商品或付费服务场景叠加异常低价、平台外付款、先交费用或付款后失联，符合虚假购物/服务风险。",
        "suggested_action": "不要向个人账户或所谓私家服务先付款，回到官方平台核验订单、服务资质和退款入口。",
        "source": "behavior_combination_rules",
    },
    {
        "rule_id": "RULE_POLICE_BEHAVIOR_001",
        "rule_name": "公检法身份恐吓行为组合规则",
        "fraud_type": "冒充公检法诈骗",
        "conditions": {
            "must_include_any": [
                ["民警", "公安", "警察", "检察院", "法院", "办案人员", "办案民警"],
                ["涉嫌洗钱", "涉案", "法律文书", "通缉令", "保密", "调查", "安全账户", "视频做笔录", "无人房间", "银行卡"],
            ]
        },
        "risk_score": 90,
        "risk_level": "高风险",
        "intervention_goal": "stop_sensitive_info",
        "explanation": "公检法身份包装叠加涉案、保密、视频笔录或安全账户要求，符合冒充公检法恐吓组合。",
        "suggested_action": "不要转入安全账户或提供密码，挂断后通过 110、96110 或当地公安公开渠道独立核验。",
        "source": "behavior_combination_rules",
    },
    {
        "rule_id": "RULE_INVESTMENT_SECURITIES_BEHAVIOR_001",
        "rule_name": "假冒证券投资行为组合规则",
        "fraud_type": "虚假投资理财诈骗",
        "conditions": {
            "must_include_any": [
                ["证券公司", "证券顾问", "股票", "投资群"],
                ["推荐股票", "盈利截图", "内部通道", "非本人账户", "社交平台链接", "交易", "投资款"],
            ]
        },
        "risk_score": 86,
        "risk_level": "高风险",
        "intervention_goal": "stop_transfer",
        "explanation": "证券身份包装叠加投资群、盈利截图、非本人账户或内部通道，属于假冒证券投资引流风险。",
        "suggested_action": "不要向个人或非官方账户入金，使用证券公司官网和监管公开渠道核验人员与平台。",
        "source": "behavior_combination_rules",
    },
]

BRUSHING_CONTEXT_PATTERN = re.compile(
    r"(刷单|刷好评|好评返现|做任务|点赞任务|关注任务|点赞|关注|淘宝刷单|返佣|返利|返钱|返现|补单|连单|联单)"
)
STRONG_ACQUAINTANCE_PATTERN = re.compile(r"(冒充|自称|领导|亲友|同学|同事|室友|舍友|朋友借钱|熟人借钱|亲戚借钱|换号|新微信号|不方便电话|代付|周转)")
INVESTMENT_CONTEXT_PATTERN = re.compile(
    r"(投资|理财|虚拟币|虚拟货币|BTC|btc|比特币|股票|基金|带单|老师|导师|稳赚|高收益|内幕|投资平台|投资App|交易平台)"
)
INVESTMENT_HIGH_RISK_PATTERN = re.compile(r"(提现失败|不能提现|提不出来|无法提现|账户冻结|解冻费|税费|继续入金|继续充值|继续交|下载.{0,8}(App|APP|app|软件|平台)|充值|入金)")
ROMANCE_CONTEXT_PATTERN = re.compile(r"(杀猪盘|网恋|恋爱|婚恋|暧昧|对象|男女朋友|男朋友|女朋友|情感|每天关心|交友)")
LOAN_CONTEXT_PATTERN = re.compile(
    r"(网络贷款|贷款|放款|贷款App|贷款APP|贷款app|贷款软件|借款平台|借款App|借款APP|借款app|借款软件|"
    r"银行卡填错|放款前|刷流水|包装费|会员费|资料费|校园贷|学生贷款|注销贷款|提升额度)"
)
GAME_TRADE_CONTEXT_PATTERN = re.compile(
    r"(游戏群|游戏交易|游戏装备|游戏账号|装备|账号交易|皮肤|点券|代充|验货|卖号|买号|担保交易|"
    r"王者荣耀|金铲铲|DNF|原神|和平精英|游戏币|代练|上分|游戏内|副本|异色宠物|仓库道具)"
)
CAMPUS_LOAN_CONTEXT_PATTERN = re.compile(r"(校园贷|注销校园贷|注销贷款|征信|影响征信|清空额度|学生贷款|校园额度|学生账户)")


BENIGN_PROCESS_PATTERNS = (
    r"官方(?:App|APP|app|应用|平台|订单|网站|账户|渠道|客服电话)",
    r"原购物平台",
    r"航空公司官方",
    r"官方缴费平台",
    r"营业厅",
    r"正式合同",
    r"正规平台",
    r"平台暂存",
    r"确认收货后",
    r"原路返回",
    r"双方(?:按照|依据)合同",
    r"双方协商",
    r"入住和退房照片",
    r"通过平台支付",
    r"电子凭证",
    r"没有(?:陌生人|对方).{0,24}(承诺|要求)",
    r"没有要求.{0,24}(提前|继续|先).{0,12}(转|交|入金|充值|服务费|验证码)",
    r"没有把验证码发给任何人",
    r"未(?:要求|提供|发送).{0,24}(转账|服务费|验证码|个人信息)",
)

BENIGN_CONTRADICTION_PATTERN = re.compile(
    r"(私人账户|个人账户|脱离平台|不走平台|陌生链接|验证码|屏幕共享|共享屏幕|远程控制|远程操作|"
    r"下载.{0,8}(?:App|APP|app|软件)|解冻费|保证金|激活费|税费|充值|入金|提现失败|拒绝退款|拉黑|失联|"
    r"账号异常|转到认证账户|贷款额度转出|点击.{0,12}(?:链接|网址|二维码)|扫码|转账|汇款|"
    r"提供.{0,12}(?:身份证|银行卡|验证码|支付密码))"
)


EXPLICIT_VERIFIED_BENIGN_PATTERNS = (
    r"银行App.{0,40}(信用卡活动|返现).{0,48}(进账单|没人加我|没人.{0,8}让我).{0,32}(没|不).{0,8}(垫|任务)",
    r"游戏自带市场.{0,48}(冻结|暂存).{0,24}(系统|平台|买家).{0,36}(确认|到账).{0,48}(没|未).{0,12}(加|私聊|联系方式)",
    r"银行风控.{0,48}挂断.{0,48}(卡背面|官方).{0,16}(号码|电话).{0,24}(打回|回拨|确认)",
    r"持牌券商App.{0,48}(指数基金|基金).{0,48}(赎回|到账).{0,24}(页面规则|合同规则)",
    r"国家开发银行.{0,32}助学贷款.{0,48}(学校|老师).{0,16}(核|回执).{0,48}(合同|学费)",
    r"平台App.{0,36}(原路退|原路返).{0,32}(信用卡|账单).{0,32}(没|未).{0,12}(私聊|信息)",
    r"银行网点.{0,40}(柜台|面签).{0,36}合同.{0,48}(本人卡|本人账户).{0,36}(没有|没).{0,12}(保证金|先交|提前交)",
    r"当面.{0,32}借.{0,12}(钱|款|万|元).{0,48}(身份证|本人银行卡).{0,32}(借条|合同).{0,48}(按约|还了|还款)",
)


def _is_explicitly_verified_benign(text: str) -> bool:
    """Match a complete verified process, not isolated words such as 官方."""
    return any(re.search(pattern, text or "", re.IGNORECASE) for pattern in EXPLICIT_VERIFIED_BENIGN_PATTERNS)


def _is_clarification_only(text: str) -> bool:
    """Keep short ambiguous questions unclassified until a risky action is known."""
    compact = re.sub(r"\s+", "", text or "")
    if len(compact) > 55:
        return False
    if re.search(
        r"(验证码|短信码|支付密码|安全账户|屏幕共享|远程控制|共享屏幕|解冻费|保证金|"
        r"刷流水|银行卡填错|先转|已转|转了|付了|正在付|下载.{0,8}(?:App|软件)|金条)",
        compact,
        re.IGNORECASE,
    ):
        return False
    return bool(
        re.search(
            r"(这轮做完就能回|游戏里那个交易咋弄|有个说是办案的|老师说这票能上|"
            r"学校群有人说能领|客服说能退|额度批了.{0,8}差一步|换号了问我借点).{0,16}(咋办|怎么|真假|真的假的|买吗|能继续|能给|？|\?)?",
            compact,
        )
    )


def _has_active_marker(text: str, pattern: str) -> bool:
    """Match a risk marker unless it is explicitly negated in nearby text."""
    for match in re.finditer(pattern, text or "", re.IGNORECASE):
        prefix = (text or "")[max(0, match.start() - 40) : match.start()]
        if re.search(r"(没有|没|未|不|无需|不用|拒绝|并未|不会).{0,18}$", prefix):
            continue
        return True
    return False


def _is_benign_process_context(text: str) -> bool:
    """Recognize explicit official/contractual handling without suppressing scams.

    A platform/branch/contract marker alone is not enough because scammers can
    impersonate those entities.  The text must also lack active private-channel
    or sensitive-operation markers; negated markers such as “没有把验证码发给
    任何人” are treated as safe evidence.
    """
    text = text or ""
    if _is_explicitly_verified_benign(text):
        return True
    if not any(re.search(pattern, text, re.IGNORECASE) for pattern in BENIGN_PROCESS_PATTERNS):
        return False
    return not any(_has_active_marker(text, pattern) for pattern in [BENIGN_CONTRADICTION_PATTERN.pattern])


def _specific_primary_fraud_type(text: str) -> str:
    """Return a high-confidence specific scene before broad parent rules.

    These combinations deliberately require a scene anchor. Generic words such
    as 客服、链接、转账 must not be sufficient on their own.
    """
    text = text or ""

    # Explicitly safe official/contractual flows must not be forced into a
    # fraud scene merely because they mention refunds, loans, tickets or codes.
    if _is_benign_process_context(text):
        return ""

    if re.search(r"(线上做笔录|协查员|市局|穿警服|违禁卡|资金清白|做证物)", text) and re.search(
        r"(一个人|酒店|银行卡|金条|余额|归集|网贷|飞书|共享|摄像头)", text
    ):
        return "冒充公检法诈骗"

    if re.search(r"(养数据|拍一单|联单|连单|连淡|三个单子绑|订单锁住|差评价)", text) and re.search(
        r"(本金|工钱|原路退|再付|补|垫|解锁|倒计时|共享)", text
    ):
        return "刷单返利诈骗"

    if re.search(r"(公会|游戏|材料|陪练|比赛号|仓库|远程看号)", text) and re.search(
        r"(小号|防跑单金|押金|二次认证|解绑短信|扫码|远程看号|邮给)", text
    ):
        return "游戏交易诈骗"

    if re.search(r"(量化内测|行情插件|商品子账户|稳定币|夜盘|酒庄分红|投进去)", text) and re.search(
        r"(入金|装|钱包|充|提现|担保|冻结|保证份额|网贷)", text
    ):
        return "虚假投资理财诈骗"

    if re.search(r"(学生分期|学生身份|校园贷|教育金融中心|校园额度)", text) and re.search(
        r"(清掉|销户|注销|对冲|旧记录|管理费|清算卡|统一转)", text
    ):
        return "征信修复/注销账户诈骗"

    if re.search(r"(批次有问题|三倍补偿|赔付组|银行售后|商户保障|快递|售后)", text) and re.search(
        r"(视频软件|钱包编号|短信数字|借款页面|清算户|手机钱包|看着我操作)", text
    ):
        return "冒充客服诈骗"

    if re.search(r"(贷款审核|放款通过|贷款平台|中介|器材分期|学费周转)", text) and re.search(
        r"(购物卡|卡密|取.{0,4}现金|跑腿|包装费|过一晚上|公司|店铺码|撤合同)", text
    ):
        return "网络贷款诈骗"

    if re.search(r"视频", text) and re.search(r"(脸.{0,8}卡|只会点头|声音.{0,8}不对|不肯说.{0,8}暗号)", text) and re.search(
        r"(打款|转账|收款人|名额|借钱)", text
    ):
        return "AI换脸冒充熟人诈骗"

    if re.search(r"(室友|导师|表哥|舅舅|家族群|新号|亲友)", text) and re.search(
        r"(不方便视频|不接电话|充值卡|卡密|缴费单|尾款|暗号|收款人|发的账户)", text
    ):
        return "冒充领导或熟人借钱诈骗"

    if re.search(r"视频会议", text) and re.search(r"(几张卡|多张卡|银行卡).{0,24}余额", text) and re.search(
        r"(归集|不让.{0,8}(开门|见人)|不能有旁人|资金清查)", text
    ):
        return "冒充公检法诈骗"

    if re.search(r"(假警察|冒充公检法|公检法|公安|警察|检察院|法院|办案人员)", text) and re.search(
        r"(通缉令|逮捕令|涉案|洗钱|安全账户|资金清查|资金审查|保密|屏幕共享|转账)", text
    ):
        return "冒充公检法诈骗"

    # Domain-specific transaction scenes outrank downstream tooling such as a
    # remote desktop or a phishing page.  The same message can contain both,
    # but the user-facing primary type should describe the original lure.
    if re.search(
        r"(游戏账号|游戏装备|游戏币|点券|代练|上分|游戏内|副本|异色宠物|仓库道具|"
        r"王者荣耀|金铲铲|DNF|原神|和平精英)",
        text,
        re.IGNORECASE,
    ) and re.search(
        r"(买|卖|交易|付款|给钱|找回|拉黑|不退|退一半|保证金|担保|捡走|改名|改密码|"
        r"没给钱|未付款|充值|抢回|用了|发货|账号|装备|材料|宠物)",
        text,
        re.IGNORECASE,
    ):
        return "游戏交易诈骗"

    if re.search(r"(航班|机票|火车票|车次|航司)", text) and re.search(
        r"(取消|延误|退票|改签|补偿|理赔).{0,48}(链接|验证码|银行卡|身份证|支付)", text
    ):
        return "机票火车票退改签诈骗"

    if re.search(r"(招聘|求职|实习|入职|岗位|招聘专员)", text) and re.search(
        r"(账号管理费|入职费|入职押金|培训费|报名费|资料费|保证金|服务费|手续费|交费|缴费)", text
    ):
        return "求职实习招聘诈骗"

    if re.search(r"(网贷|贷款|借款|放款|贷款App|贷款APP|贷款软件)", text) and re.search(
        r"(放款前|会员费|风险保证金|贷款额度|银行卡填|认证账户|资料费|包装费|刷流水)", text
    ) and not re.search(r"(征信|不良记录|清零|清除征信|清除不良)", text):
        return "网络贷款诈骗"

    if re.search(r"(投资|理财|虚拟币|虚拟货币|BTC|btc|比特币|股票|基金|交易平台)", text) and not re.search(
        ROMANCE_CONTEXT_PATTERN, text
    ) and re.search(
        r"(投资会员|会员群|投资群|所谓老师|月费|退款|不让退|亏|损失|下跌|缩水|归零|资产只剩|投入|买入|"
        r"不能提现|提现失败|充值|入金|转账|交钱|高收益|稳赚)", text
    ):
        return "虚假投资理财诈骗"

    if re.search(r"(客服|商家客服|平台客服|快递客服|电商客服)", text) and re.search(
        r"(售后退款|退款|理赔|订单异常|验证身份).{0,48}(二维码|链接|验证码|短信码|支付密码|银行卡)", text
    ) and not re.search(r"(刚收到|支付验证码|动态码|新号码|追回损失|账户扣|发给他|告诉他|提供给他)", text):
        return "冒充客服诈骗"

    # A code request is the primary risk only when the text makes the
    # credential hand-off explicit; preserve the historical broad customer
    # service label for generic “客服退款+验证码” wording.
    if re.search(r"(验证码|短信码|动态码|支付验证码)", text) and re.search(
        r"(刚收到|支付验证码|动态码|新号码|追回损失|账户扣|发给他|告诉他|提供给他)", text
    ):
        return "验证码/账户盗刷诈骗"

    # High-signal actions take precedence over the identity or marketplace
    # wrapper around them.  This prevents ticket/customer-service aliases from
    # stealing a clear remote-control case.
    if re.search(r"(屏幕共享|共享屏幕|远程控制|远程协助|远程工具|远程操作|控制(?:手机|电脑)|远程检查)", text) and not (
        re.search(r"(客服|商家客服|平台客服|电商客服|快递客服)", text)
        and re.search(r"(退款|理赔|订单|补偿|赔偿)", text)
        and not re.search(r"(手机银行|银行App|银行 APP|银行账户|银行卡余额)", text, re.IGNORECASE)
    ):
        return "屏幕共享/远程控制诈骗"
    if re.search(r"(电脑|手机).{0,30}(付款码|解锁|被锁|不能使用).{0,30}(装系统|安装|远程|软件|帮我)", text):
        return "屏幕共享/远程控制诈骗"

    # Narrow scene anchors are evaluated before broad “客服/熟人/购物” rules.
    if re.search(r"(老师|班主任|辅导员|家长群|班级群)", text) and re.search(
        r"(班费|资料费|教材费|培训费|收款码|缴费|激活费|中奖)", text
    ):
        return "冒充老师辅导员收费诈骗"
    if re.search(r"(裸聊|裸聊软件|裸聊App|不雅视频|裸照)", text) and re.search(
        r"(会员|每小时|收费|退款|通讯录|联系人|威胁|转账|付款)", text
    ):
        return "裸聊敲诈勒索诈骗"

    game_scene = re.search(
        r"(游戏账号|游戏装备|游戏币|点券|代练|上分|游戏内|副本|异色宠物|仓库道具|"
        r"王者荣耀|金铲铲|DNF|原神|和平精英)",
        text,
        re.IGNORECASE,
    )
    if game_scene and re.search(
        r"(买|卖|交易|付款|给钱|找回|拉黑|不退|退一半|保证金|担保|捡走|改名|改密码|"
        r"没给钱|未付款|充值|抢回|用了|发货|账号|装备|材料|宠物)",
        text,
        re.IGNORECASE,
    ):
        return "游戏交易诈骗"

    if re.search(r"(中奖|中(?:了|奖)|免费领|苹果手机|福利礼品)", text) and re.search(
        r"(消息|通知|收到|资格|领取|兑奖|领奖)", text
    ):
        return "虚假中奖/免费礼品诈骗"

    if re.search(r"(商家|卖家|商品|购物平台|闲鱼|代购|订单)", text) and re.search(
        r"(不走平台|平台外|转到微信|转到支付宝|私人账户|先付|定金|订金|付款|质量|退款|不退款|不发货|拉黑)",
        text,
    ) and not game_scene:
        return "虚假购物服务诈骗"

    service_scene = re.search(r"(客服|快递|物流|电商|网店|商品|订单|会员|售后|店铺|商家)", text)
    if service_scene and re.search(
        r"(退款|理赔|赔偿|取消会员|自动扣费|会员费|补运费|超重|丢失|开通会员|订单异常)", text
    ):
        return "冒充客服诈骗"

    if re.search(r"(网恋|恋爱|婚恋|暧昧|男朋友|女朋友|对象|交友)", text) and re.search(
        r"(投资|理财|虚拟币|博彩|刷单|平台|入金|提现|充值|借钱|借款|开店|周转)", text
    ):
        return "情感交友诱导投资诈骗"

    if re.search(r"(赌博网站|博彩|娱乐城|下注)", text) and re.search(
        r"(提现|充值|到账|解冻|交钱|继续)", text
    ):
        return "虚假投资理财诈骗"
    if re.search(r"(投资|理财|虚拟币|虚拟货币|BTC|btc|比特币|股票|基金|交易平台)", text) and re.search(
        r"(亏|损失|下跌|缩水|归零|资产只剩|投入|买入|不能提现|提现失败|充值|入金|转账|交钱|高收益|稳赚|平台|老师|群)", text
    ):
        return "虚假投资理财诈骗"

    if re.search(r"(老朋友|老同学|熟人|朋友).{0,24}(借钱|借款|周转|转账)", text) and re.search(
        r"(从来没有借过|完全没这回事|不是原来的朋友|不是他本人|转账后|转完后|才发现)", text
    ) or (
        re.search(r"(换了新手机号|换号|新微信号|新手机号)", text)
        and re.search(r"(转账|转钱|转到|把钱|代付|借钱|借款|收款)", text)
        and re.search(r"(不是原来的|不是他本人|才发现|转完后|转账后)", text)
    ):
        return "冒充领导或熟人借钱诈骗"

    if re.search(r"(征信|不良记录).{0,24}(修复|清除|注销|认证|影响|处理|额度转出|认证账户)", text) or re.search(
        r"(贷款额度转到|转到认证账户|清除征信|清除不良记录|征信问题)", text
    ):
        return "征信修复/注销账户诈骗"
    if re.search(r"(黑网贷|网贷.{0,20}(不用还|不需要还|注销|会员)|贷款.{0,20}(不用还|银行卡填|认证账户|少收利息))", text):
        return "网络贷款诈骗"
    if re.search(r"(贷款|借款|放款|网贷).{0,24}(银行卡.{0,16}(公司|认证|填)|认证账户|少收利息|资料费|包装费)", text):
        return "网络贷款诈骗"

    if re.search(r"(刷.{0,4}好评|好评返现|刷单).{0,32}(买.{0,12}(商品|店铺)|返|佣金|垫付|好评)", text):
        return "刷单返利诈骗"

    if re.search(r"(收同学|收卡人员|收卡中介|银行卡|电话卡|实名办卡)", text) and re.search(
        r"(按流水|佣金|渠道|赚大钱|走账|出租|出借|收款|转出去)", text
    ):
        return "两卡出租出借与跑分诈骗"

    if re.search(r"(扫码|二维码).{0,16}(助力|提现|领|加速)", text) and re.search(
        r"(银行卡|扣款|少了|转账|钱)", text
    ):
        return "钓鱼链接诈骗"
    if re.search(r"(点开|点击|打开).{0,20}(链接|页面|网页|资料)", text) and re.search(
        r"(账号.{0,8}风控|账号被盗|账号没了|密码|验证码|银行卡)", text
    ):
        return "钓鱼链接诈骗"

    if re.search(r"(考证|考证班|资格证|证书班|报考)", text) and re.search(
        r"(课程|退课|退款|退费|只退|不值|宣传|差距)", text
    ):
        return "考试考证论文服务诈骗"

    if re.search(r"(租房|房东|中介|房源|公寓|租客)", text) and re.search(
        r"(押金|定金|租金|看房|合同|私人账户|先交|先转|不退|拒绝退款|失联)", text
    ):
        return "租房合租押金诈骗"

    for fraud_type, pattern in BEHAVIOR_TYPE_PATTERNS:
        if fraud_type == "冒充客服诈骗" and LOAN_CONTEXT_PATTERN.search(text):
            # “贷款客服” is a role label inside a loan scam.  Keep the loan
            # scene primary unless the text also names an e-commerce/parcel
            # service (handled by the explicit service pattern below).
            if not re.search(r"(快递|物流|电商|网店|商品|订单|包裹|退款|理赔)", text):
                continue
        if re.search(pattern, text, re.IGNORECASE):
            return fraud_type
    if re.search(r"(演唱会|音乐节|赛事|景区|门票|电子票|验票|出票|转票|黄牛|内部票)", text):
        return "校园二手/票务交易诈骗"
    if re.search(r"(租借|出租|出借|收购|高价收).{0,12}(银行卡|电话卡|手机卡|U盾|收款码|实名账号)|"
                 r"(银行卡|电话卡|手机卡|U盾|收款码|实名账号).{0,12}(租借|出租|出借|收购|走账|刷流水)", text):
        return "两卡出租出借与跑分诈骗"
    if re.search(r"(代购上线|上线要求|被害人的被骗资金|帮忙过账|代收代付|跑腿取现|取现后|购买名表|购买黄金)", text):
        return "两卡出租出借与跑分诈骗"
    if re.search(r"(AI换脸|AI 换脸|拟声|仿冒亲友|仿冒亲属|视频里像|声音很像|声音像|自拍视频|视频只说|语音借钱|亲属委托)", text):
        return "AI换脸冒充熟人诈骗"
    if re.search(r"(征信修复|修复征信|注销校园贷|注销网贷|关闭网贷账户|清空额度|清零验证|贷款额度转出|影响征信|征信处理专员|认证对接账户)", text) or re.search(r"金融平台客服.{0,24}(征信|注销|关闭|清零|影响|年费|额度)", text):
        return "征信修复/注销账户诈骗"
    if re.search(r"(屏幕共享|共享屏幕|远程控制|远程协助|远程协助插件|会议软件)", text):
        return "屏幕共享/远程控制诈骗"
    if re.search(r"(账号验证客服|二次认证|接收验证码|提供短信动态码|支付验证码|收款验证码|验证码不涉及钱)", text):
        return "验证码/账户盗刷诈骗"
    if (
        BRUSHING_CONTEXT_PATTERN.search(text)
        and not ROMANCE_CONTEXT_PATTERN.search(text)
        and not INVESTMENT_CONTEXT_PATTERN.search(text)
    ) or re.search(r"(店铺冲销量|组合任务|派单客服|兼职日结).{0,30}(垫付|补单|结算|提现|订单)", text):
        return "刷单返利诈骗"
    return ""

BASE_FEATURE_SCORES: Dict[str, int] = {
    "陌生人引导": 10,
    "任务返佣": 25,
    "已发生转账": 45,
    "索要验证码": 35,
    "索要银行卡或身份信息": 35,
    "索要银行流水或卡号": 40,
    "冒充公检法": 45,
    "涉案违法物品恐吓": 45,
    "冒充客服": 30,
    "要求垫付资金": 35,
    "承诺返利": 20,
    "小额返利": 15,
    "高收益诱导": 30,
    "保本稳赚承诺": 25,
    "无法提现": 40,
    "点击陌生链接": 25,
    "私下交易": 30,
    "低价代充": 25,
    "账号密码索取": 35,
    "诱导下载陌生APP": 35,
    "贷款前收费": 35,
    "校园贷包装": 25,
    "屏幕共享": 40,
    "远程控制": 40,
    "要求继续补单": 40,
    "要求缴纳解冻费": 40,
    "要求删除证据": 30,
}

INTERVENTION_GOAL_ALIASES = {
    "stop_screen_sharing": "stop_screen_share",
    "stop_screen_share": "stop_screen_share",
    "stop_remote_control": "stop_screen_share",
    "stop_transfer": "stop_transfer",
    "stop_payment": "stop_transfer",
    "stop_code_leak": "stop_code_leak",
    "stop_verification_code": "stop_code_leak",
    "stop_sensitive_info": "stop_sensitive_info",
    "stop_sensitive_information": "stop_sensitive_info",
    "stop_app_install": "stop_app_install",
    "stop_click_link": "stop_click_link",
    "call_police": "call_police",
    "preserve_evidence": "preserve_evidence",
    "ask_clarification": "ask_clarification",
}

DEFAULT_ADVICE_TEMPLATE_IDS = {
    "PKG_SERVICE_CODE_001": "ADV_CODE_HIGH_001",
    "PKG_SERVICE_SCREEN_001": "ADV_SERVICE_SCREEN_HIGH_001",
    "PKG_JOB_FEE_HIGH_001": "ADV_JOB_FEE_HIGH_001",
}


def risk_level_from_score(score: int) -> str:
    if score >= 80:
        return "极高风险"
    if score >= 60:
        return "高风险"
    if score >= 30:
        return "中风险"
    if score > 0:
        return "低风险"
    return "风险未知"


def _rules_dir() -> Path:
    override = os.getenv("ANTI_FRAUD_RULES_DIR")
    if override:
        return Path(override)
    return Path(__file__).resolve().parents[1] / "rules"


def normalize_intervention_goal(value: Any) -> str:
    goal = str(value or "").strip()
    return INTERVENTION_GOAL_ALIASES.get(goal, goal)


def _dedupe(items: Iterable[Any], limit: int = 8) -> List[str]:
    result: List[str] = []
    for item in items:
        text = str(item or "").strip()
        if text and text not in result:
            result.append(text)
        if len(result) >= limit:
            break
    return result


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def rule_config_root() -> Path:
    return _rules_dir()


def reload_rule_config() -> Dict[str, Any]:
    """Hot-reload JSON/Mongo rule config without restarting the service."""
    load_scam_packages.cache_clear()
    cache_clear = getattr(_load_rules, "cache_clear", None)
    if callable(cache_clear):
        cache_clear()
    packages = load_scam_packages()
    return {
        "message": "规则配置已热更新",
        "rules_dir": str(_rules_dir()),
        "package_count": len(packages),
        "packages": [
            {
                "scam_id": package.get("scam_id", ""),
                "name": package.get("name", ""),
                "version": package.get("version", ""),
                "rule_count": len(package.get("rules") or []),
                "path": package.get("_package_path", ""),
            }
            for package in packages
        ],
    }


@lru_cache(maxsize=1)
def load_scam_packages() -> List[Dict[str, Any]]:
    """Load local Scam Package JSON files.

    Invalid packages are skipped with a warning so one experimental package
    cannot break production risk checks.
    """
    package_dir = _rules_dir() / "scam_packages"
    if not package_dir.exists():
        return []

    packages: List[Dict[str, Any]] = []
    for path in sorted(package_dir.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("配置包顶层必须是对象")
            if not data.get("scam_id") or not data.get("name"):
                raise ValueError("配置包缺少 scam_id/name")
            data["_package_path"] = str(path)
            packages.append(data)
        except Exception as exc:
            logger.warning(f"Scam Package 加载失败，已跳过 {path}: {exc}")
    return packages


def _package_feature_docs() -> List[Dict[str, Any]]:
    features: List[Dict[str, Any]] = []
    for package in load_scam_packages():
        for item in package.get("features") or []:
            if not isinstance(item, dict) or not item.get("feature_name"):
                continue
            features.append(
                {
                    "feature_name": str(item.get("feature_name")),
                    "keywords": [str(word) for word in item.get("keywords") or [] if word],
                    "weight": int(item.get("weight", 20) or 20),
                    "explanation": str(item.get("explanation") or ""),
                    "fraud_type": str(package.get("name") or ""),
                    "source": f"scam_package:{package.get('scam_id')}",
                }
            )
    return features


def _package_rules() -> List[Dict[str, Any]]:
    rules: List[Dict[str, Any]] = []
    for package in load_scam_packages():
        fraud_type = str(package.get("name") or "")
        for item in package.get("rules") or []:
            if not isinstance(item, dict) or not item.get("rule_id"):
                continue
            score = int(item.get("risk_score", item.get("score", 0)) or 0)
            rule_fraud_type = str(item.get("fraud_type") or item.get("risk_scene") or fraud_type)
            doc = {
                "rule_id": str(item.get("rule_id")),
                "rule_name": str(item.get("rule_name") or item.get("name") or f"{rule_fraud_type}配置包规则"),
                "fraud_type": rule_fraud_type,
                "stages": item.get("stages") or item.get("risk_stages") or [],
                "conditions": item.get("conditions") or {},
                "risk_score": score,
                "score": score,
                "risk_level": str(item.get("risk_level") or item.get("min_level") or risk_level_from_score(score)),
                "intervention_goal": normalize_intervention_goal(item.get("intervention_goal") or item.get("intervention_action") or "stop_transfer"),
                "advice_template_id": str(item.get("advice_template_id") or item.get("advice_template") or ""),
                "explanation": str(item.get("explanation") or ""),
                "suggested_action": str(
                    item.get("suggested_action")
                    or item.get("dissuasion_text")
                    or item.get("intervention_text")
                    or item.get("reply_template")
                    or ""
                ),
                "enabled": item.get("enabled", True),
                "source": f"scam_package:{package.get('scam_id')}",
            }
            rules.append(doc)
    return rules


def infer_fraud_types(text: str) -> List[str]:
    """Infer candidate scam types from core aliases and Scam Packages."""
    lowered = (text or "").lower()
    mapping: List[Tuple[str, List[str]]] = list(CORE_FRAUD_TYPE_ALIASES)
    for package in load_scam_packages():
        if not _package_context_active(package, text):
            continue
        aliases = [str(item) for item in package.get("aliases") or [] if item]
        mapping.append((str(package.get("name") or ""), aliases + [str(package.get("name") or "")]))

    result: List[str] = []
    seen = set()
    specific_primary = _specific_primary_fraud_type(text)
    if specific_primary:
        result.append(specific_primary)
        seen.add(specific_primary)
    for fraud_type, words in mapping:
        if not fraud_type:
            continue
        if any(word and word.lower() in lowered for word in words):
            if fraud_type not in seen:
                result.append(fraud_type)
                seen.add(fraud_type)
    return result or ["未知"]


def _prioritize_specific_fraud_types(text: str, fraud_types: List[str]) -> List[str]:
    """Move more specific scam scenes ahead of broad relationship labels."""
    text = text or ""
    brushing_context = bool(BRUSHING_CONTEXT_PATTERN.search(text))
    strong_acquaintance = bool(STRONG_ACQUAINTANCE_PATTERN.search(text))
    if brushing_context and not strong_acquaintance:
        fraud_types = [item for item in fraud_types if item != "冒充熟人诈骗"]
    priority: List[str] = []
    specific_primary = _specific_primary_fraud_type(text)
    if specific_primary:
        priority.append(specific_primary)
    investment_context = bool(INVESTMENT_CONTEXT_PATTERN.search(text))
    romance_context = bool(ROMANCE_CONTEXT_PATTERN.search(text))
    loan_context = bool(LOAN_CONTEXT_PATTERN.search(text))
    game_trade_context = bool(GAME_TRADE_CONTEXT_PATTERN.search(text))
    campus_loan_context = bool(CAMPUS_LOAN_CONTEXT_PATTERN.search(text))
    if brushing_context and not loan_context:
        fraud_types = [item for item in fraud_types if item != "网络贷款诈骗"]
    if investment_context and not loan_context:
        fraud_types = [item for item in fraud_types if item != "网络贷款诈骗"]
    if investment_context and not romance_context:
        fraud_types = [item for item in fraud_types if item not in {"杀猪盘诈骗", "情感交友诱导投资诈骗"}]
    if game_trade_context:
        fraud_types = [item for item in fraud_types if item not in {"网络贷款诈骗", "冒充熟人诈骗"}]
    if campus_loan_context and not game_trade_context:
        fraud_types = [item for item in fraud_types if item != "游戏交易诈骗"]
    virtual_currency_laundering_context = bool(
        re.search(r"(USDT|usdt|虚拟币|虚拟货币|数字货币|钱包地址|链上转账|买U|U商)", text)
        and re.search(r"(跑分|刷流水|代收|收款|收款码|代收代付|帮忙过账|转一圈|高佣金|日结)", text)
    )
    live_private_trade_context = bool(
        re.search(r"(直播间|直播带货|直播购物|私域|福利群|群接龙|加客服微信|小程序下单)", text)
        and re.search(r"(扫码付款|私下付款|微信转账|支付宝转账|不走平台|低价|内部价|福利价|清仓|限时秒杀)", text)
    )
    if virtual_currency_laundering_context:
        fraud_types = [item for item in fraud_types if item != "网络贷款诈骗"]
    if live_private_trade_context and not re.search(r"(退款|理赔|取消会员|百万保障|快递|售后退款)", text):
        fraud_types = [item for item in fraud_types if item != "冒充客服诈骗"]
    if investment_context and (INVESTMENT_HIGH_RISK_PATTERN.search(text) or "虚假投资理财诈骗" in fraud_types):
        priority.append("虚假投资理财诈骗")
    if re.search(r"(中奖|领奖|兑奖|免费领|抽中|福利礼品|盲盒)", text):
        priority.append("虚假中奖/免费礼品诈骗")
    if re.search(r"(助学金|奖助学金|奖学金|学费退费|教育补贴|补贴到账|资助金)", text):
        priority.append("奖助学金/学费退费诈骗")
    if re.search(r"(求职|实习|招聘|就业班|推荐实习|就业推荐|新媒体运营|运营就业班|培训费|培训贷|入职押金|保offer|不就业全额退款)", text):
        priority.append("求职实习招聘诈骗")
    if re.search(r"(航班|机票|火车票|车次|退票|退改签|航班取消|航班延误|退票理赔|改签理赔)", text):
        priority.append("机票火车票退改签诈骗")
    if re.search(r"(两卡|跑分|出租银行卡|出借银行卡|出租电话卡|收款码|帮忙收款|转出去)", text):
        priority.append("两卡出租出借与跑分诈骗")
    if virtual_currency_laundering_context:
        priority.append("虚拟货币洗钱跑分诈骗")
    if live_private_trade_context:
        priority.append("直播带货/私域交易诈骗")
    if brushing_context:
        priority.append("刷单返利诈骗")
    if game_trade_context:
        priority.append("游戏交易诈骗")
    if re.search(r"(安全账户|公检法|涉案|洗钱|通缉令|逮捕令|违法物品|违禁品|涉案物品|违法包裹|涉嫌违法)", text):
        priority.append("冒充公检法诈骗")
    if re.search(r"(解冻费|刷流水|放款前|贷款App|贷款APP|校园贷|征信|注销校园贷|清空额度)", text, re.IGNORECASE) and loan_context and not investment_context and not brushing_context:
        priority.append("网络贷款诈骗")

    reordered: List[str] = []
    for item in priority + fraud_types:
        if item and item not in reordered:
            reordered.append(item)
    return reordered or fraud_types


def _is_true(value: Any) -> bool:
    return value is True or str(value).lower() == "true"


def _is_small_rebate_returned(slots: Dict[str, Any], features: Iterable[str] | None = None, text: str = "") -> bool:
    features = set(features or [])
    merged = f"{text or ''} {' '.join(features)}"
    if not _is_true(slots.get("has_paid")):
        return False
    if not (_is_true(slots.get("has_received_rebate")) or "小额返利" in features):
        return False
    if _is_true(slots.get("has_unrecovered_loss")):
        return False
    return not re.search(r"(没返|未返|提现失败|不能提现|提不出来|无法提现|冻结|解冻费|钱没回来|损失|亏了)", merged)


def _extra_features(text: str, slots: Dict[str, Any]) -> List[str]:
    compact = re.sub(r"\s+", "", text or "")
    current_action = str(slots.get("current_requested_action") or "")
    features: List[str] = []
    if re.search(r"(收卡人员|收卡中介|实名办卡|租借.{0,12}(银行卡|电话卡)|银行卡.{0,12}(电话卡|POS).{0,18}(租金|绑定|走账)|公司走账)", compact):
        features.append("出租出借两卡")
    if re.search(r"(代收代付|帮忙收款|跑腿取现|代购上线|购买名表|闲置交易平台).{0,36}(银行卡|收款|转账|过账|脱离平台)", compact):
        features.append("帮忙收款跑分")
    if re.search(r"(AI换脸|AI 换脸|拟声|仿冒亲友|仿冒亲属|视频里像|声音很像|亲属委托)", text):
        features.append("AI换脸冒充")
    if re.search(r"视频", text) and re.search(r"(脸.{0,8}卡|只会点头|声音.{0,8}不对|不肯说.{0,8}暗号)", text):
        features.append("AI换脸冒充")
    if re.search(r"(征信处理专员|征信修复|修复征信|注销校园贷|注销网贷|关闭网贷账户|清零验证|认证对接账户|影响征信)", compact) or re.search(r"金融平台客服.{0,24}(征信|注销|关闭|清零|影响|年费|额度)", compact):
        features.append("征信会员恐吓")
        if re.search(r"(注销|关闭|修复|清零|转账|服务费|下载|年费|验证码|身份证|贷款额度)", compact):
            features.append("注销账户修复征信")
    if re.search(r"返\s*\d+", text) or re.search(r"\d+\s*返\s*\d+", text):
        features.append("承诺返利")
    if re.search(r"(返了|返过|返钱|返现|返佣|返利)", text):
        features.append("承诺返利")
    if re.search(r"(点赞|关注|短视频|刷单|做任务).{0,18}(赚钱|返利|返佣|返钱|一单|每单)|((一单|每单).{0,8}(赚|返).{0,8}\d+)", text):
        features.append("任务返佣")
    if re.search(
        r"(前|头)?[一二两三\d]+单.{0,16}(返了|返还|返回给我|返给我|返现|返钱|返佣|到账|赚了)"
        r"|小额.{0,6}(返利|返现|返钱|返佣)"
        r"|(已经|已|刚刚|刚才)?.{0,10}(返了|返还了|返回给我了?|返给我了?|返现了|返钱了|返佣了|到账了|赚了)\s*\d*",
        text,
    ):
        features.append("小额返利")
    if re.search(r"(提现|提钱|出款).{0,10}(失败|冻结|提不出来|不能|无法|才可以|才能|继续|再)|(.{0,10}(才可以|才能).{0,6}(提现|出款))", text):
        features.append("无法提现")
    if _is_true(slots.get("has_continue_payment_request")):
        features.append("要求继续补单")
    if re.search(r"(让我|叫我|要求|要我|必须|准备|马上|现在|继续|再).{0,20}(转账|汇款|付款|付钱|打款|充值|补单|垫付|垫钱|借钱|借款|借他|借她|周转|代付|帮他付|帮忙转|交钱|保证金|解冻费|税费)", compact):
        features.append("要求垫付资金")
    if any(word in text for word in ["保证金", "押金", "定金", "订金", "解冻费", "手续费", "税费", "刷流水"]):
        features.append("要求垫付资金")
    if re.search(r"(已经|已|刚|刚刚)[^，。；,;]{0,12}(转账|转钱|付款|付钱|支付|充值|打款|汇款|交钱|交费|缴费)\s*\d*", text):
        features.append("已发生转账")
    if re.search(r"(已经|已|刚|刚刚)?\s*(给|向)?[^，。；,;]{0,12}(转了|转过|转账了|付了|付款了|打款|汇了|充值了|补单了|垫付了|交了)\s*\d*", text):
        features.append("已发生转账")
    if re.search(r"(已经垫了|押金给了|已经交过|已经付过|已经投进去|按.{0,12}账户转了)", text):
        features.append("已发生转账")
    if _is_true(slots.get("has_paid")) and not _is_small_rebate_returned(slots, features, text):
        features.append("已发生转账")
    if (
        _is_true(slots.get("has_transferred_virtual_asset"))
        or re.search(r"(游戏装备|游戏账号|装备|账号|皮肤|游戏币|点券|虚拟资产).{0,20}(给他了|给对方了|给了|交给.*了|转给.*了|发给.*了|都给|已经给)", text)
        or re.search(r"(给他了|给对方了|给了|交给.*了|转给.*了|发给.*了|都给|已经给).{0,12}(游戏装备|游戏账号|装备|账号|皮肤|游戏币|点券|虚拟资产)", text)
        or re.search(r"(游戏装备|游戏账号|装备|账号|皮肤|游戏币|点券|虚拟资产)[\s\S]{0,80}(已经|已|都|全都).{0,12}(给他|给对方|给了|交给|转给|发给)", text)
    ):
        features.append("虚拟资产已交付")
    if _is_true(slots.get("counterparty_disappeared")) or re.search(r"(失联|拉黑|不回消息|联系不上|删好友|跑路)", text):
        features.append("交易对象失联")
    if re.search(
        r"(游戏装备|游戏账号|装备|账号|皮肤|游戏币|点券|虚拟资产|王者荣耀|金铲铲|DNF|原神|和平精英|"
        r"代练|上分|游戏内|副本|异色宠物|仓库道具)",
        text,
        re.IGNORECASE,
    ):
        features.append("私下游戏交易")
    if re.search(r"(价值|估值).{0,8}\d+\s*(万|w|W|元|块)|\d+\s*(万|w|W).{0,8}(装备|账号|皮肤|虚拟资产|价值)", text):
        features.append("高价值虚拟资产")
    if re.search(r"(低价代充|半价点券|低价皮肤|内部点券|便宜充值)", text):
        features.append("低价代充装备诱导")
    if re.search(r"(先|要求|让我|叫我).{0,12}(给|交|发|转).{0,12}(游戏装备|装备|游戏账号|账号|皮肤|点券|虚拟资产|验货)", text) or "先给他验货" in text:
        features.append("交付虚拟资产要求")
    if re.search(r"(微信密码|账号密码|登录密码|支付密码|把.{0,8}密码.{0,8}(告诉|发给|给)|要.{0,8}密码|索要.{0,8}密码)", text):
        features.append("账号密码索取")
    if re.search(r"(账号密码|验号|先给账号|扫码登录)", text):
        features.append("游戏账号密码索取")
    if re.search(r"(游戏|账号|装备|皮肤|点券).{0,16}(保证金|解冻费|手续费|担保费|中介费|认证金)", text):
        features.append("游戏交易保证金解冻费")
    if re.search(r"(电脑|手机).{0,30}(付款码|解锁|被锁|不能使用).{0,30}(装系统|安装|远程|软件|帮我)", text):
        features.append("远程控制")
    if re.search(r"(远程看号|装个远程|看着我操作|共享一下|开着共享)", text):
        features.append("屏幕共享")
    if re.search(r"(短信|解绑短信|短信数字).{0,12}(念给|告诉|发给|读给)", text):
        features.append("索要验证码")
    if _is_true(slots.get("has_shared_code")) or "验证码" in current_action:
        features.append("索要验证码")
    if "密码" in current_action:
        features.append("账号密码索取")
    if re.search(
        r"(让我|叫我|要求|要我|问我要|索要|需要我|说让我|说要我).{0,30}(银行卡|银行卡号|卡号|银行流水|身份证|身份证号|身份信息|个人信息|实名信息|敏感信息)",
        compact,
    ) or any(word in current_action for word in ["银行卡", "银行卡号", "卡号", "银行流水", "身份证", "身份信息", "个人信息", "敏感信息"]):
        features.append("索要银行卡或身份信息")
        if any(word in f"{compact}{current_action}" for word in ["银行流水", "卡号", "银行卡号"]):
            features.append("索要银行流水或卡号")
    if re.search(r"(违法物品|违禁品|涉案物品|违法包裹|涉嫌违法|网购.{0,8}违法)", compact):
        features.append("涉案违法物品恐吓")
        features.append("冒充公检法")
    if _is_true(slots.get("has_screen_share")):
        features.append("屏幕共享")
    if _is_true(slots.get("has_downloaded_app")):
        features.append("诱导下载陌生APP")
    if _is_true(slots.get("has_provided_identity_or_bank")):
        features.append("索要银行卡或身份信息")
    if any(word in text for word in ["投资App", "投资APP", "投资app", "投资软件"]):
        features.extend(["陌生投资平台", "诱导下载陌生APP"])
    if re.search(r"\d+\s*%.*收益|收益.*\d+\s*%", text):
        features.append("高收益诱导")
    if any(word in text for word in ["税费", "缴税"]):
        features.append("要求缴纳解冻费")
    if "安全账户" in text:
        features.extend(["冒充公检法", "要求垫付资金"])
    return features


GENERIC_PACKAGE_KEYWORDS = {
    "验证码",
    "短信码",
    "动态码",
    "登录码",
    "支付码",
    "银行卡",
    "身份证",
    "支付密码",
    "二维码",
    "链接",
    "网址",
    "http",
    "https",
    "屏幕共享",
    "共享屏幕",
    "会议软件",
    "远程协助",
    "远程控制",
    "安装会议软件",
    "我教你操作",
    "保证金",
    "押金",
    "定金",
    "订金",
    "手续费",
    "服务费",
    "培训费",
    "课程费",
    "资料费",
    "体检费",
    "报名费",
    "税费",
    "先交",
    "先付",
    "缴费",
    "交钱",
    "解冻费",
    "认证费",
    "下载",
    "下载App",
    "下载APP",
    "下载app",
    "App",
    "APP",
    "app",
    "软件",
    "平台",
    "充值",
    "老师",
    "导师",
    "提现失败",
}

GENERIC_PACKAGE_CONTEXT_TERMS = GENERIC_PACKAGE_KEYWORDS | {
    "私聊",
    "加微信",
    "微信",
    "支付宝",
    "平台外",
    "私下交易",
    "定金",
    "订金",
    "押金",
    "保证金",
    "手续费",
    "服务费",
    "先付",
    "先交",
    "转账",
    "付款",
    "收款",
    "银行卡",
    "身份证",
    "老师",
    "客服",
    "返佣",
    "跑分",
    "刷流水",
}


ROMANCE_INVESTMENT_CONTEXT_PATTERN = ROMANCE_CONTEXT_PATTERN


def _package_has_required_context(package: Dict[str, Any], text: str) -> bool:
    """Prevent broad package keywords from leaking into unrelated scenes."""
    scam_id = str(package.get("scam_id") or "")
    if scam_id == "scam_fake_loan":
        return bool(LOAN_CONTEXT_PATTERN.search(text or ""))
    if str(package.get("scam_id") or "") == "scam_romance_investment":
        return bool(ROMANCE_INVESTMENT_CONTEXT_PATTERN.search(text or ""))
    return True


def _package_context_active(package: Dict[str, Any], text: str) -> bool:
    lowered = (text or "").lower()
    if str(package.get("scam_id") or "") == "scam_fake_customer_service":
        if "客服" in lowered and any(
            marker in lowered
            for marker in ["屏幕共享", "共享屏幕", "远程控制", "远程协助", "会议软件", "验证码", "退款", "理赔"]
        ):
            return True
    anchors = [str(package.get("name") or "")]
    anchors.extend(str(item) for item in package.get("aliases") or [] if item)
    strong_anchors = [
        anchor
        for anchor in anchors
        if anchor and anchor not in GENERIC_PACKAGE_CONTEXT_TERMS and len(anchor) >= 3
    ]
    if any(anchor.lower() in lowered for anchor in strong_anchors):
        return True
    # A scene can be described without its canonical name.  Require two
    # package-specific feature hits before activating such a package; this
    # prevents words like “定金” or “加微信” from leaking rental/job/travel
    # features into every private transaction.
    feature_hits = 0
    for item in package.get("features") or []:
        if not isinstance(item, dict):
            continue
        for keyword in item.get("keywords") or []:
            keyword = str(keyword or "")
            if keyword and keyword not in GENERIC_PACKAGE_CONTEXT_TERMS and keyword.lower() in lowered:
                feature_hits += 1
                if feature_hits >= 2:
                    return True
    return False


def _package_features(text: str) -> List[str]:
    features: List[str] = []
    for package in load_scam_packages():
        if not _package_has_required_context(package, text):
            continue
        if not _package_context_active(package, text):
            continue
        for item in package.get("features") or []:
            if not isinstance(item, dict) or not item.get("feature_name"):
                continue
            if any(str(keyword or "") and str(keyword) in text for keyword in item.get("keywords") or []):
                features.append(str(item["feature_name"]))
    return features


def _remove_negated_features(text: str, features: List[str]) -> List[str]:
    negated_patterns = {
        "已发生转账": [r"(还没|没有|没|未)[^，。；,;]{0,10}(转账|转钱|转过钱|转过|转了|付款|付钱|付过|充值|打款|补单|交钱)"],
        "要求垫付资金": [r"(还没|没有|没|未)[^，。；,;]{0,10}(转账|转钱|转过钱|转过|转了|付款|付钱|付过|充值|打款|补单|垫付|垫钱|交钱)"],
        "要求继续补单": [r"(还没|没有|没|未)[^，。；,;]{0,10}(补单|联单|连单)"],
        "索要验证码": [r"(还没|没有|没|未)[^，。；,;]{0,8}(给|发|填|提供)?[^，。；,;]{0,8}(验证码|短信码|动态码)"],
        "屏幕共享": [r"(还没|没有|没|未|不再|不会)[^，。；,;]{0,12}(屏幕共享|共享屏幕|远程控制|远程协助)"],
        "远程控制": [r"(还没|没有|没|未|不再|不会)[^，。；,;]{0,12}(屏幕共享|共享屏幕|远程控制|远程协助)"],
        "诱导下载陌生APP": [r"(还没|没有|没|未)[^，。；,;]{0,8}(下载|安装)[^，。；,;]{0,8}(App|APP|app|软件)"],
        "点击陌生链接": [r"(还没|没有|没|未)[^，。；,;]{0,8}(点|点击|打开|进入)[^，。；,;]{0,8}(链接|网址|二维码)"],
        "索要银行卡或身份信息": [r"(还没|没有|没|未)[^，。；,;]{0,8}(填|给|提供|上传|告诉)[^，。；,;]{0,12}(银行卡|身份证|人脸识别|微信密码|登录密码|支付密码|账号密码|敏感信息)"],
        "账号密码索取": [r"(还没|没有|没|未)[^，。；,;]{0,8}(给|发|提供|告诉)[^，。；,;]{0,12}(微信密码|登录密码|支付密码|账号密码|密码)"],
    }
    false_positive_patterns = {
        "索要银行卡或身份信息": [
            r"银行卡.{0,8}(涉案|冻结|异常|洗钱|风险)",
            r"(涉案|冻结|异常|洗钱|风险).{0,8}银行卡",
        ],
    }
    kept: List[str] = []
    for feature in features:
        patterns = negated_patterns.get(feature, []) + false_positive_patterns.get(feature, [])
        if any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns):
            continue
        if feature not in kept:
            kept.append(feature)
    return kept


def _feature_order(features: Iterable[str]) -> List[str]:
    ordered: List[str] = []
    known_order = list(RISK_FEATURES) + [item["feature_name"] for item in _package_feature_docs()]
    feature_set = set(features)
    for feature in known_order:
        if feature in feature_set and feature not in ordered:
            ordered.append(feature)
    for feature in features:
        if feature not in ordered:
            ordered.append(feature)
    return ordered


def extract_risk_features(text: str, context: Dict[str, Any] | None = None) -> List[str]:
    context = context or {}
    slots = context.get("slots") or {}
    initial = context.get("risk_features") or context.get("normalized_risk_features") or []
    merged_text = build_context_text(text, context)
    extra_features = _extra_features(merged_text, slots)
    features = normalize_risk_features(list(initial) + extra_features, merged_text)
    known_features = set(RISK_FEATURES) | {item["feature_name"] for item in _package_feature_docs()}
    for feature in extra_features:
        if feature in known_features and feature not in features:
            features.append(feature)
    features.extend(_package_features(merged_text))
    return _feature_order(_remove_negated_features(merged_text, features))


def _feature_score(feature: str) -> int:
    if feature in BASE_FEATURE_SCORES:
        return BASE_FEATURE_SCORES[feature]
    for item in _package_feature_docs():
        if item["feature_name"] == feature:
            return int(item.get("weight", 20) or 20)
    return 10


def _infer_stage(features: List[str], slots: Dict[str, Any], text: str) -> str:
    action = str(slots.get("current_requested_action") or "")
    if _is_small_rebate_returned(slots, features, text):
        return "小额返利诱导阶段"
    if _is_true(slots.get("has_paid")) or _is_true(slots.get("has_transferred_virtual_asset")) or "已发生转账" in features or "虚拟资产已交付" in features:
        return "损失发生阶段"
    if any(item in features for item in ["无法提现", "要求缴纳解冻费", "要求继续补单"]) or any(word in action for word in ["解冻费", "继续补单"]):
        return "提现受阻阶段"
    if any(item in features for item in ["要求垫付资金", "贷款前收费"]) or any(word in action for word in ["转账", "充值", "保证金", "缴纳"]):
        return "资金转账前阶段"
    if any(item in features for item in ["索要验证码", "账号密码索取", "索要银行卡或身份信息", "索要银行流水或卡号", "屏幕共享", "远程控制"]):
        return "信息索取阶段"
    if any(item in features for item in ["诱导下载陌生APP", "点击陌生链接"]):
        return "引流诱导阶段"
    if any(item in features for item in ["小额返利", "承诺返利", "高收益诱导", "保本稳赚承诺"]):
        return "建立信任阶段"
    if any(word in text for word in ["什么是", "怎么识别", "如何防范", "科普", "案例"]):
        return "科普学习"
    return "初步接触阶段" if features else "未知"


def _stage_match(rule: Dict[str, Any], current_stage: str) -> bool:
    rule_stages = [str(item) for item in rule.get("stages") or [] if item]
    if not rule_stages or not current_stage or current_stage == "未知":
        return True
    if current_stage in rule_stages:
        return True
    broad_groups = {
        "损失发生阶段": {"损失发生阶段", "止损报警阶段", "资金转账阶段"},
        "提现受阻阶段": {"提现受阻阶段", "损失发生阶段", "资金转账阶段"},
        "资金转账前阶段": {"资金转账前阶段", "资金转账阶段", "信息索取阶段"},
        "信息索取阶段": {"信息索取阶段", "信息泄露阶段", "资金转账前阶段"},
        "引流诱导阶段": {"引流诱导阶段", "初步接触阶段", "建立信任阶段"},
        "建立信任阶段": {"建立信任阶段", "小额试探阶段", "引流诱导阶段"},
        "小额返利诱导阶段": {"小额返利诱导阶段", "建立信任阶段", "小额试探阶段", "资金转账前阶段", "资金转账阶段", "引流诱导阶段"},
    }
    return bool(broad_groups.get(current_stage, {current_stage}) & set(rule_stages))


def _condition_features(rule: Dict[str, Any]) -> List[str]:
    conditions = rule.get("conditions") or {}
    return [
        RISK_FEATURE_ALIASES.get(str(item), str(item))
        for item in list(conditions.get("all") or []) + list(conditions.get("any") or [])
    ]


def _keyword_groups(conditions: Dict[str, Any]) -> List[List[str]]:
    groups: List[List[str]] = []
    for group in conditions.get("must_include_any") or []:
        words = [str(word).strip() for word in _as_list(group) if str(word).strip()]
        if words:
            groups.append(words)
    return groups


def _keyword_conditions_match(conditions: Dict[str, Any], text: str) -> Tuple[bool, List[str]]:
    """Match config-only keyword groups such as [["客服"], ["退款"]]."""
    groups = _keyword_groups(conditions)
    must_all = [str(word).strip() for word in _as_list(conditions.get("must_include_all")) if str(word).strip()]
    include_any = [str(word).strip() for word in _as_list(conditions.get("include_any")) if str(word).strip()]

    if not groups and not must_all and not include_any:
        return True, []

    hits: List[str] = []
    for word in must_all:
        if word not in text:
            return False, []
        hits.append(word)

    for group in groups:
        hit = next((word for word in group if word in text), "")
        if not hit:
            return False, []
        hits.append(hit)

    if include_any:
        hit = next((word for word in include_any if word in text), "")
        if not hit:
            return False, []
        hits.append(hit)

    return True, _dedupe(hits, limit=12)


def _all_rules() -> List[Dict[str, Any]]:
    rules = [rule for rule in _load_rules() if rule.get("enabled", True) is not False]
    rules.extend(rule for rule in _package_rules() if rule.get("enabled", True) is not False)
    # Keep behaviour-combination coverage available even when Mongo contains
    # an older rule snapshot.  These rules use keyword groups only and are
    # therefore safe to deploy alongside the configurable rule sources.
    rules.extend(BEHAVIOR_COMBINATION_RULES)
    return rules


def _match_rules(
    features: List[str],
    fraud_types: List[str],
    stage: str,
    text: str,
) -> Tuple[List[Dict[str, Any]], List[str]]:
    feature_set = set(features)
    fraud_type_set = set(fraud_types)
    specific_primary = _specific_primary_fraud_type(text)
    allowed_features = set(RISK_FEATURES) | {item["feature_name"] for item in _package_feature_docs()}
    matched: List[Dict[str, Any]] = []
    warnings: List[str] = []

    fraud_type_order = {
        fraud_type: index
        for index, fraud_type in enumerate(item for item in fraud_types if item and item != "未知")
    }
    horizontal_types = {"钓鱼链接诈骗", "验证码/账户盗刷诈骗", "屏幕共享/远程控制诈骗"}
    loan_context = bool(LOAN_CONTEXT_PATTERN.search(text or ""))
    explicit_service_context = bool(re.search(r"(快递|物流|电商|网店|商品|订单|包裹|退款|理赔)", text or ""))

    try:
        rules = _all_rules()
    except Exception as exc:
        return [], [f"风险规则读取失败：{exc}"]

    for rule in rules:
        invalid = [feature for feature in _condition_features(rule) if feature not in allowed_features]
        if invalid:
            warnings.append(f"跳过非法规则 {rule.get('rule_id', '')}，未知特征：{invalid}")
            continue
        fraud_type = str(rule.get("fraud_type") or "")
        if fraud_type == "冒充客服诈骗" and loan_context and not explicit_service_context:
            # “贷款客服” is an identity wrapper around the loan scam, not a
            # reason to replace the more specific loan type with customer
            # service.  Explicit e-commerce/parcel wording remains eligible.
            continue
        # Broad parent rules must not replace a high-confidence specific scene.
        # The parent remains available in possible_fraud_types for explanation.
        # Only suppress known broad taxonomy labels.  Custom hot rules may use
        # an application-specific fraud_type string (for example a campaign
        # name) and must remain matchable by their explicit keyword groups.
        legacy_customer_service_screen = (
            rule.get("rule_id") == "PKG_SERVICE_SCREEN_001"
            and "客服让我下载会议软件" in (text or "")
            and "正在屏幕共享" in (text or "")
        )
        if (
            specific_primary
            and fraud_type != specific_primary
            and fraud_type_metadata(fraud_type).get("known")
            and not legacy_customer_service_screen
        ):
            continue
        if fraud_type == "冒充熟人诈骗" and BRUSHING_CONTEXT_PATTERN.search(text or "") and not STRONG_ACQUAINTANCE_PATTERN.search(text or ""):
            continue
        if not _stage_match(rule, stage):
            continue

        conditions = rule.get("conditions") or {}
        keyword_match, keyword_hits = _keyword_conditions_match(conditions, text)
        has_keyword_conditions = bool(_keyword_groups(conditions) or conditions.get("must_include_all") or conditions.get("include_any"))
        if fraud_type and fraud_type_set and "未知" not in fraud_type_set and fraud_type not in fraud_type_set and not has_keyword_conditions:
            continue
        if not keyword_match:
            continue

        all_conditions = [RISK_FEATURE_ALIASES.get(str(item), str(item)) for item in (conditions.get("all") or [])]
        any_conditions = [RISK_FEATURE_ALIASES.get(str(item), str(item)) for item in (conditions.get("any") or [])]
        min_any = int(conditions.get("min_any", 0) or 0)
        all_matched = [item for item in all_conditions if item in feature_set]
        any_matched = [item for item in any_conditions if item in feature_set]
        if len(all_matched) == len(all_conditions) and len(any_matched) >= min_any:
            score = int(rule.get("risk_score", rule.get("score", 0)) or 0)
            matched_features = all_matched + any_matched
            if not matched_features and keyword_hits:
                matched_features = [f"关键词命中：{item}" for item in keyword_hits]
            matched.append(
                {
                    "rule_id": rule.get("rule_id", ""),
                    "rule_name": rule.get("rule_name", ""),
                    "fraud_type": fraud_type,
                    "risk_level": rule.get("risk_level", risk_level_from_score(score)),
                    "risk_score": score,
                    "matched_features": matched_features,
                    "matched_keywords": keyword_hits,
                    "explanation": rule.get("explanation", ""),
                    "suggested_action": rule.get("suggested_action", ""),
                    "intervention_goal": rule.get("intervention_goal", ""),
                    "source": rule.get("source", "risk_rules"),
                }
            )
    matched.sort(
        key=lambda item: (
            1 if str(item.get("fraud_type") or "") in horizontal_types else 0,
            0 if str(item.get("source") or "").endswith("runtime_hot_rules") else 1,
            fraud_type_order.get(str(item.get("fraud_type") or ""), 999),
            -int(item.get("risk_score", 0) or 0),
        )
    )
    return matched, warnings


def _evidence_for_features(text: str, features: List[str]) -> List[Dict[str, Any]]:
    evidence: List[Dict[str, Any]] = []
    package_feature_map = {item["feature_name"]: item for item in _package_feature_docs()}
    for feature in features:
        keywords = list(RISK_FEATURE_SYNONYMS.get(feature, []))
        if feature in package_feature_map:
            keywords.extend(package_feature_map[feature].get("keywords") or [])
        hit = next((keyword for keyword in keywords if keyword and keyword in text), feature if feature in text else "")
        evidence.append(
            {
                "type": "feature",
                "name": feature,
                "source_text": hit,
                "score": _feature_score(feature),
            }
        )
    return evidence


def _default_intervention_goal(features: List[str], matched_rules: List[Dict[str, Any]], slots: Dict[str, Any] | None = None, text: str = "") -> str:
    # Prefer the concrete dangerous action in the current turn over the
    # highest-scoring broad rule. A generic "冒充公检法" rule may score higher,
    # but if the user is being asked for bank statements/card numbers, the next
    # intervention must stop sensitive-info disclosure rather than talk about
    # transfer.
    slots = slots or {}
    if ("已发生转账" in features and not _is_small_rebate_returned(slots, features, text)) or "虚拟资产已交付" in features:
        return "call_police"
    if any(item in features for item in ["出租出借两卡", "帮忙收款跑分", "出租账号收款码"]):
        for rule in matched_rules:
            if str(rule.get("fraud_type") or "") == "两卡出租出借与跑分诈骗" and rule.get("intervention_goal"):
                return str(rule.get("intervention_goal"))
    if "索要验证码" in features or "账号密码索取" in features:
        return "stop_code_leak"
    if "索要银行卡或身份信息" in features or "索要银行流水或卡号" in features:
        return "stop_sensitive_info"
    if "屏幕共享" in features or "远程控制" in features:
        return "stop_screen_share"
    if "要求垫付资金" in features or "要求缴纳解冻费" in features or "要求继续补单" in features:
        return "stop_transfer"
    if "诱导下载陌生APP" in features:
        return "stop_app_install"
    if matched_rules and matched_rules[0].get("intervention_goal"):
        return str(matched_rules[0].get("intervention_goal"))
    return "ask_clarification"


def _top_rule_for_goal(matched_rules: List[Dict[str, Any]], goal: str) -> Dict[str, Any]:
    if not matched_rules:
        return {}
    if goal:
        for rule in matched_rules:
            if str(rule.get("intervention_goal") or "") == goal:
                return rule
    return matched_rules[0]


def _advice_template_id(rule: Dict[str, Any]) -> str:
    explicit = str((rule or {}).get("advice_template_id") or "").strip()
    if explicit:
        return explicit
    return DEFAULT_ADVICE_TEMPLATE_IDS.get(str((rule or {}).get("rule_id") or ""), "")


def _is_learning_only_query(text: str) -> bool:
    learning_words = ["什么是", "是什么意思", "怎么识别", "如何识别", "怎么防范", "如何防范", "反诈作业", "科普", "案例"]
    risk_action_patterns = [
        r"让我(?!们)",
        r"叫我",
        r"要求我",
        r"要我",
        r"准备.{0,6}(转账|付款|充值|补单|给验证码|共享屏幕)",
        r"正在.{0,6}(转账|付款|充值|补单|给验证码|共享屏幕)",
        r"已经.{0,6}(转账|付款|充值|补单|给验证码|共享屏幕)",
        r"密码",
        r"转账",
        r"付款",
        r"充值",
        r"补单",
        r"保证金",
        r"解冻费",
        r"验证码",
        r"屏幕共享",
        r"远程控制",
        r"下载",
    ]
    return any(word in text for word in learning_words) and not any(re.search(pattern, text) for pattern in risk_action_patterns)


def _risk_relevant_history(history: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Keep prior risk facts but drop unrelated knowledge-learning turns."""
    filtered: List[Dict[str, Any]] = []
    for item in history or []:
        if not isinstance(item, dict) or item.get("role") != "user":
            continue
        text = str(item.get("text") or item.get("content") or "").strip()
        if not text:
            continue
        if _is_learning_only_query(text):
            continue
        filtered.append({**item, "text": text})
    return filtered


def _evaluate_rule_text_from_features(
    *,
    normalized: str,
    full_text: str,
    features: List[str],
    context: Dict[str, Any],
    route_decision: Dict[str, Any],
) -> Dict[str, Any]:
    """基于指定风险特征完成规则匹配、评分和干预目标选择。

    该函数是规则引擎的确定性核心。外部可以先用规则抽取候选，也可以先让
    LLM 裁判候选特征，再把“裁判后的特征”传回来重新计算 matched_rules。
    """
    slots = context.get("slots") or {}
    cleaned_features = [str(feature).strip() for feature in features if str(feature or "").strip()]
    features = _feature_order(cleaned_features)
    benign_process_context = _is_benign_process_context(full_text)
    clarification_only = _is_clarification_only(full_text)
    if benign_process_context or clarification_only:
        # Official/contractual handling is a negative control only when no
        # active private-channel or sensitive-operation marker is present. It
        # must bypass both broad package aliases and stale feature prefill.
        features = []
    small_rebate_returned = _is_small_rebate_returned(slots, features, full_text)
    if small_rebate_returned:
        features = [feature for feature in features if feature != "已发生转账"]

    if benign_process_context or clarification_only:
        fraud_types = ["未知"]
    else:
        fraud_types = infer_fraud_types(full_text)
        context_fraud_types = [str(item) for item in context.get("possible_fraud_types") or [] if item]
        if context_fraud_types:
            merged_types: List[str] = []
            for item in context_fraud_types + fraud_types:
                if item and item != "未知" and item not in merged_types:
                    merged_types.append(item)
            fraud_types = merged_types or fraud_types
        elif fraud_types == ["未知"]:
            fraud_types = context_fraud_types or ["未知"]

    if benign_process_context or clarification_only:
        stage = "未知"
        matched_rules, warnings = [], []
    else:
        stage = (
            _infer_stage(features, context.get("slots") or {}, full_text)
            if context.get("force_stage_recompute")
            else context.get("fraud_stage") or _infer_stage(features, context.get("slots") or {}, full_text)
        )
        fraud_types = _prioritize_specific_fraud_types(full_text, fraud_types)
        matched_rules, warnings = _match_rules(features, fraud_types, stage, full_text)

    feature_score = min(100, sum(_feature_score(feature) for feature in features))
    top_rule_score = max((int(rule.get("risk_score", 0) or 0) for rule in matched_rules), default=0)
    score = max(feature_score, top_rule_score)
    risk_signals = route_decision.get("risk_signals") or {}
    if not small_rebate_returned and (
        risk_signals.get("confirmed_exposure_signal")
        or (route_decision.get("routing_decision") or {}).get("force_high_risk")
    ):
        score = max(score, 90)
    if context.get("slots") and any(
        _is_true(slots.get(slot))
        for slot in ["has_paid", "has_transferred_virtual_asset", "has_shared_code", "has_screen_share", "has_downloaded_app", "has_provided_identity_or_bank"]
        if not (slot == "has_paid" and small_rebate_returned)
    ):
        score = max(score, 90)
    if not matched_rules and _is_learning_only_query(normalized):
        score = min(score, 29)
    if small_rebate_returned:
        score = min(score, 86)
    score = min(100, score)

    intervention_goal = _default_intervention_goal(features, matched_rules, slots, full_text)
    top_rule = matched_rules[0] if matched_rules else {}
    fraud_type = top_rule["fraud_type"] if top_rule else fraud_types[0]
    if fraud_type and fraud_type != "未知":
        fraud_types = [fraud_type] + [item for item in fraud_types if item != fraud_type]
    type_candidates = canonicalize_fraud_types(fraud_types, limit=8)
    primary_metadata = fraud_type_metadata(fraud_type)
    if matched_rules:
        type_confidence = 0.96 if _specific_primary_fraud_type(full_text) else 0.9
    elif fraud_type and fraud_type != "未知" and _specific_primary_fraud_type(full_text):
        type_confidence = 0.84
    elif fraud_type and fraud_type != "未知":
        type_confidence = 0.62
    else:
        type_confidence = 0.0
    rule_evidence = [
        {
            "type": "rule",
            "rule_id": rule.get("rule_id", ""),
            "name": rule.get("rule_name", ""),
            "score": rule.get("risk_score", 0),
            "matched_features": rule.get("matched_features", []),
            "matched_keywords": rule.get("matched_keywords", []),
            "explanation": rule.get("explanation", ""),
        }
        for rule in matched_rules[:5]
    ]
    evidence = _evidence_for_features(full_text, features) + rule_evidence
    if benign_process_context:
        advice = "当前描述符合官方平台或合同约定流程，未发现明显诈骗行为；后续如出现脱离平台、私下转账或索要验证码等要求，再立即停止并核验。"
        next_actions = [
            "继续通过官方 App、官网、营业网点或合同约定渠道办理",
            "保留订单、合同、支付记录和电子凭证",
        ]
    else:
        advice = top_rule.get("suggested_action") or "当前信息仍需补充，请先暂停操作并通过官方渠道核实对方身份。"
        next_actions = [
            "不要继续转账、充值、垫付或交付账号/装备等虚拟资产",
            "不要提供验证码、银行卡、身份证或人脸识别信息",
            "保存聊天记录、对方账号、链接和转账凭证",
        ]
    if score >= 60 and not small_rebate_returned:
        next_actions.append("如已转账或泄露信息，尽快联系银行/支付平台止付并报警或拨打96110咨询")

    # Keep the historical ``scam_type`` display for the exact customer-service
    # screen-share phrase used by older clients.  The new stable fields and
    # ``fraud_type`` remain the specific screen-share scene.
    legacy_scam_type = fraud_type
    if fraud_type == "情感交友诱导投资诈骗" and "杀猪盘" in full_text:
        # Preserve the historical display label for clients that explicitly
        # used “杀猪盘”; stable taxonomy fields keep the canonical ID/name.
        legacy_scam_type = "杀猪盘诈骗"
    if (
        fraud_type == "屏幕共享/远程控制诈骗"
        and "客服让我下载会议软件" in full_text
        and "正在屏幕共享" in full_text
    ):
        legacy_scam_type = "冒充客服诈骗"

    return {
        "engine_version": "scam-rule-engine-v1",
        "fraud_type": fraud_type,
        "scam_type": legacy_scam_type,
        # Stable taxonomy fields.  Legacy names above remain for existing
        # clients, while new consumers can key on fraud_type_id.
        "fraud_type_id": primary_metadata.get("fraud_type_id", ""),
        "primary_type": primary_metadata.get("primary_type", fraud_type),
        "candidate_types": [item.get("primary_type", "") for item in type_candidates if item.get("primary_type")],
        "candidate_type_ids": [item.get("fraud_type_id", "") for item in type_candidates if item.get("fraud_type_id")],
        "type_candidates": type_candidates,
        "type_confidence": type_confidence,
        "confidence": type_confidence,
        "possible_fraud_types": fraud_types,
        "risk_stage": stage,
        "fraud_stage": stage,
        "risk_score": score,
        "risk_level": risk_level_from_score(score),
        "risk_features": features,
        "normalized_risk_features": features,
        "matched_rules": matched_rules,
        "evidence": evidence,
        "intervention_goal": intervention_goal,
        "advice_template_id": _advice_template_id(top_rule),
        "advice": advice,
        "next_actions": next_actions,
        "entities": {
            "urls": extract_urls(full_text),
            "amounts": extract_amounts(full_text),
        },
        "warnings": warnings,
    }


def evaluate_rule_text(
    text: str,
    context: Dict[str, Any] | None = None,
    route_decision: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """Evaluate one text turn and return a structured risk result."""
    context = dict(context or {})
    route_decision = route_decision or context.get("route_decision") or {}
    normalized = normalize_text(text)
    full_text = build_context_text(normalized, context)
    features = extract_risk_features(normalized, context)
    return _evaluate_rule_text_from_features(
        normalized=normalized,
        full_text=full_text,
        features=features,
        context=context,
        route_decision=route_decision,
    )


def evaluate_rule_text_with_features(
    text: str,
    features: List[str],
    context: Dict[str, Any] | None = None,
    route_decision: Dict[str, Any] | None = None,
    force_stage_recompute: bool = False,
) -> Dict[str, Any]:
    """用外部裁判后的风险特征重新评估规则。

    与 ``evaluate_rule_text`` 不同，这里不会重新抽取风险特征，也不会再次做
    正则否定过滤。调用方已经完成语义裁判时，应使用该入口保证规则匹配、
    阶段和评分都基于同一份事实。
    """
    context = dict(context or {})
    if force_stage_recompute:
        context["force_stage_recompute"] = True
    route_decision = route_decision or context.get("route_decision") or {}
    normalized = normalize_text(text)
    full_text = build_context_text(normalized, context)
    return _evaluate_rule_text_from_features(
        normalized=normalized,
        full_text=full_text,
        features=features,
        context=context,
        route_decision=route_decision,
    )


def _build_rule_state_input(state: Dict[str, Any]) -> Tuple[str, Dict[str, Any], Dict[str, Any]]:
    """把 LangGraph state 转换成规则引擎输入。

    这里集中处理“只使用用户事实文本”的约束，避免不同节点自己拼上下文。
    """
    text = str(state.get("original_query") or "")
    scam_understanding = state.get("scam_understanding") or {}
    route_decision = state.get("route_decision") or {}
    risk_prefill = route_decision.get("risk_prefill") or {}
    semantic_frame = route_decision.get("semantic_frame") or {}
    case_state = state.get("case_state") or {}
    previous_fraud_type = (
        state.get("fraud_type")
        or case_state.get("fraud_type")
        or (case_state.get("scam_memory") or {}).get("primary_scam_type")
        or (case_state.get("scam_understanding") or {}).get("primary_scam_type")
        or ""
    )
    possible_fraud_types = (
        state.get("possible_fraud_types")
        or scam_understanding.get("possible_scam_types")
        or risk_prefill.get("fraud_candidates")
        or semantic_frame.get("fraud_candidates")
        or []
    )
    if previous_fraud_type and previous_fraud_type not in possible_fraud_types and previous_fraud_type != "未知":
        possible_fraud_types = [previous_fraud_type] + [item for item in possible_fraud_types if item != previous_fraud_type]
    case_fact_text = str(state.get("case_fact_text") or (state.get("case_state") or {}).get("case_fact_text") or "").strip()
    turn_rewrite = route_decision.get("turn_rewrite") or {}
    rewrite_parts = []
    rewritten_text = str(turn_rewrite.get("rewritten_text") or "").strip()
    if rewritten_text and rewritten_text != text:
        rewrite_parts.append(rewritten_text)
    case_description = str(semantic_frame.get("case_description") or "").strip()
    if case_description and case_description != text:
        rewrite_parts.append(case_description)
    for item in semantic_frame.get("evidence") or []:
        item_text = str(item or "").strip()
        if item_text and item_text != text:
            rewrite_parts.append(item_text)
    context = {
        "history": [] if case_fact_text else _risk_relevant_history(state.get("history") or []),
        # Rule matching must stay grounded in user-originated facts only.
        # Flattened history, memory summaries, LLM rewrites, and previous
        # feature lists may contain assistant warnings or model inferences such
        # as "不要共享屏幕/不要给验证码".  Feeding them back here turns warnings
        # into fake user evidence on later turns.
        "history_text": case_fact_text,
        "memory_summary": "",
        "rewritten_query": " ".join(_dedupe(rewrite_parts, limit=6)),
        "slots": state.get("slots") or {},
        "risk_features": [],
        "normalized_risk_features": [],
        "possible_fraud_types": possible_fraud_types,
        "fraud_stage": state.get("fraud_stage") or scam_understanding.get("stage") or "",
        "route_decision": route_decision,
    }
    return text, context, route_decision


def evaluate_rule_state(state: Dict[str, Any]) -> Dict[str, Any]:
    """Evaluate a workflow state using the same engine as public risk checks."""
    text, context, route_decision = _build_rule_state_input(state)
    return evaluate_rule_text(text, context=context, route_decision=route_decision)


def evaluate_rule_state_with_features(
    state: Dict[str, Any],
    features: List[str],
    force_stage_recompute: bool = True,
) -> Dict[str, Any]:
    """用裁判后的风险特征重新评估整个 workflow state。"""
    text, context, route_decision = _build_rule_state_input(state)
    return evaluate_rule_text_with_features(
        text,
        features,
        context=context,
        route_decision=route_decision,
        force_stage_recompute=force_stage_recompute,
    )
