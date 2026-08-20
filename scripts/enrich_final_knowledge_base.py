"""Enrich the final structured anti-fraud knowledge base.

This script is intentionally non-destructive and repeatable.  It keeps existing
IDs and fields, fixes inconsistent references, and adds the structured material
needed by the LLM-first risk and education flows:

- critical facts and loss signals on every scam type
- one teaching path for every scam type
- stage-aware prevention advice and multiple cases per scam type
- complete report/evidence guides
- structured risk-rule condition groups
- related scam coverage and source references for legal/handling guides
"""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List


ROOT = Path(__file__).resolve().parents[1]
KNOWLEDGE_DIR = ROOT / "data" / "knowledge"
BUILD_VERSION = "final_structured_kb_2026_06_05"

COMMON_SOURCE_REFS = [
    "https://www.mps.gov.cn/",
    "https://www.npc.gov.cn/c2/c30834/202209/t20220902_319186.html",
]
POLICE_SOURCE_REFS = [
    "https://www.mps.gov.cn/n2253534/n2253543/c8882901/content.html",
    "https://www.mps.gov.cn/n2253534/n2253543/c8090077/content.html",
]
LAW_SOURCE_REFS = [
    "https://www.npc.gov.cn/c2/c30834/202209/t20220902_319186.html",
    "https://www.gov.cn/",
]
LOCAL_SOURCE_REFS = [f"local:{BUILD_VERSION}"]

STAGE_ORDER = ["overview", "features", "tactics", "case", "prevention", "law", "summary"]
STAGE_GOAL_TEMPLATES = {
    "overview": "先让用户记住：{rule}",
    "features": "讲清{feature_focus}这些识别点。",
    "tactics": "拆解从{lure}到{trap}的完整诱导流程。",
    "case": "用脱敏案例复盘{case_focus}。",
    "prevention": "给出{verify_focus}、停止危险动作和证据保存建议。",
    "law": "讲清报警、止付、证据保存、平台举报和敏感信息保护的通用处置常识。",
    "summary": "用一句口诀收束：{rule}",
}

SCAM_PROFILES: Dict[str, Dict[str, Any]] = {
    "scam_brush_rebate": {
        "code": "BRUSH",
        "rule": "只要兼职任务让你先垫钱、补单或交解冻费，就按刷单返利诈骗处理。",
        "lure": "点赞关注、做任务返佣和前几单小额到账",
        "trap": "垫付大额订单、联单补单、提现受阻继续收费",
        "feature_focus": "任务返佣、小额返利、垫付资金、提现受阻、继续补单/解冻费",
        "verify_focus": "招聘主体、任务平台、收款账户和是否要求预付费用",
        "critical_facts": ["是否已经垫付、充值或转账", "金额是多少、收款账户是谁", "是否能提现或退款", "对方是否要求继续补单/解冻/激活", "是否下载了陌生任务App"],
        "loss_signals": ["已垫付订单", "提现失败", "继续补单或联单", "要求解冻费/保证金/激活费", "对方失联或踢出群聊"],
        "case_focus": "小额返利如何诱导大额垫付",
        "case_early": "用户看到“点赞关注日结”的兼职广告，进群后前两单返了几十元，随后被要求下载任务App做高佣金垫付单。",
        "case_loss": "用户垫付多笔订单后提现失败，客服以“联单未完成、操作超时”为由要求继续补单，最终本金和佣金都无法取出。",
        "verify_methods": ["正规招聘平台客服", "96110反诈咨询", "公安机关", "家人或可信朋友二次核验"],
        "early_do": ["核实招聘主体和结算方式", "保留广告、群聊和客服账号", "只接受不需要预付费用的正规兼职"],
        "early_dont": ["不要进陌生任务群", "不要下载任务App", "不要因小额到账放松警惕"],
        "preloss_do": ["看到垫付/补单立刻停止", "截图任务规则和收款账户", "和家人或96110核实后再决定"],
        "preloss_dont": ["不要垫付订单", "不要交保证金或解冻费", "不要借钱继续做单"],
        "loss_do": ["联系银行或支付平台尝试止付", "保存转账凭证、群聊和App页面", "尽快拨打110或到派出所报案"],
        "loss_dont": ["不要继续补单追回本金", "不要相信内部通道退款", "不要删除聊天记录"],
    },
    "scam_fake_customer_service": {
        "code": "SERVICE",
        "rule": "官方客服不会让你开屏幕共享、给验证码，或向私人账户转账办理退款理赔。",
        "lure": "退款理赔、取消会员、快递丢失或订单异常",
        "trap": "会议软件共享屏幕、索要验证码、刷流水或转账验证",
        "feature_focus": "冒充客服、退款理赔、屏幕共享、验证码、陌生链接和先交钱",
        "verify_focus": "官方App订单页、平台官方客服电话和快递官网",
        "critical_facts": ["对方自称哪个平台客服", "是否点了链接或下载会议软件", "是否共享屏幕或远程控制", "是否提供验证码/支付密码/银行卡", "是否已转账或被扣款"],
        "loss_signals": ["验证码已泄露", "屏幕共享时打开支付或银行页面", "已向指定账户转账验证", "支付账户异常扣款", "对方要求继续认证/刷流水"],
        "case_focus": "退款理赔如何变成账户盗刷",
        "case_early": "用户接到自称电商客服的电话，对方能说出订单信息，要求加好友领取三倍理赔并打开链接填写银行卡。",
        "case_loss": "用户按客服要求下载会议软件共享屏幕，对方看到验证码后完成转账，随后又以关闭会员失败为由继续索要费用。",
        "verify_methods": ["电商官方App", "快递公司官网/官方客服", "支付平台官方客服", "96110反诈咨询"],
        "early_do": ["挂断后从官方App订单页核实", "记录来电号码和自称工号", "把退款入口限定在官方页面内"],
        "early_dont": ["不要回拨陌生号码", "不要点短信链接", "不要把订单信息当成身份真实证明"],
        "preloss_do": ["退出会议软件和屏幕共享", "关闭免密支付并检查授权", "通过官方客服确认账户状态"],
        "preloss_dont": ["不要给验证码", "不要共享屏幕", "不要转账验证或刷流水"],
        "loss_do": ["联系银行/支付平台冻结或止付", "修改支付密码并检查异常登录", "保存通话、会议号、验证码短信和交易记录后报警"],
        "loss_dont": ["不要继续按客服指令操作", "不要卸载前忘记截图", "不要相信二次退款专员"],
    },
    "scam_fake_police": {
        "code": "POLICE",
        "rule": "自称公检法还让你保密、视频笔录或转入安全账户，直接按诈骗处理。",
        "lure": "涉案洗钱、通缉令、案件编号和来学校/单位抓人的恐吓",
        "trap": "保密隔离、下载App、屏幕共享、资金清查和安全账户转账",
        "feature_focus": "冒充公检法、涉案恐吓、伪造文书、保密、屏幕共享和安全账户",
        "verify_focus": "110、就近派出所、老师家人陪同核验",
        "critical_facts": ["是否被要求保密或独处", "是否下载对方发的App/会议软件", "是否共享屏幕或视频笔录", "是否提供身份证银行卡验证码", "是否准备或已经转入安全账户"],
        "loss_signals": ["已转入所谓安全账户", "屏幕共享暴露银行页面", "验证码/银行卡信息泄露", "被要求删除证据或切断联系", "继续要求资金清查"],
        "case_focus": "权威恐吓和保密隔离如何逼人转账",
        "case_early": "用户接到自称公安局电话，对方发来带照片身份证号的通缉令，要求下载App做视频笔录并不能告诉家人老师。",
        "case_loss": "用户在恐吓下把银行卡余额转到所谓安全账户，对方随后以审查未完成为由要求再转其他账户资金。",
        "verify_methods": ["110", "就近派出所", "学校老师或家长", "官方政务平台"],
        "early_do": ["立即挂断并到派出所核实", "告诉家人老师或可信同伴", "保存号码、文书截图和App名称"],
        "early_dont": ["不要按要求保密", "不要下载陌生办案App", "不要进入视频笔录或共享屏幕"],
        "preloss_do": ["停止转账和屏幕共享", "从官方渠道核验身份", "让身边人陪同处理"],
        "preloss_dont": ["不要转入安全账户", "不要提供验证码/银行卡密码", "不要删除通话和聊天记录"],
        "loss_do": ["马上联系银行止付冻结", "拨打110或去派出所报案", "提交通缉令截图、App、号码和转账流水"],
        "loss_dont": ["不要继续配合资金清查", "不要相信保密威胁", "不要联系对方所谓上级"],
    },
    "scam_fake_investment": {
        "code": "INVEST",
        "rule": "高收益带单加陌生平台，再遇到提现先交钱，基本就是虚假投资诈骗。",
        "lure": "投资老师、内部消息、群内晒收益和小额盈利提现",
        "trap": "诱导大额入金、后台盈利造假、提现受阻后缴税费保证金",
        "feature_focus": "老师带单、保本高收益、陌生投资App、提现受阻和税费/保证金",
        "verify_focus": "金融资质、官方交易渠道、资金去向和提现规则",
        "critical_facts": ["平台名称和下载来源", "是否向个人账户或虚拟币地址入金", "是否承诺保本高收益", "是否能提现", "是否被要求缴税费/保证金/解冻费"],
        "loss_signals": ["已大额入金", "页面盈利但无法提现", "要求缴纳税费或保证金", "老师催促继续加仓", "平台关闭或客服失联"],
        "case_focus": "假投资平台如何用盈利截图收割",
        "case_early": "用户被拉进投资群，群里老师讲课、学员晒收益，助理推荐下载一个不在应用商店的交易App。",
        "case_loss": "用户账户显示盈利后申请提现，客服要求先交税费和保证金，交完又提示风控升级，资金一直无法取出。",
        "verify_methods": ["金融监管部门公开查询渠道", "持牌机构官网/官方App", "银行官方客服", "96110反诈咨询"],
        "early_do": ["查平台和机构是否持牌", "核对App下载来源和域名", "把收益承诺截图保存下来"],
        "early_dont": ["不要相信稳赚保本", "不要进私域带单群", "不要下载陌生投资App"],
        "preloss_do": ["停止入金和加仓", "核实收款主体是否一致", "保存老师、客服和平台页面"],
        "preloss_dont": ["不要向个人账户或虚拟币地址转账", "不要交提现税费/保证金", "不要借钱补仓"],
        "loss_do": ["整理入金流水和平台截图", "联系银行/支付平台尝试拦截", "尽快报警并提交收款账户/钱包地址"],
        "loss_dont": ["不要再缴解冻费", "不要相信黑客追款", "不要删除App前忘记取证"],
    },
    "scam_fake_loan": {
        "code": "LOAN",
        "rule": "正规贷款不会在放款前让你交保证金、解冻费或刷流水。",
        "lure": "无抵押、低息、秒放款、不看征信和校园贷包装",
        "trap": "放款前收费、银行卡号错误冻结、刷流水和征信威胁",
        "feature_focus": "贷款前收费、解冻费、陌生贷款App、身份银行卡信息和快速放款诱导",
        "verify_focus": "持牌金融机构、官方App、贷款合同和是否放款前收费",
        "critical_facts": ["贷款是否真正到账", "是否下载陌生贷款App", "是否填写身份证/银行卡/人脸", "是否被要求交保证金/解冻费/刷流水", "是否被威胁影响征信"],
        "loss_signals": ["放款前已交费", "提现显示银行卡错误或冻结", "继续要求认证金/刷流水", "个人信息已提交", "App或客服失联"],
        "case_focus": "贷款没到账先收费的连环套路",
        "case_early": "用户收到“额度已提升、秒到账”的短信，点击链接下载贷款App并填写身份证、银行卡和联系人。",
        "case_loss": "平台显示审批通过但银行卡号错误被冻结，客服要求交解冻费，交完又以认证失败、征信异常继续收费。",
        "verify_methods": ["持牌银行/消费金融公司官网", "官方应用商店", "中国人民银行征信中心官方渠道", "96110反诈咨询"],
        "early_do": ["只走持牌机构官方渠道", "核实App是否来自官方应用商店", "先看合同和收费规则"],
        "early_dont": ["不要点短信贷款链接", "不要提交人脸和通讯录", "不要相信黑户可贷秒到账"],
        "preloss_do": ["放款前收费立即停止", "保存App页面和客服话术", "联系官方机构核验"],
        "preloss_dont": ["不要交保证金/解冻费", "不要刷流水", "不要提供验证码"],
        "loss_do": ["保存合同、App、客服和转账记录", "联系银行止付并监控账户", "报警并留意个人信息被冒用"],
        "loss_dont": ["不要继续交钱修复征信", "不要相信内部通道放款", "不要删除App数据"],
    },
    "scam_phishing_link": {
        "code": "PHISH",
        "rule": "陌生链接只要让你填账号、银行卡或验证码，就先关闭并走官方入口核验。",
        "lure": "账户异常、积分兑换、ETC认证、快递理赔或活动领取",
        "trap": "仿冒网页收集账号密码、银行卡、身份证和短信验证码",
        "feature_focus": "陌生链接、银行卡身份信息、验证码、仿冒域名和诱导安装App",
        "verify_focus": "官方App/官网入口、域名、发送者账号和页面权限",
        "critical_facts": ["是否点击链接或扫码", "是否填写账号密码/身份证/银行卡", "是否输入验证码", "是否下载APK或授权权限", "是否出现异常登录或扣款"],
        "loss_signals": ["验证码已输入", "银行卡已绑定或扣款", "账号被异地登录", "下载了陌生APK", "对方继续索要认证"],
        "case_focus": "仿冒页面如何拿走账户授权",
        "case_early": "用户收到“ETC认证失效”短信，链接页面和官方很像，要求填写车牌、身份证、银行卡和手机号。",
        "case_loss": "用户在钓鱼页输入验证码后银行卡被扣款，页面仍提示认证失败并要求再次输入短信码。",
        "verify_methods": ["官方App", "平台官网", "官方客服电话", "96110反诈咨询"],
        "early_do": ["从官方App重新进入业务", "检查域名和证书", "截图保存短信和链接"],
        "early_dont": ["不要在链接里填敏感信息", "不要安装未知APK", "不要扫陌生二维码"],
        "preloss_do": ["关闭页面并清理授权", "修改相关账号密码", "联系平台确认异常登录"],
        "preloss_dont": ["不要输入验证码", "不要继续补填资料", "不要把页面转给更多人"],
        "loss_do": ["冻结银行卡或支付账户", "修改密码并退出所有设备", "保存链接、页面和扣款记录后报警"],
        "loss_dont": ["不要再次输入验证码", "不要相信页面客服", "不要删除短信"],
    },
    "scam_ai_face_family": {
        "code": "AI_FACE",
        "rule": "视频或语音像本人也不能直接转账，必须用原号码或线下共同信息二次核验。",
        "lure": "AI换脸/拟声冒充亲友领导，制造紧急借钱场景",
        "trap": "拒绝二次核验、要求保密催促、让钱转到非本人账户",
        "feature_focus": "AI换脸冒充、熟人借钱、保密催促、非本人账户和拒绝核验",
        "verify_focus": "原号码回拨、暗号核验、共同联系人确认和收款账户一致性",
        "critical_facts": ["是否通过新账号联系", "是否做过视频/语音但时间很短", "是否拒绝原号码回拨", "收款账户是否本人", "是否已经转账"],
        "loss_signals": ["已向第三方账户转账", "对方继续要求保密加急", "原本人否认借钱", "对方删除账号或失联", "继续追加费用"],
        "case_focus": "AI拟真身份如何绕过熟人信任",
        "case_early": "用户收到同学视频通话，对方画面像本人但很快挂断，随后称手机坏了让转钱到朋友账户。",
        "case_loss": "用户未回拨原号码就向第三方账户转账，后来联系本人发现账号被盗，视频是伪造素材合成。",
        "verify_methods": ["原手机号码回拨", "共同好友/家人核实", "线下暗号", "单位或学校官方通讯录"],
        "early_do": ["挂断后用原号码回拨", "问只有本人知道的细节", "核对收款账户实名"],
        "early_dont": ["不要只凭短视频确认身份", "不要按要求保密", "不要向非本人账户转账"],
        "preloss_do": ["让对方换渠道实时核验", "找共同联系人确认", "保存视频、语音和账号信息"],
        "preloss_dont": ["不要被紧急理由催着转账", "不要绕开家人同学核实", "不要点击对方链接"],
        "loss_do": ["联系银行止付", "报警并提供视频语音、账号和转账流水", "提醒本人账号可能被盗"],
        "loss_dont": ["不要继续追加借款", "不要删除通话记录", "不要相信对方退款承诺"],
    },
    "scam_acquaintance_borrow": {
        "code": "ACQ",
        "rule": "熟人新账号借钱、不方便通话、收款账户不是本人，必须先核实再转。",
        "lure": "领导、老师、同学、亲友突然用新账号联系借钱",
        "trap": "以开会、保密、急事为由拒绝电话核验并要求转第三方账户",
        "feature_focus": "熟人新账号、借钱、拒绝电话核实、保密催促和第三方收款",
        "verify_focus": "原联系方式、共同联系人、线下见面和收款账户实名",
        "critical_facts": ["是否是新账号或临时账号", "是否能原号码通话核实", "是否要求保密", "收款账户是否本人", "是否已经转账"],
        "loss_signals": ["向第三方账户转账", "本人否认借款", "新账号拉黑失联", "继续以急事追加借款", "要求删除聊天记录"],
        "case_focus": "盗号或仿冒熟人如何利用关系压力",
        "case_early": "用户收到自称领导的新微信，对方说正在开会不方便电话，让先帮忙垫付一笔款。",
        "case_loss": "用户按要求转给第三方账户后，原领导账号回复从未借钱，新号随即拉黑。",
        "verify_methods": ["原号码电话", "单位/学校通讯录", "共同联系人", "线下确认"],
        "early_do": ["通过原渠道确认身份", "核对头像昵称以外的信息", "保留新账号资料"],
        "early_dont": ["不要因领导/亲友身份直接转账", "不要接受不能通话的解释", "不要保密处理"],
        "preloss_do": ["先打原电话或找共同联系人", "核实收款账户实名", "把借款要求截图"],
        "preloss_dont": ["不要转第三方账户", "不要分多笔规避提醒", "不要删除证据"],
        "loss_do": ["联系银行止付", "报警并提交新账号和收款账户", "提醒真实熟人账号可能被盗"],
        "loss_dont": ["不要继续追加", "不要相信马上退还", "不要让对方远程处理"],
    },
    "scam_code_account_theft": {
        "code": "CODE",
        "rule": "验证码就是账户钥匙，任何人索要短信码、登录码、支付码都不能给。",
        "lure": "身份核验、退款确认、账户异常、好友辅助验证",
        "trap": "索要验证码后登录、绑卡、改密、转账或盗刷",
        "feature_focus": "验证码、身份核验、支付绑卡授权和账户异常恐吓",
        "verify_focus": "平台官方安全中心、异常登录记录和支付授权",
        "critical_facts": ["是否收到验证码", "验证码用途是什么", "是否已经告诉对方", "账号是否还能登录", "是否有异常扣款/绑卡/改密"],
        "loss_signals": ["验证码已泄露", "账号异地登录", "绑定信息被改", "银行卡/支付账户被扣款", "对方继续索要新验证码"],
        "case_focus": "一个验证码如何变成账户控制权",
        "case_early": "用户接到自称平台安全员电话，对方说账户异常，需要读出短信码完成安全验证。",
        "case_loss": "用户把验证码发给对方后账号被改密，支付账户出现异常扣款，客服还要求继续提供新的验证码。",
        "verify_methods": ["平台官方安全中心", "支付平台官方客服", "银行官方客服", "96110反诈咨询"],
        "early_do": ["看清短信里的用途和收款/登录提示", "从官方App查看异常", "提醒身边人不要代收验证码"],
        "early_dont": ["不要读出验证码", "不要截图发验证码", "不要让别人远程看短信"],
        "preloss_do": ["立即拒绝并挂断", "修改密码并退出所有设备", "关闭免密支付和可疑授权"],
        "preloss_dont": ["不要重复接收验证码", "不要点对方链接", "不要共享屏幕看短信"],
        "loss_do": ["冻结账户和银行卡", "修改密码、解绑陌生设备", "保存短信和交易记录后报警"],
        "loss_dont": ["不要再给新验证码", "不要相信客服代处理", "不要删除短信"],
    },
    "scam_screen_remote_control": {
        "code": "SCREEN",
        "rule": "陌生人让你开屏幕共享或远程控制，本质上就是让对方看你的钱包和验证码。",
        "lure": "客服退款、贷款认证、征信修复、退改签或公检法视频办案",
        "trap": "共享屏幕时打开银行支付页面、验证码和密码输入界面",
        "feature_focus": "屏幕共享、远程控制、会议软件、打开支付银行页面和暴露验证码",
        "verify_focus": "会议来源、官方业务渠道、设备权限和支付账户安全",
        "critical_facts": ["是否正在共享屏幕或远程控制", "是否打开过银行/支付/验证码页面", "是否下载会议软件", "是否输入密码或验证码", "是否已转账/扣款"],
        "loss_signals": ["远程控制仍在进行", "屏幕暴露验证码", "支付页面被对方指导操作", "异常转账扣款", "设备安装未知配置或App"],
        "case_focus": "屏幕共享如何绕开验证码保护",
        "case_early": "用户为办理退款加入会议，对方要求共享屏幕并指导打开支付宝和银行卡页面。",
        "case_loss": "用户共享屏幕时短信验证码被看到，对方同步完成转账操作，之后还要求继续验证账户。",
        "verify_methods": ["官方App业务入口", "平台官方客服", "手机权限管理", "银行/支付平台官方客服"],
        "early_do": ["立即退出会议和远程控制", "检查设备权限和已安装App", "保存会议号和对方账号"],
        "early_dont": ["不要共享屏幕", "不要打开支付银行页面", "不要让对方远程点击"],
        "preloss_do": ["断网或结束远控", "修改支付和银行密码", "联系官方客服核实业务"],
        "preloss_dont": ["不要输入验证码", "不要转账刷流水", "不要继续听指令操作"],
        "loss_do": ["联系银行/支付平台冻结止付", "卸载可疑远控软件并查杀", "保存会议记录和交易记录后报警"],
        "loss_dont": ["不要重新加入会议", "不要把设备交给对方处理", "不要删除软件前忘记截图"],
    },
    "scam_game_trade": {
        "code": "GAME",
        "rule": "游戏交易让你离开官方渠道、先给账号密码或交保证金，就先停下来核实。",
        "lure": "高价买号、低价代充、担保平台和爽快成交",
        "trap": "虚假平台冻结货款、账号密码索取、保证金/解冻费连环收费",
        "feature_focus": "私下交易、虚假担保平台、账号密码、保证金解冻费和交易对象失联",
        "verify_focus": "游戏官方交易渠道、账号绑定、平台客服真实性和资产控制权",
        "critical_facts": ["账号/装备是否已交付", "账号密码或验证码是否给过对方", "是否还能登录并控制绑定", "是否已充值保证金/解冻费", "交易平台是否官方认证"],
        "loss_signals": ["账号或装备已交付", "密码/验证码已泄露", "保证金已充值", "对方以冻结/零头继续收费", "账号被改绑或买家失联"],
        "case_focus": "假担保平台如何同时骗钱和盗号",
        "case_early": "用户在游戏公屏卖号，买家引导到所谓担保平台，客服称银行卡填错导致货款冻结。",
        "case_loss": "用户交了解冻保证金后，客服又说金额没带零头要再充，买家同时已经拿到账号密码准备改绑。",
        "verify_methods": ["游戏官方客服", "官方交易平台", "账号安全中心", "96110反诈咨询"],
        "early_do": ["只走官方交易渠道", "核实平台域名和客服入口", "保持账号绑定在自己手里"],
        "early_dont": ["不要私下给账号密码", "不要交保证金/解冻费", "不要相信假担保平台页面"],
        "preloss_do": ["立刻修改密码和检查绑定", "开启登录保护", "保存平台、买家和客服聊天"],
        "preloss_dont": ["不要继续充值", "不要给验证码", "不要交付账号或装备"],
        "loss_do": ["联系游戏官方申诉冻结异常操作", "保存充值/转账和聊天记录", "报警并提交平台网址和收款账户"],
        "loss_dont": ["不要再交零头/二次解冻费", "不要相信客服退款", "不要删除账号登录记录"],
    },
    "scam_campus_fee_impersonation": {
        "code": "CAMPUS_FEE",
        "rule": "班费、资料费、报名费只要脱离学校官方渠道收款，就先找老师本人核实。",
        "lure": "冒充老师辅导员在班群发布缴费通知",
        "trap": "二维码/群收款限时缴费，阻止学生家长向官方核实",
        "feature_focus": "冒充老师辅导员、班级费用名目、群内扫码、限时催促和拒绝核验",
        "verify_focus": "老师本人、学校缴费系统、班主任电话和班级官方通知",
        "critical_facts": ["发通知的账号是否老师本人", "是否通过学校官方缴费系统", "收款账户/二维码是谁", "是否催促限时缴费", "是否禁止找老师核实"],
        "loss_signals": ["已扫码转账", "老师本人否认收费", "群内账号退群或改名", "继续追加费用", "收款账户为个人"],
        "case_focus": "假老师进群收费如何利用集体压力",
        "case_early": "骗子混入班级群，头像昵称改成老师，发布资料费收款二维码并要求当天缴清。",
        "case_loss": "多名家长扫码付款后，班主任确认没有收费安排，假老师账号退群，二维码收款账户为陌生个人。",
        "verify_methods": ["老师本人电话", "学校官方缴费系统", "班主任/辅导员办公室", "学校官网"],
        "early_do": ["电话联系老师本人", "查看学校官方通知", "提醒群管理员核验成员身份"],
        "early_dont": ["不要直接扫群内二维码", "不要只看头像昵称", "不要被截止时间催着付款"],
        "preloss_do": ["核对收款主体是否学校", "在班群提醒先核实", "保存缴费通知和账号信息"],
        "preloss_dont": ["不要向个人账户交学杂费", "不要私聊转账", "不要转发未核实通知"],
        "loss_do": ["联系老师和学校说明情况", "保存付款凭证和群聊记录", "报警并提交收款二维码/账户"],
        "loss_dont": ["不要继续补缴", "不要删除群聊", "不要相信退款客服"],
    },
    "scam_job_internship_recruitment": {
        "code": "JOB",
        "rule": "入职前让你交报名费、押金、培训贷或内推费的招聘，先按诈骗处理。",
        "lure": "高薪轻松、名企内推、实习保offer和快速入职",
        "trap": "入职前收费、培训贷、脱离招聘平台私聊和虚假合同",
        "feature_focus": "轻松高薪、入职前收费、收费内推、培训贷和私聊引流",
        "verify_focus": "企业官网招聘页、人社/学校就业渠道、合同主体和收费项目",
        "critical_facts": ["招聘来源和企业主体", "是否要求入职前交费", "是否办理培训贷/分期", "合同或offer是否官方", "是否已转账或签约"],
        "loss_signals": ["已交押金/内推费", "办理培训贷", "岗位不存在", "中介失联", "继续要求保密费/档案费"],
        "case_focus": "高薪招聘如何包装成收费内推和培训贷",
        "case_early": "用户在社交平台看到名企远程实习，HR要求脱离招聘平台私聊，并承诺交内推费就能保offer。",
        "case_loss": "用户交费后又被要求办理培训贷才能上岗，签约主体不是招聘企业，后续岗位迟迟无法入职。",
        "verify_methods": ["企业官网招聘页", "学校就业指导中心", "人社部门公开渠道", "正规招聘平台客服"],
        "early_do": ["核验企业邮箱和官网职位", "保留招聘页面和HR账号", "询问学校就业老师"],
        "early_dont": ["不要脱离平台私聊付款", "不要相信保offer", "不要交押金报名费"],
        "preloss_do": ["要求对方提供正式合同和收费依据", "核对收款主体", "拒绝培训贷和分期"],
        "preloss_dont": ["不要办理贷款上岗", "不要交体检服装资料费给个人", "不要把身份证银行卡发给陌生HR"],
        "loss_do": ["保存合同、聊天和付款记录", "联系平台/学校就业中心投诉", "涉嫌诈骗时报警"],
        "loss_dont": ["不要继续交保证金", "不要相信补交就能入职", "不要删除招聘信息"],
    },
    "scam_scholarship_subsidy_phishing": {
        "code": "SCHOLARSHIP",
        "rule": "奖助学金和退费不会让你先转账激活，也不会索要银行卡验证码。",
        "lure": "奖助学金到账、学费退费、补贴资格异常",
        "trap": "填写银行卡身份信息、索要验证码或先转账激活补贴",
        "feature_focus": "奖助学金异常、学费退费、银行卡身份信息、验证码和先转账激活",
        "verify_focus": "学校资助中心、财务处、辅导员和官方通知系统",
        "critical_facts": ["通知来源是否学校官方", "是否填写银行卡/身份证", "是否提供验证码", "是否被要求先转账激活", "是否已扣款"],
        "loss_signals": ["验证码已泄露", "银行卡被扣款", "先转账激活补贴", "页面提示继续认证", "对方冒充学校部门失联"],
        "case_focus": "补贴退费如何变成钓鱼盗刷",
        "case_early": "用户收到“奖学金补录”短信，链接页面要求填写身份证、银行卡和手机号以核对发放资格。",
        "case_loss": "用户输入验证码后银行卡被扣款，页面仍提示认证失败，客服要求再转一笔激活金才能退回。",
        "verify_methods": ["学校资助中心", "学校财务处", "辅导员/班主任", "学校官方信息系统"],
        "early_do": ["通过学校系统核实通知", "问辅导员或资助中心", "保存短信链接"],
        "early_dont": ["不要在陌生链接填银行卡", "不要给验证码", "不要先转账激活"],
        "preloss_do": ["关闭页面并修改相关密码", "联系学校财务核验", "检查银行卡交易提醒"],
        "preloss_dont": ["不要继续认证", "不要把身份信息发给陌生客服", "不要下载不明App"],
        "loss_do": ["联系银行冻结止付", "保存短信、网页和扣款记录", "向学校和公安机关报告"],
        "loss_dont": ["不要相信退费专员", "不要再次输入验证码", "不要删除短信"],
    },
    "scam_exam_thesis_service": {
        "code": "EXAM",
        "rule": "保过、代考、代写和论文包过本身就高危，继续交保密费只会被勒索。",
        "lure": "考试保过、内部答案、论文代写降重和包录取",
        "trap": "先收定金尾款，随后以保密费、删记录费、举报威胁继续加价",
        "feature_focus": "违规保过、论文代写、定金尾款、加价保密费和拒绝正规合同",
        "verify_focus": "学校考试规定、正规教务渠道、合同合法性和服务边界",
        "critical_facts": ["服务是否涉及违规代考/代写", "是否已支付定金或尾款", "对方是否威胁举报/曝光", "是否提供个人学号证件", "是否继续加价"],
        "loss_signals": ["已交定金尾款", "服务未交付", "被威胁曝光或举报", "继续索要保密费", "个人信息和论文材料被控制"],
        "case_focus": "违规服务如何从交易变成敲诈",
        "case_early": "用户联系论文代写，对方承诺查重包过，要求先交定金并提供学号、学校和论文题目。",
        "case_loss": "用户付款后对方交付低质内容，又以掌握聊天记录和学校信息为由索要保密费，否则威胁举报。",
        "verify_methods": ["学校教务处", "导师/辅导员", "正规学习辅导机构", "公安机关"],
        "early_do": ["回到正规学习辅导渠道", "保留对方违规承诺", "向老师咨询补救方式"],
        "early_dont": ["不要购买答案/代考/代写", "不要提供学号证件", "不要交定金"],
        "preloss_do": ["停止付款并保存威胁记录", "避免继续提供材料", "必要时向学校或警方求助"],
        "preloss_dont": ["不要交保密费", "不要被举报威胁勒索", "不要继续违规交易"],
        "loss_do": ["保存付款和威胁证据", "主动寻求学校合规补救", "遭遇敲诈时报警"],
        "loss_dont": ["不要继续转账封口", "不要删除聊天", "不要向对方提供更多个人资料"],
    },
    "scam_secondhand_ticket_trade": {
        "code": "SECONDHAND",
        "rule": "二手和票务交易脱离担保平台、先付定金或低价内部票，都要先核验。",
        "lure": "低价二手、演唱会/车票内部名额和校园熟人交易",
        "trap": "私下转账定金、脱离担保平台、票据截图造假和卖家失联",
        "feature_focus": "内部低价票货、私下定金、脱离担保平台、票务退款屏幕共享和催促抢名额",
        "verify_focus": "官方票务平台、校园实名身份、担保交易和票据真伪",
        "critical_facts": ["商品/票据是否真实可核验", "是否脱离平台私下转账", "是否已付定金", "卖家身份是否可确认", "是否要求屏幕共享退款"],
        "loss_signals": ["已付定金后卖家失联", "票据无法核验或重复售卖", "快递空包", "继续要求补尾款/手续费", "退款时要求共享屏幕"],
        "case_focus": "低价票货如何诱导脱离担保",
        "case_early": "用户在校园群看到低价演唱会票，卖家发来订单截图并称名额紧张，要先转定金锁票。",
        "case_loss": "用户私下转账后发现票码无效，卖家又要求补手续费才能退款，随后拉黑。",
        "verify_methods": ["官方票务平台", "二手平台担保交易", "校园实名渠道", "平台客服"],
        "early_do": ["使用平台担保交易", "核验票务订单和实名信息", "保留卖家主页和聊天"],
        "early_dont": ["不要私下转定金", "不要相信超低价内部票", "不要脱离平台沟通"],
        "preloss_do": ["要求当面验货或平台担保", "确认退改规则", "截图商品、票据和收款账户"],
        "preloss_dont": ["不要提前确认收货", "不要走朋友代付", "不要开屏幕共享办退款"],
        "loss_do": ["向平台投诉冻结卖家", "保存付款和聊天记录", "涉嫌诈骗时报警"],
        "loss_dont": ["不要再补尾款手续费", "不要相信二次退款链接", "不要删除订单"],
    },
    "scam_rental_deposit": {
        "code": "RENTAL",
        "rule": "没看房、没核验房东和产权，就先交押金或定金，风险很高。",
        "lure": "低价好房、急租、近学校和名额抢手",
        "trap": "未看房先付押金、假房东、拒绝合同收据和平台外付款",
        "feature_focus": "低价房源、未看房押金、房东身份未核验、拒绝合同收据和平台外付款",
        "verify_focus": "房源实地、产权/租赁授权、正规合同和平台担保",
        "critical_facts": ["是否实地看房", "房东身份和产权是否核验", "是否签正规合同收据", "是否平台外付款", "是否已交押金/定金"],
        "loss_signals": ["已交押金后无法看房", "房东失联", "房源不存在或重复出租", "拒绝退款", "继续要求中介费/锁房费"],
        "case_focus": "低价房源如何骗取押金",
        "case_early": "用户看到学校附近低价房，房东称看房的人很多，要求先转押金保留房源。",
        "case_loss": "用户转押金后对方推迟看房，后来发现房源照片盗用，所谓房东账号已失联。",
        "verify_methods": ["正规租房平台", "小区物业/房屋产权资料", "线下看房", "公安机关"],
        "early_do": ["实地看房并核验产权或授权", "通过平台担保支付", "保存房源链接和聊天"],
        "early_dont": ["不要未看房先交押金", "不要向个人陌生账户转账", "不要相信明显低价急租"],
        "preloss_do": ["要求合同、收据和身份信息一致", "核对房源是否重复发布", "让同学家人陪同看房"],
        "preloss_dont": ["不要平台外付款", "不要交锁房费", "不要接受口头承诺"],
        "loss_do": ["联系平台投诉和冻结账号", "保存房源、聊天、转账凭证", "金额较大或失联时报案"],
        "loss_dont": ["不要继续交中介费", "不要删除房源截图", "不要相信补交就能退押金"],
    },
    "scam_nude_chat_extortion": {
        "code": "NUDE",
        "rule": "裸聊被威胁时，转钱不会删视频，只会让勒索升级。",
        "lure": "陌生交友、暧昧视频、诱导下载直播/交友App",
        "trap": "窃取通讯录后用隐私视频威胁转账，付款后继续勒索",
        "feature_focus": "交友App、通讯录威胁、隐私视频、转账删视频和付款后继续勒索",
        "verify_focus": "立即止付止联、保护通讯录、证据保存和报警求助",
        "critical_facts": ["是否下载陌生App并授权通讯录", "对方是否掌握隐私视频/照片", "是否威胁群发", "是否已经转账", "是否仍在持续勒索"],
        "loss_signals": ["已付款仍继续要钱", "通讯录被截图威胁", "隐私内容被发送", "对方要求借贷转账", "持续恐吓不准报警"],
        "case_focus": "裸聊勒索如何利用羞耻感持续收割",
        "case_early": "用户在交友软件认识陌生人，被诱导下载直播App并开启视频，对方随后发来通讯录截图。",
        "case_loss": "用户为让对方删视频转账，几分钟后对方又要求第二笔，否则威胁发给同学和家人。",
        "verify_methods": ["110或派出所", "平台举报入口", "手机权限管理", "可信家人朋友"],
        "early_do": ["立即停止视频和聊天", "撤销通讯录等权限", "保存威胁截图"],
        "early_dont": ["不要继续裸聊", "不要下载陌生App", "不要相信付钱删视频"],
        "preloss_do": ["不转账并拉黑前先取证", "告诉可信的人协助处理", "必要时报警"],
        "preloss_dont": ["不要借钱付款", "不要按要求录更多内容", "不要删除威胁记录"],
        "loss_do": ["停止继续付款", "保存转账和威胁证据", "报警并说明被敲诈勒索"],
        "loss_dont": ["不要继续谈判加价", "不要因为害怕独自处理", "不要相信二次追删视频"],
    },
    "scam_two_cards_rent": {
        "code": "TWO_CARDS",
        "rule": "出租出借银行卡、电话卡、收款码或实名账号，可能卷入涉诈洗钱和跑分。",
        "lure": "日结高薪、无风险兼职、只借卡刷流水",
        "trap": "用你的卡号账户收转涉诈资金，账户冻结甚至承担法律风险",
        "feature_focus": "出租两卡、跑分收款、日结高薪、收款码实名账号和账户涉案冻结",
        "verify_focus": "银行卡电话卡实名责任、资金来源和兼职合法性",
        "critical_facts": ["是否出租/出售银行卡电话卡", "是否提供收款码或实名账号", "是否帮陌生人收转账", "资金来源是否不明", "账户是否被冻结或被警方联系"],
        "loss_signals": ["银行卡/支付账户被冻结", "收到涉案通知", "被要求继续过账", "身份证和账户被控制", "无法说明资金来源"],
        "case_focus": "跑分兼职如何把学生变成涉诈工具人",
        "case_early": "用户看到日结兼职，对方说只要提供银行卡和收款码帮忙走流水，每天能拿几百元。",
        "case_loss": "用户帮忙收转多笔资金后银行卡被冻结，才知道账户被用于电信诈骗资金流转。",
        "verify_methods": ["银行官方客服", "公安机关", "学校老师/家长", "反诈宣传渠道"],
        "early_do": ["拒绝出租出借两卡", "核实兼职资金来源", "提醒同学不要代收款"],
        "early_dont": ["不要卖卡卖号", "不要帮陌生人过账", "不要出租收款码"],
        "preloss_do": ["立即停止收转账", "保留对方招募和转账指令", "联系银行说明异常"],
        "preloss_dont": ["不要继续刷流水", "不要帮助取现转移", "不要隐瞒账户用途"],
        "loss_do": ["主动向银行和公安说明情况", "提交对方招募账号和交易流水", "配合账户核查"],
        "loss_dont": ["不要继续受人指使转移资金", "不要删除聊天记录", "不要相信交钱解冻账户"],
    },
    "scam_travel_ticket_refund": {
        "code": "TRAVEL",
        "rule": "机票火车票退改签只走官方App，要求共享屏幕、验证码或手续费保证金就是高危。",
        "lure": "航班/车次延误取消、改签补偿和高额理赔",
        "trap": "下载App或会议软件、屏幕共享、索要验证码银行卡和先交手续费",
        "feature_focus": "退改签通知、下载App、屏幕共享、验证码银行卡和手续费保证金",
        "verify_focus": "航司/铁路官方App、订单页、官方客服电话和短信来源",
        "critical_facts": ["航班/车次是否真实变动", "是否通过官方订单页办理", "是否下载App或共享屏幕", "是否提供银行卡/验证码", "是否已交手续费/保证金"],
        "loss_signals": ["验证码泄露", "已交退改签手续费", "屏幕共享暴露支付页面", "账户异常扣款", "对方继续要求认证"],
        "case_focus": "退改签通知如何引导屏幕共享盗刷",
        "case_early": "用户收到航班取消短信，对方自称航空客服，要求下载会议软件办理赔付。",
        "case_loss": "用户共享屏幕填写银行卡并读出验证码后被扣款，对方又称操作失败需继续认证。",
        "verify_methods": ["航司官方App/官网", "铁路12306官方渠道", "订单平台官方客服", "96110反诈咨询"],
        "early_do": ["从官方订单页核实退改签", "核对短信发送号码", "保存来电和短信"],
        "early_dont": ["不要点击短信链接", "不要下载陌生App", "不要共享屏幕"],
        "preloss_do": ["停止填写银行卡验证码", "挂断后拨打官方客服", "检查支付账户状态"],
        "preloss_dont": ["不要交手续费/保证金", "不要刷流水", "不要让客服远程指导"],
        "loss_do": ["联系银行/支付平台止付", "保存短信、号码、会议记录和交易流水", "报警"],
        "loss_dont": ["不要继续认证退款", "不要相信二次理赔", "不要删除订单和短信"],
    },
    "scam_fake_prize_gift": {
        "code": "PRIZE",
        "rule": "中奖免费礼品如果要先交税费、保证金或填验证码，免费就变成了骗局。",
        "lure": "中奖、免费礼品、抽奖福利和限时领奖",
        "trap": "领奖前交税费保证金、填写银行卡验证码或点陌生链接",
        "feature_focus": "中奖礼品、先交税费保证金、银行卡验证码、陌生链接二维码和限时催促",
        "verify_focus": "活动主办方、官方活动页面、领奖规则和是否先收费",
        "critical_facts": ["活动来源是否官方", "是否要求先交税费/邮费/保证金", "是否填写银行卡/验证码", "是否点击领奖链接", "是否已付款"],
        "loss_signals": ["已交税费保证金", "验证码泄露后扣款", "继续要求补认证费", "奖品无法发货", "客服失联"],
        "case_focus": "免费礼品如何一步步收费",
        "case_early": "用户收到中奖短信，页面显示中了大奖，但领奖前需要填写身份证和银行卡验证身份。",
        "case_loss": "用户交了税费后，客服又说需要保证金和通道费，否则奖品和已付款项都无法退回。",
        "verify_methods": ["品牌/平台官方App", "活动官网", "官方客服", "96110反诈咨询"],
        "early_do": ["从官方活动页核实", "查看主办方和规则", "保存中奖通知"],
        "early_dont": ["不要点陌生领奖链接", "不要填写银行卡验证码", "不要相信限时威胁"],
        "preloss_do": ["遇到先收费立即停止", "核实收款主体", "截图活动页面"],
        "preloss_dont": ["不要交税费/保证金", "不要转发链接拉人", "不要提供身份银行卡"],
        "loss_do": ["保存支付凭证和客服聊天", "联系支付平台尝试拦截", "报警或向平台举报"],
        "loss_dont": ["不要继续补认证费", "不要相信客服退款", "不要删除领奖页面"],
    },
    "scam_credit_repair_cancel_account": {
        "code": "CREDIT",
        "rule": "征信修复、注销账户、刷流水验证这些说法，遇到转账和屏幕共享就是诈骗。",
        "lure": "征信异常、校园贷账户未注销、百万保障扣费和影响贷款",
        "trap": "转账刷流水、共享屏幕、索要验证码和所谓安全账户核验",
        "feature_focus": "征信会员恐吓、注销账户、刷流水验证、屏幕共享和验证码",
        "verify_focus": "人民银行征信中心、平台官方客服、官方App账户设置",
        "critical_facts": ["对方自称哪个平台或机构", "是否要求注销账户/修复征信", "是否共享屏幕", "是否转账刷流水", "是否提供验证码或银行卡"],
        "loss_signals": ["已转账刷流水", "屏幕共享暴露账户", "验证码泄露", "贷款/支付账户被控制", "继续要求二次认证"],
        "case_focus": "征信恐吓如何诱导刷流水转账",
        "case_early": "用户接到自称金融平台客服电话，说学生时期账户未注销会影响征信，要求配合清零额度。",
        "case_loss": "用户按要求把多张银行卡余额转到指定账户刷流水，对方又要求贷款套现继续清查。",
        "verify_methods": ["中国人民银行征信中心官方渠道", "金融平台官方App", "银行官方客服", "96110反诈咨询"],
        "early_do": ["挂断后查官方征信渠道", "从平台App设置查看账户", "保存来电号码和话术"],
        "early_dont": ["不要开屏幕共享", "不要转账刷流水", "不要把验证码告诉客服"],
        "preloss_do": ["停止转账和远程操作", "联系官方平台核验", "检查银行卡和贷款授权"],
        "preloss_dont": ["不要贷款套现清额度", "不要转入安全账户", "不要下载陌生App"],
        "loss_do": ["联系银行/支付平台止付冻结", "保存通话、转账和App记录", "报警并说明征信修复诈骗"],
        "loss_dont": ["不要继续借贷转账", "不要相信征信修复专员", "不要删除聊天记录"],
    },
    "scam_romance_investment": {
        "code": "ROMANCE",
        "rule": "网恋对象带你投资、博彩或刷单赚钱，本质上要先按杀猪盘警惕。",
        "lure": "情感陪伴、成功人设、共同未来和内部投资机会",
        "trap": "引导到投资/博彩/刷单平台，前期盈利后大额入金，提现失败继续收费",
        "feature_focus": "情感关系、投资博彩刷单、保本高收益、提现失败和拒绝现实核验",
        "verify_focus": "真实身份、线下核验、平台资质和资金去向",
        "critical_facts": ["是否从未线下见面", "对方是否引导投资/博彩/刷单", "平台是否陌生", "是否已入金", "是否能提现"],
        "loss_signals": ["已大额入金", "提现失败要求继续充值", "对方拒绝见面/视频核验", "平台客服和恋爱对象一起催款", "对方失联"],
        "case_focus": "情感信任如何转化为投资收割",
        "case_early": "用户在交友软件认识对象，对方每天聊天建立亲密关系，随后分享内部投资平台说一起攒未来资金。",
        "case_loss": "用户多次入金后提现失败，恋爱对象劝其再交保证金，后来平台打不开，对方也失联。",
        "verify_methods": ["现实身份核验", "金融监管公开查询", "亲友共同判断", "96110反诈咨询"],
        "early_do": ["把投资和感情分开判断", "核验对方真实身份", "查询平台资质"],
        "early_dont": ["不要向陌生平台入金", "不要相信恋爱对象内幕消息", "不要隐瞒亲友"],
        "preloss_do": ["停止投资和充值", "保存聊天与平台页面", "让可信亲友一起看风险"],
        "preloss_dont": ["不要借钱加仓", "不要交提现保证金", "不要转虚拟币到陌生地址"],
        "loss_do": ["整理入金流水和聊天记录", "联系银行/支付平台尝试拦截", "报警并提交平台和对方账号"],
        "loss_dont": ["不要继续被感情话术劝充值", "不要相信追回资金团队", "不要删除交友记录"],
    },
}


def _load(name: str) -> List[Dict[str, Any]]:
    path = KNOWLEDGE_DIR / f"{name}.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError(f"{path} must contain a list")
    return [item for item in data if isinstance(item, dict)]


def _write(name: str, rows: List[Dict[str, Any]]) -> None:
    path = KNOWLEDGE_DIR / f"{name}.json"
    path.write_text(json.dumps(rows, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _merge_unique(*groups: Iterable[Any], limit: int | None = None) -> List[Any]:
    result: List[Any] = []
    seen = set()
    for group in groups:
        for item in _as_list(group):
            if item in (None, "", [], {}):
                continue
            key = json.dumps(item, ensure_ascii=False, sort_keys=True) if isinstance(item, (dict, list)) else str(item)
            if key in seen:
                continue
            seen.add(key)
            result.append(item)
            if limit and len(result) >= limit:
                return result
    return result


def _stamp(row: Dict[str, Any], now: str) -> Dict[str, Any]:
    row.setdefault("created_at", now)
    row["updated_at"] = now
    row["knowledge_version"] = BUILD_VERSION
    return row


def _source_refs(row: Dict[str, Any], *refs: Iterable[str]) -> None:
    row["source_refs"] = _merge_unique(row.get("source_refs"), *refs, LOCAL_SOURCE_REFS)


def _upsert(rows: List[Dict[str, Any]], id_field: str, row: Dict[str, Any]) -> None:
    row_id = row.get(id_field)
    if not row_id:
        raise ValueError(f"missing {id_field}: {row}")
    for index, existing in enumerate(rows):
        if existing.get(id_field) == row_id:
            merged = dict(existing)
            merged.update(row)
            rows[index] = merged
            return
    rows.append(row)


def _stage_goals(profile: Dict[str, Any]) -> Dict[str, str]:
    data = {
        "rule": profile["rule"],
        "lure": profile["lure"],
        "trap": profile["trap"],
        "feature_focus": profile["feature_focus"],
        "verify_focus": profile["verify_focus"],
        "case_focus": profile["case_focus"],
    }
    return {stage: template.format(**data) for stage, template in STAGE_GOAL_TEMPLATES.items()}


def _features_by_scam(features: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for feature in features:
        grouped[str(feature.get("scam_id") or "")].append(feature)
    for items in grouped.values():
        items.sort(key=lambda item: int(float(item.get("risk_weight") or 0)), reverse=True)
    return grouped


def _scam_name_by_id(scams: List[Dict[str, Any]]) -> Dict[str, str]:
    return {str(item.get("scam_id") or ""): str(item.get("name") or "") for item in scams}


def _make_teaching_policy(scam: Dict[str, Any], profile: Dict[str, Any], now: str) -> Dict[str, Any]:
    code = profile["code"]
    return _stamp(
        {
            "policy_id": f"KDP_{code}_FINAL_V1",
            "policy_type": "scam_teaching_path",
            "title": f"{scam['name']}教学路径",
            "enabled": True,
            "priority": 90,
            "fraud_type": scam["name"],
            "scam_id": scam["scam_id"],
            "aliases": _merge_unique(scam.get("aliases"), [profile["lure"], profile["trap"]], limit=14),
            "stage_goals": _stage_goals(profile),
            "one_sentence_rule": profile["rule"],
            "teaching_material_requirements": {
                "must_use": ["scam_features", "prevention_advice", "typical_cases", "law_clauses"],
                "stage_policy": "每轮只取当前阶段最相关材料，避免一次性百科输出。",
                "must_cover_in_summary": ["核心识别点", "关键手法", "防范核验", "证据和报警常识"],
            },
            "closure_policy": {
                "summary_stage_closes_workflow": True,
                "after_summary": "active_workflow=idle；用户短确认不继续触发教学。",
            },
            "source_refs": _merge_unique(POLICE_SOURCE_REFS, COMMON_SOURCE_REFS, LOCAL_SOURCE_REFS),
        },
        now,
    )


def _make_prevention_rows(scam: Dict[str, Any], profile: Dict[str, Any], now: str) -> List[Dict[str, Any]]:
    code = profile["code"]
    common = {
        "fraud_type": scam["name"],
        "official_verification_methods": profile["verify_methods"],
        "common_misconceptions": [
            f"{profile['lure']}看起来真实就可靠",
            "对方催得急所以必须马上操作",
            "先交一点钱或给一次验证码问题不大",
        ],
        "source_refs": _merge_unique(POLICE_SOURCE_REFS, COMMON_SOURCE_REFS, LOCAL_SOURCE_REFS),
    }
    rows = [
        {
            "advice_id": f"PREVENT_{code}_EARLY_FINAL",
            "risk_stage": "接触引流阶段",
            "intervention_goal": "verify_identity",
            "advice": f"刚接触到{profile['lure']}时，先把身份、渠道和平台真实性核清楚，不要被第一眼的熟悉感或小利益带着走。",
            "do": profile["early_do"],
            "dont": profile["early_dont"],
        },
        {
            "advice_id": f"PREVENT_{code}_PRELOSS_FINAL",
            "risk_stage": "资金转账前阶段",
            "intervention_goal": "stop_transfer",
            "advice": f"一旦出现{profile['trap']}，先停止转账、共享、填码或交付资产，再走官方渠道核验。",
            "do": profile["preloss_do"],
            "dont": profile["preloss_dont"],
        },
        {
            "advice_id": f"PREVENT_{code}_LOSS_FINAL",
            "risk_stage": "已损失阶段",
            "intervention_goal": "call_police",
            "advice": "如果已经付款、泄露信息或交付账号资产，重点是止损、冻结、取证和报警，不要再用继续交钱的方式追回。",
            "do": profile["loss_do"],
            "dont": profile["loss_dont"],
        },
    ]
    return [_stamp({**common, **row}, now) for row in rows]


def _make_case_rows(scam: Dict[str, Any], profile: Dict[str, Any], now: str) -> List[Dict[str, Any]]:
    code = profile["code"]
    common = {
        "fraud_type": scam["name"],
        "privacy_level": "desensitized",
        "source_refs": _merge_unique(POLICE_SOURCE_REFS, COMMON_SOURCE_REFS, LOCAL_SOURCE_REFS),
    }
    rows = [
        {
            "case_id": f"CASE_{code}_EARLY_FINAL",
            "risk_stage": "建立信任阶段",
            "summary": profile["case_early"],
            "key_pattern": f"{profile['lure']} + {profile['trap'].split('、')[0]}",
            "lesson": f"看到{profile['lure']}时，不要只看表面可信度，必须核验渠道和后续资金/信息要求。",
            "use_when": [profile["lure"], profile["feature_focus"], "建立信任阶段"],
        },
        {
            "case_id": f"CASE_{code}_LOSS_FINAL",
            "risk_stage": "已损失阶段",
            "summary": profile["case_loss"],
            "key_pattern": f"{profile['trap']} + 损失扩大",
            "lesson": "损失发生后继续交钱、继续给信息或继续配合，只会扩大风险；应立即止损取证并报警。",
            "use_when": profile["loss_signals"][:5],
        },
    ]
    return [_stamp({**common, **row}, now) for row in rows]


def _make_report_guide(scam: Dict[str, Any], profile: Dict[str, Any], now: str) -> Dict[str, Any]:
    code = profile["code"]
    return _stamp(
        {
            "guide_id": f"REPORT_{code}_FINAL",
            "input_type": "mixed",
            "fraud_type": scam["name"],
            "required_fields": [
                "发生时间",
                "对方账号/电话/平台名称",
                "诱导话术",
                "是否已转账或泄露信息",
                "金额、收款账户或链接/App",
            ],
            "suggested_summary_template": (
                f"用户遇到疑似{scam['name']}：对方以{profile['lure']}为由接触，"
                f"后续出现{profile['trap']}等风险点。已发生操作：{{actions}}；金额/账户/链接：{{evidence}}。"
            ),
            "evidence_checklist": [
                "聊天记录和通话记录",
                "对方账号、电话号码、群聊或平台页面",
                "链接、二维码、App名称或下载来源",
                "转账/充值/扣款凭证",
                "对方要求继续操作的关键话术",
            ],
            "next_actions": [
                "先停止继续付款、共享屏幕、输入验证码或交付账号资产",
                "联系银行/支付平台/相关官方平台做止付、冻结或申诉",
                "拨打110或前往派出所报案并提交证据",
            ],
            "source_refs": _merge_unique(POLICE_SOURCE_REFS, COMMON_SOURCE_REFS, LOCAL_SOURCE_REFS),
        },
        now,
    )


def _make_evidence_guide(scam: Dict[str, Any], profile: Dict[str, Any], now: str) -> Dict[str, Any]:
    code = profile["code"]
    return _stamp(
        {
            "guide_id": f"EVIDENCE_{code}_FINAL",
            "fraud_type": scam["name"],
            "scenario": "通用取证",
            "evidence_items": [
                "完整聊天记录",
                "对方账号/电话/群聊信息",
                "链接、二维码、App或平台页面",
                "收款账户和转账/充值凭证",
                "对方催促、威胁或要求保密的原话",
            ],
            "collection_tips": [
                "先停止危险操作再取证",
                "截图要包含时间、账号、金额和平台名称",
                "能导出原始账单或订单号时同时保存",
            ],
            "warning": "不要为了补齐证据继续转账、输入验证码、共享屏幕或联系对方。",
            "source_refs": _merge_unique(POLICE_SOURCE_REFS, COMMON_SOURCE_REFS, LOCAL_SOURCE_REFS),
        },
        now,
    )


def _condition_terms(rule: Dict[str, Any]) -> List[str]:
    conditions = rule.get("conditions") if isinstance(rule.get("conditions"), dict) else {}
    return [str(item) for key in ["all", "any"] for item in _as_list(conditions.get(key)) if str(item or "").strip()]


def _match_feature_ids(term: str, fraud_type: str, features: List[Dict[str, Any]], scam_name_to_id: Dict[str, str]) -> List[str]:
    scam_id = scam_name_to_id.get(fraud_type, "")
    compact = term.replace(" ", "")
    matched = []
    for feature in features:
        if str(feature.get("scam_id") or "") != scam_id and str(feature.get("fraud_type") or "") != fraud_type:
            continue
        name = str(feature.get("feature_name") or "")
        candidates = [name, *[str(item) for item in _as_list(feature.get("keywords"))]]
        if any(compact and (compact in item.replace(" ", "") or item.replace(" ", "") in compact) for item in candidates if item):
            matched.append(str(feature.get("feature_id")))
    return _merge_unique(matched)


def _classify_term(term: str, matched_feature_ids: List[str]) -> str:
    if matched_feature_ids:
        return "feature"
    if term.startswith("已") or any(word in term for word in ["无法", "失联", "冻结", "泄露", "暴露", "不能提现", "登不上"]):
        return "fact"
    if any(word in term for word in ["要求", "索要", "诱导", "下载", "共享", "转账", "垫付", "交", "充值"]):
        return "action"
    return "semantic"


def enrich_scam_types(data: Dict[str, List[Dict[str, Any]]], now: str) -> None:
    for scam in data["scam_types"]:
        scam_id = str(scam.get("scam_id") or "")
        profile = SCAM_PROFILES.get(scam_id)
        if not profile:
            continue
        short_name = str(scam.get("name") or "").replace("诈骗", "").strip()
        scam["aliases"] = _merge_unique(scam.get("aliases"), [short_name] if short_name else [], limit=16)
        scam["critical_facts"] = profile["critical_facts"]
        scam["loss_signals"] = profile["loss_signals"]
        scam["one_sentence_rule"] = profile["rule"]
        scam["risk_formula"] = f"{profile['lure']} + {profile['trap']}"
        scam["knowledge_coverage"] = {
            "has_teaching_path": True,
            "has_stage_prevention": True,
            "has_multiple_cases": True,
            "has_report_guide": True,
            "has_evidence_guide": True,
        }
        _source_refs(scam, POLICE_SOURCE_REFS, COMMON_SOURCE_REFS)
        _stamp(scam, now)


def enrich_dialogue_policy(data: Dict[str, List[Dict[str, Any]]], now: str) -> None:
    scam_ids = {item["scam_id"] for item in data["scam_types"]}
    for policy in data["knowledge_dialogue_policy"]:
        if policy.get("policy_id") == "KDP_CAMPUS_LOAN_V1" and policy.get("scam_id") not in scam_ids:
            policy["scam_id"] = "scam_fake_loan"
        if policy.get("policy_type") == "global_teaching_contract":
            contract = policy.setdefault("teaching_contract", {})
            contract.setdefault("knowledge_grounding", {})
            contract["knowledge_grounding"].update(
                {
                    "must_read_materials": [
                        "scam_types.critical_facts",
                        "scam_types.loss_signals",
                        "scam_features",
                        "prevention_advice",
                        "typical_cases",
                        "law_clauses",
                    ],
                    "generation_rule": "LLM 只能基于检索到的结构化知识扩写，不编造法律条文号或不存在的官方流程。",
                }
            )
        _source_refs(policy, COMMON_SOURCE_REFS)
        _stamp(policy, now)

    for scam in data["scam_types"]:
        profile = SCAM_PROFILES.get(str(scam.get("scam_id") or ""))
        if not profile:
            continue
        existing = next(
            (
                row
                for row in data["knowledge_dialogue_policy"]
                if row.get("policy_type") == "scam_teaching_path" and row.get("fraud_type") == scam.get("name")
            ),
            None,
        )
        policy = _make_teaching_policy(scam, profile, now)
        if existing:
            existing.update(
                {
                    "scam_id": scam["scam_id"],
                    "aliases": _merge_unique(existing.get("aliases"), policy["aliases"], limit=18),
                    "stage_goals": {**policy["stage_goals"], **(existing.get("stage_goals") or {})},
                    "one_sentence_rule": existing.get("one_sentence_rule") or policy["one_sentence_rule"],
                    "teaching_material_requirements": policy["teaching_material_requirements"],
                    "closure_policy": policy["closure_policy"],
                }
            )
            _source_refs(existing, POLICE_SOURCE_REFS, COMMON_SOURCE_REFS)
            _stamp(existing, now)
        else:
            _upsert(data["knowledge_dialogue_policy"], "policy_id", policy)


def enrich_prevention_cases_reports(data: Dict[str, List[Dict[str, Any]]], now: str) -> None:
    for scam in data["scam_types"]:
        profile = SCAM_PROFILES.get(str(scam.get("scam_id") or ""))
        if not profile:
            continue
        for row in _make_prevention_rows(scam, profile, now):
            _upsert(data["prevention_advice"], "advice_id", row)
        for row in _make_case_rows(scam, profile, now):
            _upsert(data["typical_cases"], "case_id", row)
        if not any(item.get("fraud_type") == scam["name"] for item in data["report_guides"]):
            _upsert(data["report_guides"], "guide_id", _make_report_guide(scam, profile, now))
        if not any(item.get("fraud_type") == scam["name"] for item in data["evidence_guides"]):
            _upsert(data["evidence_guides"], "guide_id", _make_evidence_guide(scam, profile, now))

    for collection, source_refs in [
        ("prevention_advice", POLICE_SOURCE_REFS),
        ("typical_cases", POLICE_SOURCE_REFS),
        ("report_guides", POLICE_SOURCE_REFS),
        ("evidence_guides", POLICE_SOURCE_REFS),
    ]:
        for row in data[collection]:
            _source_refs(row, source_refs, COMMON_SOURCE_REFS)
            _stamp(row, now)


def enrich_risk_rules(data: Dict[str, List[Dict[str, Any]]], now: str) -> None:
    scam_name_to_id = {item["name"]: item["scam_id"] for item in data["scam_types"]}
    features = data["scam_features"]
    for rule in data["risk_rules"]:
        fraud_type = str(rule.get("fraud_type") or "")
        conditions = rule.get("conditions") if isinstance(rule.get("conditions"), dict) else {}
        structured_groups = []
        all_terms = []
        for operator in ["all", "any"]:
            group_terms = []
            for term in _as_list(conditions.get(operator)):
                term = str(term or "").strip()
                if not term:
                    continue
                matched_ids = _match_feature_ids(term, fraud_type, features, scam_name_to_id)
                group_terms.append(
                    {
                        "term": term,
                        "condition_type": _classify_term(term, matched_ids),
                        "matched_feature_ids": matched_ids,
                    }
                )
                all_terms.append((operator, term, matched_ids))
            structured_groups.append({"operator": operator, "terms": group_terms})
        rule["condition_schema_version"] = "v2"
        rule["semantic_condition_groups"] = structured_groups
        rule["feature_conditions"] = {
            "all": [term for operator, term, ids in all_terms if operator == "all" and ids],
            "any": [term for operator, term, ids in all_terms if operator == "any" and ids],
            "matched_feature_ids": _merge_unique([fid for _, _, ids in all_terms for fid in ids]),
        }
        rule["fact_conditions"] = [
            term
            for _, term, ids in all_terms
            if not ids and _classify_term(term, ids) == "fact"
        ]
        rule["action_conditions"] = [
            term
            for _, term, ids in all_terms
            if not ids and _classify_term(term, ids) == "action"
        ]
        rule["semantic_conditions"] = [
            term
            for _, term, ids in all_terms
            if not ids and _classify_term(term, ids) == "semantic"
        ]
        rule["risk_reasoning_steps"] = [
            "识别用户描述的诈骗类型和阶段",
            "确认是否出现资金、账号、验证码、屏幕共享或个人信息暴露",
            "优先阻止当前最危险动作，再给止损、取证和报警建议",
        ]
        _source_refs(rule, POLICE_SOURCE_REFS, COMMON_SOURCE_REFS)
        _stamp(rule, now)


def enrich_laws_and_sources(data: Dict[str, List[Dict[str, Any]]], now: str) -> None:
    all_fraud_types = [item["name"] for item in data["scam_types"]]
    mappings = {
        "LAW_PRE_TRANSFER_DISSUASION_001": all_fraud_types,
        "LAW_STOP_PAYMENT_001": all_fraud_types,
        "LAW_CODE_LEAK_001": ["验证码/账户盗刷诈骗", "冒充客服诈骗", "钓鱼链接诈骗", "机票火车票退改签诈骗", "奖助学金/学费退费诈骗"],
        "LAW_SCREEN_SHARE_DISSUASION_001": ["屏幕共享/远程控制诈骗", "冒充客服诈骗", "冒充公检法诈骗", "征信修复/注销账户诈骗", "机票火车票退改签诈骗"],
        "LAW_APP_INSTALL_RISK_001": ["网络贷款诈骗", "虚假投资理财诈骗", "屏幕共享/远程控制诈骗", "裸聊敲诈勒索诈骗", "钓鱼链接诈骗"],
        "LAW_ID_BANK_LEAK_001": ["网络贷款诈骗", "钓鱼链接诈骗", "奖助学金/学费退费诈骗", "虚假中奖/免费礼品诈骗", "冒充客服诈骗"],
        "LAW_PHISH_REPORT_001": ["钓鱼链接诈骗", "奖助学金/学费退费诈骗", "虚假中奖/免费礼品诈骗", "冒充客服诈骗"],
        "LAW_EVIDENCE_001": all_fraud_types,
        "LAW_VIRTUAL_ASSET_LOSS_001": ["游戏交易诈骗"],
        "LAW_TWO_CARDS_RISK_001": ["两卡出租出借与跑分诈骗", "网络贷款诈骗", "刷单返利诈骗"],
        "LAW_EXTORTION_EVIDENCE_001": ["裸聊敲诈勒索诈骗", "考试考证论文服务诈骗"],
    }
    for law in data["law_clauses"]:
        law_id = str(law.get("law_id") or "")
        law["related_scam_types"] = _merge_unique(law.get("related_scam_types"), mappings.get(law_id, all_fraud_types))
        law.setdefault("legal_basis_type", "general_handling_guidance")
        law.setdefault("user_visible_boundary", "只输出一般处置常识，不替代公安机关、银行或专业法律意见。")
        _source_refs(law, LAW_SOURCE_REFS, COMMON_SOURCE_REFS)
        _stamp(law, now)

    extra_laws = [
        {
            "law_id": "LAW_OFFICIAL_VERIFICATION_001",
            "topic": "官方渠道核验和二次确认",
            "related_behaviors": ["官方核验", "身份核实", "二次确认", "保密催促"],
            "related_scam_types": all_fraud_types,
            "plain_summary": "遇到自称客服、公检法、老师、熟人、平台或投资贷款机构的人要求转账、验证码、屏幕共享时，应先脱离对方提供的渠道，通过官网、官方App、110、派出所或现实联系人核验。",
            "actions": ["挂断或暂停沟通", "从官方App/官网/原号码重新发起联系", "让家人、老师或同事参与核验"],
            "evidence_to_preserve": ["来电号码", "账号主页", "链接/App页面", "要求保密或催促的聊天记录"],
            "disclaimer": "以下为一般核验建议，不替代公安机关、银行或专业法律意见。",
            "source_refs": _merge_unique(LAW_SOURCE_REFS, COMMON_SOURCE_REFS, LOCAL_SOURCE_REFS),
        },
        {
            "law_id": "LAW_SECONDARY_SCAM_PREVENTION_001",
            "topic": "被骗后的二次诈骗防范",
            "related_behaviors": ["追回资金", "网警", "黑客追款", "二次收费", "证据保存"],
            "related_scam_types": all_fraud_types,
            "plain_summary": "被骗后声称能通过内部关系、网警、黑客或维权通道追回资金，并要求先交手续费、保证金或解冻费的，通常是二次诈骗风险。",
            "actions": ["只通过公安机关、银行、支付平台和官方平台跟进", "不要向追款中介付款", "补充新线索时提交给办案民警或官方平台"],
            "evidence_to_preserve": ["追款人员账号", "收费要求", "原诈骗证据", "新的收款账户"],
            "disclaimer": "追回资金以公安机关、银行和支付平台实际处理结果为准。",
            "source_refs": _merge_unique(LAW_SOURCE_REFS, COMMON_SOURCE_REFS, LOCAL_SOURCE_REFS),
        },
        {
            "law_id": "LAW_CAMPUS_SUPPORT_001",
            "topic": "学生和校园场景求助支持",
            "related_behaviors": ["学生求助", "老师核验", "家长协助", "校园缴费", "奖助学金"],
            "related_scam_types": ["冒充公检法诈骗", "冒充老师辅导员收费诈骗", "奖助学金/学费退费诈骗", "网络贷款诈骗", "求职实习招聘诈骗", "考试考证论文服务诈骗"],
            "plain_summary": "学生遇到恐吓、收费、贷款、奖助学金或求职类疑似诈骗时，不应独自承受压力，应尽快找老师、家长、学校相关部门或派出所核验。",
            "actions": ["告诉辅导员、班主任或家长", "联系学校财务处、资助中心或就业中心", "必要时拨打110或去派出所"],
            "evidence_to_preserve": ["通知截图", "缴费二维码", "对方账号", "转账记录", "威胁或保密话术"],
            "disclaimer": "以下为校园场景一般求助建议，不替代学校正式处理或公安机关意见。",
            "source_refs": _merge_unique(LAW_SOURCE_REFS, COMMON_SOURCE_REFS, LOCAL_SOURCE_REFS),
        },
    ]
    for law in extra_laws:
        _upsert(data["law_clauses"], "law_id", _stamp(law, now))


def enrich_global_sources(data: Dict[str, List[Dict[str, Any]]], now: str) -> None:
    for name, rows in data.items():
        for row in rows:
            if name in {"stage_definitions", "semantic_risk_policy", "knowledge_dialogue_policy"}:
                _source_refs(row, COMMON_SOURCE_REFS)
            else:
                _source_refs(row, COMMON_SOURCE_REFS)
            _stamp(row, now)


def main() -> int:
    now = datetime.now().isoformat(timespec="seconds")
    names = [
        "scam_types",
        "scam_features",
        "risk_rules",
        "semantic_risk_policy",
        "knowledge_dialogue_policy",
        "prevention_advice",
        "typical_cases",
        "law_clauses",
        "report_guides",
        "stage_definitions",
        "evidence_guides",
    ]
    data = {name: _load(name) for name in names}

    enrich_scam_types(data, now)
    enrich_dialogue_policy(data, now)
    enrich_prevention_cases_reports(data, now)
    enrich_risk_rules(data, now)
    enrich_laws_and_sources(data, now)
    enrich_global_sources(data, now)

    for name in names:
        _write(name, data[name])

    summary = {name: len(rows) for name, rows in data.items()}
    print(json.dumps({"updated_at": now, "counts": summary}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
