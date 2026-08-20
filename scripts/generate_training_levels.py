import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUTS = [
    ROOT / "app" / "modules" / "training_camp" / "data" / "seed_game_levels.json",
    ROOT / "app" / "game_process" / "data" / "seed_game_levels.json",
]


SCAM_PACKAGES = [
    {
        "scam_type_id": "scam_brush_rebate",
        "fraud_type": "刷单返利诈骗",
        "badge": "刷单识别者",
        "title": "刷单返利",
        "actor": "派单客服",
        "contexts": [
            "群里发来兼职刷单任务，前两单返了小额佣金，第三单提现失败。",
            "对方称店铺冲销量，要求连续补单才能一起结算。",
            "陌生 App 显示账户有收益，但提现页面提示账户冻结。",
            "客服说数据异常，需要继续完成组合任务才能退本金。",
            "对方承诺学生兼职日结，但要求先垫付大额订单。",
        ],
        "risks": ["先垫付资金", "连续补单", "提现失败后交解冻费", "通过陌生 App 操作"],
        "safe_actions": ["停止补单并保存聊天和转账记录", "不要再垫付任何资金", "退出陌生 App 并保留截图", "向官方平台或 96110 核实"],
        "wrong_actions": ["继续做完组合任务", "再交一笔解冻费", "删除聊天记录避免麻烦", "按客服要求借钱周转", "把银行卡发给客服核验"],
    },
    {
        "scam_type_id": "scam_game_trade",
        "fraud_type": "游戏交易诈骗",
        "badge": "游戏交易守门员",
        "title": "游戏交易",
        "actor": "游戏交易中介",
        "contexts": [
            "买家要求你离开官方交易平台，到私聊群完成账号交易。",
            "所谓担保客服称账号已冻结，需要缴保证金才能放款。",
            "对方说平台手续费异常，让你向私人账户转一笔验证金。",
            "买家催促先交账号密码，承诺确认后马上付款。",
            "陌生链接显示游戏币到账，但提现要先完成实名认证和押金。",
        ],
        "risks": ["脱离官方平台", "私下交账号密码", "缴纳保证金", "陌生交易链接"],
        "safe_actions": ["只在官方平台交易并拒绝私下转账", "不要提供账号密码和验证码", "停止交易并保留对方账号信息", "向游戏官网客服核实订单"],
        "wrong_actions": ["先把账号密码发过去", "交保证金让平台解冻", "点击对方发来的交易链接", "按中介要求扫码付款", "删除订单重新私聊"],
    },
    {
        "scam_type_id": "scam_fake_customer_service",
        "fraud_type": "冒充客服诈骗",
        "badge": "客服核验员",
        "title": "冒充客服",
        "actor": "冒充平台客服",
        "contexts": [
            "自称电商客服来电，说你的订单质量问题可三倍理赔。",
            "对方说快递丢失，要你点击链接填写银行卡收退款。",
            "客服称会员误开通，每月扣费，需要共享屏幕关闭。",
            "短信提示包裹异常，链接页面要求输入身份证和验证码。",
            "对方说退款通道拥堵，让你下载会议软件远程指导。",
        ],
        "risks": ["理赔退款诱导", "索要银行卡和验证码", "屏幕共享", "陌生链接填写信息"],
        "safe_actions": ["通过官方 App 查询订单和退款", "不要在陌生链接输入银行卡信息", "立即停止屏幕共享", "挂断电话后联系官方客服"],
        "wrong_actions": ["按对方要求共享屏幕", "把验证码告诉客服", "在链接里填写银行卡", "下载对方指定会议软件", "向所谓安全账户转账"],
    },
    {
        "scam_type_id": "scam_fake_police",
        "fraud_type": "冒充公检法诈骗",
        "badge": "公检法防线",
        "title": "冒充公检法",
        "actor": "冒充民警",
        "contexts": [
            "陌生电话称你银行卡涉嫌洗钱，要求视频做笔录。",
            "对方发来带警徽的通缉令，要求把钱转入安全账户。",
            "所谓办案人员让你保密，不许告诉家人和老师。",
            "对方要求下载会议软件，开启屏幕共享接受资金审查。",
            "电话转接到外地公安，要求提供银行卡密码配合调查。",
        ],
        "risks": ["安全账户", "要求保密", "视频办案", "索要密码或验证码"],
        "safe_actions": ["挂断并拨打 110 或属地派出所核实", "拒绝转入所谓安全账户", "不要透露银行卡密码和验证码", "及时告诉家人或学校老师"],
        "wrong_actions": ["按要求把钱转到安全账户", "继续保密接受调查", "下载软件共享屏幕", "把银行卡密码发给对方", "相信通缉令图片"],
    },
    {
        "scam_type_id": "scam_romance_investment",
        "fraud_type": "杀猪盘诈骗",
        "badge": "情感投资识别者",
        "title": "情感投资",
        "actor": "网恋对象",
        "contexts": [
            "网恋对象说掌握投资平台漏洞，带你短期翻倍。",
            "对方每天关心你，随后推荐虚拟币内部通道。",
            "平台显示收益很高，但提现需要继续充值升级会员。",
            "对方称两人未来需要共同理财，让你把钱转到指定账户。",
            "陌生投资群里多人晒收益，管理员催你抓住最后名额。",
        ],
        "risks": ["情感铺垫后投资", "虚假收益截图", "提现前继续充值", "内部通道"],
        "safe_actions": ["拒绝向陌生投资平台充值", "不要相信网恋对象的稳赚承诺", "保存聊天和转账证据后停止联系", "通过正规金融机构核验资质"],
        "wrong_actions": ["跟着对方继续加仓", "借钱补齐提现门槛", "把账户交给对方代投", "相信群友晒出的盈利截图", "下载陌生投资 App"],
    },
    {
        "scam_type_id": "scam_fake_loan",
        "fraud_type": "虚假贷款诈骗",
        "badge": "贷款安全员",
        "title": "虚假贷款",
        "actor": "贷款客服",
        "contexts": [
            "贷款 App 显示额度已批，但放款前要交保证金。",
            "客服称银行卡号填错导致资金冻结，需要解冻费。",
            "对方说征信不足，先刷流水才能提高额度。",
            "贷款页面要求上传身份证、银行卡和短信验证码。",
            "客服让你向私人账户转服务费，承诺马上放款。",
        ],
        "risks": ["放款前收费", "刷流水", "解冻费", "索要验证码"],
        "safe_actions": ["拒绝任何放款前收费要求", "通过正规银行或持牌机构申请", "不要提供验证码和支付密码", "保留 App 截图并卸载陌生贷款软件"],
        "wrong_actions": ["先交保证金等放款", "转账刷流水提高额度", "把验证码发给客服", "继续支付解冻费", "按客服要求开通网贷账户"],
    },
    {
        "scam_type_id": "scam_code_account_theft",
        "fraud_type": "验证码/账户盗刷诈骗",
        "badge": "验证码守护者",
        "title": "验证码盗刷",
        "actor": "账号验证客服",
        "contexts": [
            "好友发消息说账号异常，让你帮忙接收验证码。",
            "客服称账户需要二次认证，要求提供短信动态码。",
            "对方说只要验证码不涉及钱，可以放心发给他。",
            "陌生链接登录后提示需要输入支付验证码完成验证。",
            "同学账号发来借款消息，随后索要你的收款验证码。",
        ],
        "risks": ["索要验证码", "账号异常借口", "盗用熟人账号", "登录陌生链接"],
        "safe_actions": ["任何验证码都不转发给他人", "通过电话核实好友真实身份", "立即修改账号密码并开启保护", "退出陌生链接并清理登录状态"],
        "wrong_actions": ["把验证码截图发过去", "相信熟人账号直接帮忙", "在陌生页面继续登录", "把支付码告诉客服", "关闭账户安全提醒"],
    },
    {
        "scam_type_id": "scam_screen_share_remote",
        "fraud_type": "屏幕共享/远程控制诈骗",
        "badge": "屏幕安全官",
        "title": "屏幕共享",
        "actor": "远程协助客服",
        "contexts": [
            "对方说退款流程复杂，要你打开会议软件共享屏幕。",
            "客服让你开启远程控制，帮你关闭自动扣费。",
            "对方要求你边共享屏幕边打开银行 App 查看余额。",
            "所谓技术人员让你安装远程协助插件解决账户异常。",
            "电话里对方指导你打开付款码，说只是核验账户。",
        ],
        "risks": ["共享屏幕暴露验证码", "远程控制手机", "打开银行 App", "诱导查看付款码"],
        "safe_actions": ["立即停止屏幕共享和远程控制", "不要在通话中打开银行或支付 App", "挂断后通过官方渠道处理", "检查账户并修改重要密码"],
        "wrong_actions": ["继续让对方远程操作", "按要求打开银行 App", "展示付款码供对方核验", "下载陌生远程插件", "关闭安全提醒"],
    },
    {
        "scam_type_id": "scam_ai_face_family",
        "fraud_type": "AI 换脸冒充亲友诈骗",
        "badge": "AI识别员",
        "title": "AI 换脸",
        "actor": "仿冒亲友",
        "contexts": [
            "视频里像是亲友的人说急需手术费，要求马上转账。",
            "熟人头像发来语音借钱，声音很像但拒绝接你电话。",
            "对方视频只说几句话就挂断，随后发来收款码。",
            "自称孩子老师发来自拍视频，要求缴临时培训费。",
            "亲友账号说手机坏了，只能通过陌生账号收款。",
        ],
        "risks": ["视频或语音仿冒", "拒绝二次核验", "紧急转账", "陌生收款账户"],
        "safe_actions": ["通过原号码或共同熟人二次核实", "拒绝向陌生账户紧急转账", "询问只有本人知道的问题", "保留聊天和收款码截图"],
        "wrong_actions": ["看到视频就立刻转账", "按陌生账号要求付款", "不核实就相信语音", "删除记录保护亲友情面", "继续提供银行卡信息"],
    },
    {
        "scam_type_id": "scam_job_internship_recruitment",
        "fraud_type": "虚假招聘/实习诈骗",
        "badge": "求职守门员",
        "title": "虚假招聘",
        "actor": "招聘专员",
        "contexts": [
            "招聘方承诺高薪实习，但入职前要交培训押金。",
            "对方说内部推荐名额有限，需要先缴资料审核费。",
            "兼职群要求下载 App 接任务，先交会员费才能派单。",
            "面试通过后，HR 让你向私人账户转工牌制作费。",
            "对方要求提交身份证和银行卡照片办理工资卡。",
        ],
        "risks": ["入职前收费", "高薪低门槛", "私人账户收费", "过度收集身份信息"],
        "safe_actions": ["拒绝任何入职前收费", "通过公司官网核实招聘信息", "不要向私人账户转招聘费用", "谨慎提交身份证和银行卡照片"],
        "wrong_actions": ["先交押金保住名额", "下载 App 交会员费", "把身份证银行卡照片发群里", "向 HR 私人账户转账", "相信无需面试的高薪岗位"],
    },
    {
        "scam_type_id": "scam_scholarship_subsidy_phishing",
        "fraud_type": "奖助学金/补贴诈骗",
        "badge": "补贴核验员",
        "title": "奖助学金补贴",
        "actor": "补贴办理员",
        "contexts": [
            "短信称你获得助学金，链接要求填写银行卡和验证码。",
            "自称教育部门人员通知补贴到账失败，要你开通网银。",
            "对方说奖学金名额即将过期，需要先缴税费。",
            "群里发补贴二维码，页面要求输入身份证和支付密码。",
            "来电称国家补助发放，要你去 ATM 按提示操作。",
        ],
        "risks": ["补贴链接填敏感信息", "先缴税费", "ATM 指导操作", "索要支付密码"],
        "safe_actions": ["向学校资助部门或辅导员核实", "不要在陌生链接填写银行卡验证码", "拒绝任何补贴前收费", "不按陌生电话操作 ATM"],
        "wrong_actions": ["马上在链接中填写验证码", "先交税费领取补贴", "按电话提示操作 ATM", "把支付密码发给办理员", "转发二维码给同学填写"],
    },
    {
        "scam_type_id": "scam_rental_deposit",
        "fraud_type": "租房押金诈骗",
        "badge": "租房安全员",
        "title": "租房押金",
        "actor": "房东中介",
        "contexts": [
            "网上房源价格明显低于市场，房东要求先付定金才看房。",
            "中介称房源抢手，让你先转押金保留名额。",
            "对方只发精装修照片，拒绝视频看房和实地看房。",
            "房东要求私下转账，不签合同也不出示产权证明。",
            "对方说人在外地，钥匙可快递，但要先付三个月租金。",
        ],
        "risks": ["未看房先付定金", "低价诱导", "拒绝合同和证明", "私下大额转账"],
        "safe_actions": ["实地看房并核验证件后再付款", "签署正规合同并保留收据", "拒绝未见房源先付押金", "通过正规平台和监管账户交易"],
        "wrong_actions": ["先转押金抢房源", "只看照片就付租金", "不签合同直接入住", "向私人账户付三个月租金", "相信低价房源不核实"],
    },
    {
        "scam_type_id": "scam_secondhand_ticket_trade",
        "fraud_type": "二手票务交易诈骗",
        "badge": "票务防骗员",
        "title": "二手票务",
        "actor": "票务卖家",
        "contexts": [
            "演唱会门票卖家要求微信私下转账，拒绝走担保平台。",
            "对方发来电子票截图，但要求先付全款再转票。",
            "卖家说订单异常，需要你补差价才能出票。",
            "黄牛声称有内部票，付款后再安排实名信息。",
            "对方让你点击验票链接填写身份证和银行卡。",
        ],
        "risks": ["私下转账买票", "电子票截图不可核验", "补差价出票", "陌生验票链接"],
        "safe_actions": ["通过官方票务平台交易", "拒绝私下全款转账", "核验票源和实名规则", "不要在陌生验票链接填身份证银行卡"],
        "wrong_actions": ["先付全款等转票", "相信截图就确认购票", "继续补差价出票", "点击陌生链接验票", "把实名信息发给黄牛"],
    },
    {
        "scam_type_id": "scam_nude_chat_extortion",
        "fraud_type": "裸聊敲诈诈骗",
        "badge": "隐私防护员",
        "title": "裸聊敲诈",
        "actor": "敲诈者",
        "contexts": [
            "陌生人诱导视频裸聊后，威胁把录屏发给通讯录好友。",
            "对方让你下载交友 App，随后读取通讯录进行威胁。",
            "敲诈者要求连续转账买断视频，否则马上群发。",
            "对方发来通讯录截图，要求你不要报警只转账。",
            "陌生账号诱导发送隐私照片后索要封口费。",
        ],
        "risks": ["隐私视频威胁", "读取通讯录", "连续敲诈", "禁止报警"],
        "safe_actions": ["停止转账并保存威胁证据", "不要继续发送隐私内容", "尽快报警并告知可信成年人", "检查并卸载可疑 App"],
        "wrong_actions": ["继续转账买断视频", "删除证据独自处理", "再发送照片证明诚意", "按对方要求不要报警", "提供更多联系人信息"],
    },
    {
        "scam_type_id": "scam_two_cards_rent",
        "fraud_type": "两卡出租出借诈骗",
        "badge": "两卡守护者",
        "title": "两卡出租",
        "actor": "收卡人员",
        "contexts": [
            "陌生人租借你的银行卡和电话卡，承诺每天给租金。",
            "兼职人员要求你实名办卡后交给他们刷流水。",
            "对方说只是公司走账，不会影响你的征信。",
            "有人收购学生银行卡、U 盾和手机卡，现场给现金。",
            "群里发布高价收卡广告，要求配合人脸识别开户。",
        ],
        "risks": ["出租银行卡电话卡", "刷流水", "配合人脸开户", "可能涉案违法"],
        "safe_actions": ["拒绝出租出借出售银行卡和电话卡", "保护实名账户和 U 盾", "发现收卡线索及时举报", "不要配合陌生人刷流水"],
        "wrong_actions": ["把银行卡租给对方", "配合人脸识别开户", "出售手机卡赚快钱", "相信只是公司走账", "帮别人刷流水"],
    },
    {
        "scam_type_id": "scam_travel_ticket_refund",
        "fraud_type": "机票退改签诈骗",
        "badge": "出行核验员",
        "title": "退改签",
        "actor": "航司客服",
        "contexts": [
            "自称航空客服来电，说航班取消可领取补偿金。",
            "短信提示机票退改签，链接要求填写银行卡和验证码。",
            "客服说理赔通道异常，需要你下载会议软件操作。",
            "对方要求先转手续费，补偿金随后一起退回。",
            "所谓客服能准确说出航班信息，随后索要支付验证码。",
        ],
        "risks": ["退改签补偿诱导", "索要验证码", "会议软件指导", "先交手续费"],
        "safe_actions": ["通过航司官方 App 或客服电话核实", "不要提供银行卡验证码", "拒绝下载会议软件处理退票", "不要先交手续费领取补偿"],
        "wrong_actions": ["点击短信链接填写银行卡", "把验证码告诉客服", "先转手续费等退款", "共享屏幕办理退票", "相信对方能说出航班信息"],
    },
    {
        "scam_type_id": "scam_campus_fee_impersonation",
        "fraud_type": "冒充老师收费诈骗",
        "badge": "班群核验员",
        "title": "冒充老师收费",
        "actor": "冒充老师",
        "contexts": [
            "班级群里有人换成老师头像，通知缴资料费。",
            "群公告突然要求扫码缴培训费，收款方是个人账户。",
            "对方催促家长马上付款，说晚了影响报名。",
            "所谓老师私聊你补交考试费，拒绝电话确认。",
            "群里多个账号配合催缴，制造大家都已付款的氛围。",
        ],
        "risks": ["班群冒充老师", "个人收款码", "催促缴费", "拒绝电话核实"],
        "safe_actions": ["通过学校官方渠道或电话核实", "不向个人收款码缴学校费用", "提醒群管理员核验身份", "保留截图并等待正式通知"],
        "wrong_actions": ["看到老师头像就扫码付款", "被催促后马上转账", "私聊补交考试费", "转发收款码给同学", "不核实就相信群公告"],
    },
    {
        "scam_type_id": "scam_exam_thesis_service",
        "fraud_type": "考试论文代办诈骗",
        "badge": "学业诚信守护者",
        "title": "考试论文代办",
        "actor": "代办中介",
        "contexts": [
            "对方承诺保过考试，要求先交报名和保密费。",
            "论文代写中介说查重不过可退款，但要先付全款。",
            "所谓内部老师提供答案，要求你交押金进群。",
            "对方以泄露记录威胁你继续补尾款。",
            "中介要求提供学号密码，代你登录教务系统操作。",
        ],
        "risks": ["保过承诺", "先付全款", "索要教务账号密码", "违规把柄威胁"],
        "safe_actions": ["拒绝考试论文代办和保过服务", "不要提供教务账号密码", "保留威胁证据并向学校求助", "通过正规学习支持渠道解决问题"],
        "wrong_actions": ["先交押金进内部群", "提供学号密码给中介", "继续补尾款防止曝光", "相信查重不过退款", "购买所谓考试答案"],
    },
    {
        "scam_type_id": "scam_credit_repair_cancel_account",
        "fraud_type": "征信修复/注销账户诈骗",
        "badge": "征信安全员",
        "title": "征信修复",
        "actor": "金融平台客服",
        "contexts": [
            "对方称你的校园贷账户影响征信，需要注销。",
            "客服说不关闭网贷账户会产生高额年费。",
            "所谓银监人员要求你把贷款额度转出做清零验证。",
            "对方说可以修复征信，但要先交服务费。",
            "电话要求你下载多个贷款 App，把额度提现吗再转回。",
        ],
        "risks": ["注销账户诱导贷款", "清零验证", "征信修复收费", "冒充监管人员"],
        "safe_actions": ["通过官方金融机构核实账户状态", "拒绝把贷款额度转出验证", "不要支付征信修复服务费", "咨询银行或征信中心正规渠道"],
        "wrong_actions": ["把贷款额度提现转给对方", "先交征信修复费", "按客服要求下载网贷 App", "相信监管人员电话指导", "提供支付密码做清零"],
    },
    {
        "scam_type_id": "scam_fake_prize_gift",
        "fraud_type": "虚假中奖/免费礼品诈骗",
        "badge": "中奖免疫者",
        "title": "虚假中奖",
        "actor": "领奖客服",
        "contexts": [
            "短信称你抽中大奖，领奖前要先交个人所得税。",
            "直播间私信说免费送手机，但要付运费和激活费。",
            "对方让你点击领奖链接，填写身份证和银行卡。",
            "客服说奖品已锁定，需要提供验证码确认身份。",
            "群里发免费礼品活动，要求拉人并缴保证金。",
        ],
        "risks": ["中奖先收费", "领奖链接填敏感信息", "索要验证码", "免费礼品保证金"],
        "safe_actions": ["拒绝任何领奖前收费", "不在陌生领奖链接填写敏感信息", "不提供验证码确认身份", "通过活动官方账号核实规则"],
        "wrong_actions": ["先交税费领奖", "填写银行卡领取礼品", "把验证码发给客服", "缴保证金锁定奖品", "继续拉人完成任务"],
    },
    {
        "scam_type_id": "scam_phishing_link",
        "fraud_type": "钓鱼链接诈骗",
        "badge": "链接鉴别师",
        "title": "钓鱼链接",
        "actor": "链接发送者",
        "contexts": [
            "短信提示账户异常，附带一个含 login 的陌生网址。",
            "好友发来投票链接，页面要求输入支付密码。",
            "邮件称网盘文件过期，链接域名与官网很像但后缀异常。",
            "二维码页面要求输入身份证、银行卡和验证码。",
            "链接声称可领取红包，但要求先授权通讯录和短信权限。",
        ],
        "risks": ["陌生登录链接", "仿冒域名", "索要支付密码", "授权敏感权限"],
        "safe_actions": ["不要点击陌生链接或扫码登录", "手动打开官方 App 核实", "不在链接页面输入密码和验证码", "关闭异常授权并修改密码"],
        "wrong_actions": ["直接输入账号密码", "扫码后授权通讯录", "相信相似域名是官网", "把验证码填入页面", "转发链接给同学领取"],
    },
]


ACTIVE_SCAM_PACKAGES = [
    item for item in SCAM_PACKAGES
    if item["scam_type_id"] != "scam_exam_thesis_service"
]

QUESTION_BLUEPRINTS = [
    ("risk", "风险信号识别", "这段场景最应警惕的风险信号是什么？"),
    ("safe_action", "安全处理", "此时最稳妥的第一步是什么？"),
    ("danger", "危险操作辨别", "下面哪种做法最可能让损失扩大？"),
    ("type", "诈骗类型判断", "这个场景更符合哪类诈骗套路？"),
    ("verify", "官方核实渠道", "如果要核实真伪，应优先通过哪类可信渠道？"),
    ("evidence", "证据保留", "如果准备投诉、求助或报警，最该保留哪组证据？"),
    ("pressure", "话术拆解", "对方主要使用了哪种诱导或施压手法？"),
    ("reply", "阻断话术", "哪句回复最能立即阻断对方继续诱导？"),
    ("protected_info", "敏感信息保护", "这个场景中最需要保护的是哪类信息或权限？"),
    ("principle", "核心原则", "完成本题后，最应该记住哪条防骗原则？"),
]

RISK_DISTRACTORS = [
    "普通订单状态提醒",
    "正常售后进度查询",
    "公开活动规则说明",
    "常规身份称呼",
    "普通物流延迟通知",
    "平台页面视觉风格变化",
    "客服使用礼貌用语",
    "对方发送公开宣传海报",
]

SAFE_ACTION_DISTRACTORS = [
    "先按对方步骤完成一轮操作",
    "等到账后再核实对方身份",
    "把验证码发过去节省时间",
    "先小额转账测试可信度",
    "下载对方指定软件让其指导",
    "为了不影响流程暂时保密",
    "把身份证和银行卡拍照发给对方",
    "关闭安全提醒继续办理",
]

DANGEROUS_ACTION_DISTRACTORS = [
    "挂断后通过官方渠道核实",
    "保留聊天截图和转账凭证",
    "拒绝提供验证码和密码",
    "提醒家人或老师一起判断",
    "停止操作并检查账户安全",
    "通过平台客服查询订单",
    "向 96110 或 110 咨询求助",
    "卸载可疑 App 并修改密码",
]

VERIFY_CHANNELS = {
    "scam_brush_rebate": "通过官方招聘/电商平台或 96110 核实兼职任务",
    "scam_game_trade": "通过游戏官网或官方交易平台客服核实订单",
    "scam_fake_customer_service": "打开电商或快递平台官方 App 核对订单和退款",
    "scam_fake_police": "挂断后拨打 110 或联系属地派出所核实",
    "scam_romance_investment": "查询监管信息并只通过持牌金融机构核实投资资质",
    "scam_fake_loan": "通过银行或持牌贷款机构官方渠道核实贷款",
    "scam_code_account_theft": "通过原 App 安全中心或熟人原号码核实",
    "scam_screen_share_remote": "挂断后用官方 App 或客服电话处理账户问题",
    "scam_ai_face_family": "拨打亲友原号码或联系共同熟人二次核实",
    "scam_job_internship_recruitment": "通过公司官网、官方邮箱或学校就业部门核实招聘",
    "scam_scholarship_subsidy_phishing": "向学校资助部门、辅导员或官方政务渠道核实",
    "scam_rental_deposit": "实地看房并核验证件、合同和平台交易记录",
    "scam_secondhand_ticket_trade": "通过官方票务平台或主办方实名规则核实票源",
    "scam_nude_chat_extortion": "保留威胁记录后向公安机关和平台举报求助",
    "scam_two_cards_rent": "向银行、运营商或公安反诈渠道核实收卡行为",
    "scam_travel_ticket_refund": "通过航司官方 App、官网或官方客服电话核实退改签",
    "scam_campus_fee_impersonation": "通过班主任原号码、学校财务或官方通知核实收费",
    "scam_credit_repair_cancel_account": "通过银行、征信中心或金融平台官方客服核实账户",
    "scam_fake_prize_gift": "通过活动主办方官方账号或平台客服核实中奖规则",
    "scam_phishing_link": "手动打开官方 App 或官网核实链接所称事项",
}

EVIDENCE_ITEMS = {
    "scam_brush_rebate": "任务群聊天、App 余额页、提现失败提示和转账凭证",
    "scam_game_trade": "交易聊天、对方账号、陌生链接、收款码和账号交接记录",
    "scam_fake_customer_service": "来电号码、短信链接、订单页面、会议软件记录和银行卡填写页面",
    "scam_fake_police": "通话记录、所谓证件/通缉令图片、转账账户和屏幕共享提示",
    "scam_romance_investment": "聊天记录、投资平台页面、充值提现记录和对方身份信息",
    "scam_fake_loan": "贷款 App 页面、客服聊天、收费名目、转账凭证和银行卡异常提示",
    "scam_code_account_theft": "索要验证码的聊天、登录提醒、短信内容和异常登录记录",
    "scam_screen_share_remote": "会议软件邀请、屏幕共享提示、客服聊天和账户异常截图",
    "scam_ai_face_family": "视频/语音聊天记录、陌生收款账户、借款理由和二次核实过程",
    "scam_job_internship_recruitment": "招聘信息、收费要求、私人账户、合同材料和对方身份资料",
    "scam_scholarship_subsidy_phishing": "补贴短信、二维码页面、银行卡填写页和学校核实结果",
    "scam_rental_deposit": "房源链接、房东身份、产权/合同材料、聊天记录和付款凭证",
    "scam_secondhand_ticket_trade": "票务聊天、电子票截图、转票记录、实名信息要求和付款凭证",
    "scam_nude_chat_extortion": "威胁聊天、通讯录截图、转账要求、可疑 App 名称和账号信息",
    "scam_two_cards_rent": "收卡广告、聊天记录、收卡人员信息、办卡要求和付款记录",
    "scam_travel_ticket_refund": "退改签短信、来电号码、航班信息、会议软件记录和转账要求",
    "scam_campus_fee_impersonation": "群公告、收款码、冒充账号资料、缴费通知和学校核实记录",
    "scam_credit_repair_cancel_account": "通话记录、贷款 App 页面、提现要求、转账账户和客服话术",
    "scam_fake_prize_gift": "中奖短信、领奖链接、收费要求、客服聊天和活动官方核实结果",
    "scam_phishing_link": "可疑链接、仿冒域名截图、权限授权页、登录提醒和验证码短信",
}

PRESSURE_TACTICS = {
    "scam_brush_rebate": "先给小额返利，再用组合任务逼迫继续垫付",
    "scam_game_trade": "用账号冻结或保证金制造交易恐慌",
    "scam_fake_customer_service": "以退款理赔为理由催你共享屏幕或填写验证码",
    "scam_fake_police": "冒充权威并要求保密，制造涉案恐惧",
    "scam_romance_investment": "用情感信任包装稳赚投资",
    "scam_fake_loan": "用已批额度和资金冻结诱导先交钱",
    "scam_code_account_theft": "淡化验证码风险，说只是帮忙验证",
    "scam_screen_share_remote": "把远程指导包装成客服协助",
    "scam_ai_face_family": "利用熟人影像和紧急事件压缩核实时间",
    "scam_job_internship_recruitment": "用高薪低门槛和名额紧张催缴费用",
    "scam_scholarship_subsidy_phishing": "用补贴过期或到账失败制造急迫",
    "scam_rental_deposit": "用低价房源和名额抢手催付押金",
    "scam_secondhand_ticket_trade": "用稀缺票源和截图证明催你私下付款",
    "scam_nude_chat_extortion": "用隐私曝光威胁持续勒索",
    "scam_two_cards_rent": "用轻松租金淡化出借两卡的违法风险",
    "scam_travel_ticket_refund": "准确说出行程信息后以补偿金诱导验证",
    "scam_campus_fee_impersonation": "利用班群身份和群体付款氛围催缴",
    "scam_credit_repair_cancel_account": "用征信受损恐吓你提现清零",
    "scam_fake_prize_gift": "用中奖名额和免费礼品诱导先付费用",
    "scam_phishing_link": "用相似域名和异常提示诱导登录授权",
}

PROTECTED_INFO = {
    "scam_brush_rebate": "银行卡、支付验证码和转账账户信息",
    "scam_game_trade": "游戏账号密码、实名信息和支付验证码",
    "scam_fake_customer_service": "银行卡号、短信验证码、屏幕内容和支付密码",
    "scam_fake_police": "银行卡密码、验证码、账户余额和身份证件",
    "scam_romance_investment": "投资账户、银行卡、身份信息和充值记录",
    "scam_fake_loan": "身份证、银行卡、短信验证码和人脸验证信息",
    "scam_code_account_theft": "短信验证码、登录二维码和支付确认码",
    "scam_screen_share_remote": "屏幕内容、付款码、验证码和银行余额",
    "scam_ai_face_family": "亲友联系方式、收款确认和转账凭证",
    "scam_job_internship_recruitment": "身份证照片、银行卡照片和学籍信息",
    "scam_scholarship_subsidy_phishing": "身份证号、银行卡号、支付密码和验证码",
    "scam_rental_deposit": "身份证照片、银行卡和提前转账信息",
    "scam_secondhand_ticket_trade": "实名购票信息、身份证号和付款凭证",
    "scam_nude_chat_extortion": "通讯录、隐私照片视频和更多联系人信息",
    "scam_two_cards_rent": "银行卡、电话卡、U 盾和人脸验证信息",
    "scam_travel_ticket_refund": "银行卡、验证码、行程信息和支付密码",
    "scam_campus_fee_impersonation": "家长手机号、学生信息和付款截图",
    "scam_credit_repair_cancel_account": "网贷账户、贷款额度、支付密码和验证码",
    "scam_fake_prize_gift": "身份证、银行卡、验证码和收货信息",
    "scam_phishing_link": "账号密码、支付密码、验证码和通讯录权限",
}

BLOCKING_REPLIES = {
    "scam_brush_rebate": "我不再补单，也不会交解冻费；聊天和转账记录我会保留。",
    "scam_game_trade": "我只走官方交易平台，不会私发账号密码或保证金。",
    "scam_fake_customer_service": "我会自己打开官方 App 查订单，不共享屏幕也不发验证码。",
    "scam_fake_police": "我会挂断并拨打 110 核实，不转所谓安全账户。",
    "scam_romance_investment": "我不会给陌生投资平台充值，先核验资质并停止转账。",
    "scam_fake_loan": "放款前收费我不接受，我会通过正规机构重新核实。",
    "scam_code_account_theft": "验证码不能给任何人，我会先用电话确认真实身份。",
    "scam_screen_share_remote": "我马上停止共享屏幕，不在通话中打开银行或支付 App。",
    "scam_ai_face_family": "我会拨打原号码二次确认，不向陌生账户紧急转账。",
    "scam_job_internship_recruitment": "入职前收费我不交，我会通过官网和学校就业部门核实。",
    "scam_scholarship_subsidy_phishing": "我会问辅导员或资助部门，不点链接也不填银行卡验证码。",
    "scam_rental_deposit": "没实地看房和签合同前，我不会先付押金或租金。",
    "scam_secondhand_ticket_trade": "我只通过官方票务平台交易，不私下全款转账。",
    "scam_nude_chat_extortion": "我不会继续转账，会保存威胁证据并报警求助。",
    "scam_two_cards_rent": "银行卡和电话卡不能出租出借，我不会配合办卡刷流水。",
    "scam_travel_ticket_refund": "我会用航司官方渠道查退改签，不发验证码也不交手续费。",
    "scam_campus_fee_impersonation": "我会联系老师和学校财务核实，不向个人收款码付款。",
    "scam_credit_repair_cancel_account": "我不会提现贷款额度做清零验证，会联系官方客服核实。",
    "scam_fake_prize_gift": "领奖前收费和要验证码我不接受，我会查官方活动规则。",
    "scam_phishing_link": "我不会点陌生链接登录，会手动打开官网核实并修改密码。",
}

UNSAFE_REPLIES = [
    "你把链接发来，我现在按页面提示填写。",
    "我先转一小笔试试，确认没问题再继续。",
    "我可以共享屏幕，你直接告诉我点哪里。",
    "我先把验证码发你，后面再改密码。",
    "我怕错过名额，先照你说的处理完再核实。",
    "你把收款码发来，我先付款保留资格。",
    "这件事我先不告诉家人，按你的流程走。",
    "账号密码我发你，你帮我快点处理。",
]

PRINCIPLES = {
    "scam_brush_rebate": "任何要求先垫付、再返利、不能提现继续充值的任务都应停止。",
    "scam_game_trade": "游戏资产交易不脱离官方平台，不交保证金，不交账号密码。",
    "scam_fake_customer_service": "退款理赔只走官方 App，验证码和屏幕共享都拒绝。",
    "scam_fake_police": "公检法不会电话办案索要转账，也不存在安全账户。",
    "scam_romance_investment": "网恋关系不能替代投资资质，陌生平台稳赚收益不可信。",
    "scam_fake_loan": "正规贷款放款前不收费，不刷流水，不索要验证码。",
    "scam_code_account_theft": "验证码就是账户钥匙，任何人索要都不能给。",
    "scam_screen_share_remote": "屏幕共享等于把账户操作暴露给对方，应立即停止。",
    "scam_ai_face_family": "看到语音视频也要用原号码或线下关系二次确认。",
    "scam_job_internship_recruitment": "招聘入职前收费和私人账户收款都是高风险信号。",
    "scam_scholarship_subsidy_phishing": "补贴奖助学金以学校或官方通知为准，不先缴费。",
    "scam_rental_deposit": "未实地核验房源和合同前，不支付押金或大额租金。",
    "scam_secondhand_ticket_trade": "票务交易走官方实名平台，截图和私下转账不能当保障。",
    "scam_nude_chat_extortion": "遇到隐私勒索不转账，保留证据并尽快报警求助。",
    "scam_two_cards_rent": "银行卡电话卡不能出租出借出售，否则可能承担法律责任。",
    "scam_travel_ticket_refund": "退改签和赔偿只在航司或平台官方渠道办理，不交验证费。",
    "scam_campus_fee_impersonation": "学校收费必须多渠道核实，不向个人码匆忙付款。",
    "scam_credit_repair_cancel_account": "征信不能花钱修复，注销账户不需要提现转账清零。",
    "scam_fake_prize_gift": "中奖免费礼品先收费或要验证码，基本都是陷阱。",
    "scam_phishing_link": "涉及登录、密码、验证码的链接，必须手动进官网核实。",
}


def _pool(mapping: dict[str, str]) -> list[str]:
    return list(dict.fromkeys(mapping.values()))


def _rotated(items: list[str], start: int) -> list[str]:
    if not items:
        return []
    offset = start % len(items)
    return items[offset:] + items[:offset]


def unique_options(correct: str, distractors: list[str], correct_index: int) -> list[str]:
    values: list[str] = []
    for item in distractors:
        value = str(item or "").strip()
        if value and value != correct and value not in values:
            values.append(value)
    if len(values) < 3:
        raise ValueError(f"题目缺少足够干扰项：{correct}")
    options = values[:3]
    options.insert(correct_index, correct)
    return options


def _other_fraud_types(current: str, level_id: int) -> list[str]:
    values = [item["fraud_type"] for item in ACTIVE_SCAM_PACKAGES if item["fraud_type"] != current]
    return _rotated(values, level_id)


def build_question(package: dict, variant_index: int, level_id: int) -> dict:
    kind, title_suffix, question = QUESTION_BLUEPRINTS[variant_index]
    scam_type_id = package["scam_type_id"]
    context = package["contexts"][variant_index % len(package["contexts"])]
    risk = package["risks"][variant_index % len(package["risks"])]
    action = package["safe_actions"][variant_index % len(package["safe_actions"])]
    wrong = _rotated(package["wrong_actions"], variant_index)
    correct_index = (level_id - 1) % 4

    if kind == "risk":
        correct = risk
        distractors = _rotated([item for item in package["risks"] if item != correct] + RISK_DISTRACTORS, level_id)
        explanation = f"本题关键风险是“{risk}”。它会把用户推进到转账、泄露信息或脱离官方平台的环节。"
    elif kind == "safe_action":
        correct = action
        distractors = _rotated([item for item in package["safe_actions"] if item != correct] + SAFE_ACTION_DISTRACTORS, level_id)
        explanation = f"最稳妥的做法是“{action}”，先阻断对方继续诱导，再核实和留证。"
    elif kind == "danger":
        correct = wrong[0]
        distractors = _rotated(DANGEROUS_ACTION_DISTRACTORS + package["safe_actions"], level_id)
        explanation = f"“{correct}”会扩大资金、隐私或账户风险，真实场景中应立即停止。"
    elif kind == "type":
        correct = package["fraud_type"]
        distractors = _other_fraud_types(correct, level_id)
        explanation = f"该场景中的身份包装、操作要求和风险信号更符合“{package['fraud_type']}”。"
    elif kind == "verify":
        correct = VERIFY_CHANNELS[scam_type_id]
        distractors = _rotated([item for item in _pool(VERIFY_CHANNELS) if item != correct], level_id)
        explanation = f"核实要回到可信来源。本场景应优先“{correct}”，不要沿着对方给的链接或电话继续操作。"
    elif kind == "evidence":
        correct = EVIDENCE_ITEMS[scam_type_id]
        distractors = _rotated([item for item in _pool(EVIDENCE_ITEMS) if item != correct], level_id)
        explanation = f"完整证据链包括“{correct}”，有助于平台投诉、学校介入或报警处理。"
    elif kind == "pressure":
        correct = PRESSURE_TACTICS[scam_type_id]
        distractors = _rotated([item for item in _pool(PRESSURE_TACTICS) if item != correct], level_id)
        explanation = f"这类话术的核心是“{correct}”，目的是压缩你的核实时间并降低警惕。"
    elif kind == "reply":
        correct = BLOCKING_REPLIES[scam_type_id]
        distractors = _rotated(UNSAFE_REPLIES, level_id)
        explanation = f"安全回复要明确拒绝高危动作，并把核实渠道拉回官方或可信关系链。"
    elif kind == "protected_info":
        correct = PROTECTED_INFO[scam_type_id]
        distractors = _rotated([item for item in _pool(PROTECTED_INFO) if item != correct], level_id)
        explanation = f"本场景最需要保护“{correct}”，一旦泄露可能导致账户被盗、资金损失或隐私勒索。"
    else:
        correct = PRINCIPLES[scam_type_id]
        distractors = _rotated([item for item in _pool(PRINCIPLES) if item != correct], level_id)
        explanation = f"应牢记：{correct}"

    options = unique_options(correct, distractors, correct_index)
    scenario = f"{context} 对方身份自称：{package['actor']}。请根据场景判断最安全的选择。"
    return {
        "level_id": level_id,
        "title": f"{package['title']} · {title_suffix}",
        "scenario": scenario,
        "question": question,
        "options": options,
        "answer": correct,
        "points": 2,
        "badge": package["badge"],
        "explanation": explanation,
        "scam_type_id": package["scam_type_id"],
        "fraud_type": package["fraud_type"],
        "enabled": True,
    }


def main() -> None:
    levels = []
    level_id = 1
    for package in ACTIVE_SCAM_PACKAGES:
        for variant_index in range(len(QUESTION_BLUEPRINTS)):
            levels.append(build_question(package, variant_index, level_id))
            level_id += 1

    for output in OUTPUTS:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(levels, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {len(levels)} levels -> {output}")


if __name__ == "__main__":
    main()
