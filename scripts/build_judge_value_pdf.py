from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    BaseDocTemplate, Frame, Image, KeepTogether, PageBreak, PageTemplate,
    Paragraph, Spacer, Table, TableStyle,
)


ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "output" / "pdf"
PDF_PATH = OUT_DIR / "反诈项目价值与评测报告_评委版.pdf"
CHART_PATH = ROOT / "reports" / "judges" / "assets" / "评测改进证据图.png"
FONT_PATH = "/System/Library/Fonts/Supplemental/Arial Unicode.ttf"

NAVY = colors.HexColor("#17324D")
BLUE = colors.HexColor("#2E74B5")
TEAL = colors.HexColor("#137A72")
GREEN = colors.HexColor("#237A57")
RED = colors.HexColor("#A13D3D")
INK = colors.HexColor("#17212B")
MUTED = colors.HexColor("#596773")
LIGHT = colors.HexColor("#F2F4F7")
PALE_BLUE = colors.HexColor("#EAF2F8")
PALE_GREEN = colors.HexColor("#E9F5F1")
PALE_GOLD = colors.HexColor("#FFF5DB")
GRID = colors.HexColor("#CBD5DE")


def P(text, style):
    return Paragraph(text, style)


def make_styles():
    pdfmetrics.registerFont(TTFont("CJK", FONT_PATH))
    base = getSampleStyleSheet()
    styles = {
        "body": ParagraphStyle("body", parent=base["BodyText"], fontName="CJK", fontSize=9.8,
                               leading=15, textColor=INK, wordWrap="CJK", spaceAfter=6),
        "small": ParagraphStyle("small", parent=base["BodyText"], fontName="CJK", fontSize=7.6,
                                leading=11, textColor=MUTED, wordWrap="CJK", spaceAfter=4),
        "h1": ParagraphStyle("h1", parent=base["Heading1"], fontName="CJK", fontSize=15,
                             leading=21, textColor=BLUE, wordWrap="CJK", spaceBefore=8, spaceAfter=8),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], fontName="CJK", fontSize=11.5,
                             leading=17, textColor=BLUE, wordWrap="CJK", spaceBefore=7, spaceAfter=5),
        "title": ParagraphStyle("title", parent=base["Title"], fontName="CJK", fontSize=25,
                                leading=32, textColor=NAVY, wordWrap="CJK", alignment=TA_LEFT, spaceAfter=8),
        "subtitle": ParagraphStyle("subtitle", parent=base["BodyText"], fontName="CJK", fontSize=12,
                                   leading=18, textColor=MUTED, wordWrap="CJK", spaceAfter=12),
        "white": ParagraphStyle("white", parent=base["BodyText"], fontName="CJK", fontSize=10,
                                leading=16, textColor=colors.white, wordWrap="CJK"),
        "table": ParagraphStyle("table", parent=base["BodyText"], fontName="CJK", fontSize=7.8,
                                leading=11, textColor=INK, wordWrap="CJK"),
        "table_head": ParagraphStyle("table_head", parent=base["BodyText"], fontName="CJK", fontSize=8,
                                     leading=11, textColor=NAVY, wordWrap="CJK"),
        "bullet": ParagraphStyle("bullet", parent=base["BodyText"], fontName="CJK", fontSize=9.5,
                                 leading=15, leftIndent=14, firstLineIndent=-10, textColor=INK,
                                 wordWrap="CJK", spaceAfter=5),
    }
    return styles


def header_footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("CJK", 7.5)
    canvas.setFillColor(MUTED)
    canvas.drawString(inch, 10.46 * inch, "面向反诈教育的智能客服  |  项目价值与评测证据")
    canvas.drawRightString(7.5 * inch, 0.48 * inch, f"评委审阅版  ·  第 {doc.page} 页")
    canvas.restoreState()


def table(data, widths, styles, header=LIGHT, font_size=None):
    rows = []
    for r, row in enumerate(data):
        style = styles["table_head"] if r == 0 else styles["table"]
        if font_size:
            style = ParagraphStyle(f"t{font_size}-{r}", parent=style, fontSize=font_size, leading=font_size + 3)
        rows.append([P(str(v).replace("\n", "<br/>"), style) for v in row])
    t = Table(rows, colWidths=widths, repeatRows=1, hAlign="LEFT")
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), header),
        ("GRID", (0, 0), (-1, -1), 0.45, GRID),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    return t


def callout(text, styles, fill=PALE_BLUE, color=INK):
    st = ParagraphStyle("callout", parent=styles["body"], fontSize=9.8, leading=15, textColor=color)
    t = Table([[P(text, st)]], colWidths=[6.5 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), fill),
        ("BOX", (0, 0), (-1, -1), 0, fill),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    return t


def build():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    styles = make_styles()
    doc = BaseDocTemplate(str(PDF_PATH), pagesize=letter, leftMargin=inch, rightMargin=inch,
                          topMargin=0.82 * inch, bottomMargin=0.72 * inch,
                          title="面向反诈教育的智能客服：项目价值与评测证据报告",
                          author="项目团队", subject="评委审阅版")
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="main")
    doc.addPageTemplates([PageTemplate(id="report", frames=[frame], onPage=header_footer)])
    s = []

    s += [Spacer(1, 0.45 * inch), P("项目价值与评测证据报告", styles["h2"]),
          P("面向反诈教育的<br/>智能客服", styles["title"]),
          P("从风险识别到可执行劝阻：一套可复核、可迭代的反诈交互系统", styles["subtitle"])]
    conclusion = Table([[P("报告结论  项目已经形成“识别风险—解释证据—给出处置动作”的工程闭环；本轮困难开发集问题已闭环，但仍需独立盲测验证泛化能力。", styles["white"])]], colWidths=[6.5 * inch])
    conclusion.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), NAVY), ("LEFTPADDING", (0, 0), (-1, -1), 10),
                                    ("RIGHTPADDING", (0, 0), (-1, -1), 10), ("TOPPADDING", (0, 0), (-1, -1), 9),
                                    ("BOTTOMPADDING", (0, 0), (-1, -1), 9)]))
    s += [conclusion, Spacer(1, 12)]
    s += [table([
        ["证据项", "当前结果", "评委应如何理解"],
        ["210 条困难开发集", "Top-1 100%\n正常对照误报 0%", "证明本轮暴露的边界问题已被工程化修复，不等同于盲测成绩"],
        ["完整 HTTP 链路", "210/210 成功\n10 并发，P95 76.83 ms", "证明结果不只来自离线函数，真实接口链路可稳定返回"],
        ["400 条内部回归", "Top-1 50.75% → 98.00%", "证明优化过程可量化、可复现，低覆盖类型持续收敛"],
        ["规则可靠性", "18/18 单元测试通过\nwarning 样本 0", "证明关键组合、冲突矩阵、多轮状态与动作元数据均有回归保护"],
    ], [1.45*inch, 1.6*inch, 3.45*inch], styles, PALE_BLUE), Spacer(1, 10),
          P("报告日期：2026 年 8 月 2 日  |  评测口径：本地确定性回归 + HTTP 端到端压测", styles["small"]),
          P("证据边界：210 条样本由 105 条种子及其语义改写构成，共享案件族，明确归入开发集。", ParagraphStyle("red", parent=styles["small"], textColor=RED))]

    s += [PageBreak(), P("一、项目解决的不是“答题”，而是风险处置", styles["h1"]),
          P("多数反诈产品只回答“这像不像诈骗”。真实用户更需要的是：在口语化、信息不完整、类型相互重叠的描述中，系统能否识别当前风险，说明为什么，并给出此刻最该做的动作。本项目把这三件事放进同一条交互链路。", styles["body"]),
          callout("用户描述  →  场景路由  →  行为组合提取  →  风险类型/阶段判断  →  止损与核验动作", styles),
          P("1. 识别价值：处理真实口语和相邻类型", styles["h2"]),
          P("系统不再只依赖“刷单”“客服”“游戏交易”等类型名称，而是组合判断接触渠道、交易对象、付款方式、账号控制、验证码、远程控制、承诺收益和退款条件等行为。这样可以处理用户没有说出诈骗名称、同一句话同时含有多个风险线索的情况。", styles["body"]),
          P("2. 解释价值：让判断可审计", styles["h2"]),
          P("规则引擎输出主类型、候选类型、风险分、命中特征、风险阶段和干预动作。评委可以追溯“为什么判成这一类”，研发也能定位混淆来源，而不是只能接受一个不可解释的标签。", styles["body"]),
          P("3. 行动价值：把识别转化为止损", styles["h2"]),
          P("对正在发生的风险，回答优先停止转账、停止共享屏幕或停止提供验证码，再引导官方渠道核验、保存证据、账户保护和报警止付；对正常官方流程，则明确提示当前未见明显诈骗特征，避免制造恐慌。", styles["body"]),
          P("二、核心技术改进", styles["h1"]),
          table([
              ["此前问题", "本轮改进", "带来的实际效果"],
              ["类型关键词互相覆盖", "以多项行为组合设置优先级与冲突矩阵", "游戏交易、屏幕共享、投资等主要混淆对被拆开"],
              ["未知特征导致整条规则跳过", "补齐特征注册并校验加载结果", "210 条 HTTP 评测 warning 样本降为 0"],
              ["正常交易也被高风险提示", "增加官方渠道、合同流程、否定表达和安全支付识别", "困难集正常对照误报由 90% 降为 0%"],
              ["对话层用原文反推诈骗类型", "以风险引擎明确结果为准，未知/正常不再强行补类型", "减少“底层判正常、上层又报诈骗”的链路冲突"],
              ["风险回答缺少场景动作", "依据验证码、远程控制、培训费等目标选择干预动作", "回答从通用提醒升级为场景化处置"],
          ], [1.45*inch, 2.45*inch, 2.6*inch], styles)]

    s += [PageBreak(), P("三、量化证据：持续收敛，而非一次性“调到满分”", styles["h1"]),
          Image(str(CHART_PATH), width=6.35*inch, height=3.02*inch),
          P("图 1  两条开发回归证据线。400 条数据来自项目案例衍生；210 条数据来自人工口语化种子及语义改写。两者均用于开发回归，不作为独立盲测。", styles["small"]),
          P("1. 400 条内部回归：优化过程可量化", styles["h2"]),
          table([
              ["阶段", "Top-1", "Top-k", "风险接口 P95", "主要意义"],
              ["初始规则", "50.75%", "68.25%", "90.9 ms", "暴露两卡、AI 换脸、票务、征信等低覆盖类型"],
              ["接口优化", "72.75%", "—", "—", "建立可运行的 HTTP 评测链路"],
              ["行为规则 v2", "92.50%", "97.75%", "237.9 ms", "行为组合与类型优先级显著减少混淆"],
              ["行为规则 v3", "98.00%", "98.50%", "102.6 ms", "剩余错误收敛到游戏交易等少数边界"],
          ], [1.0*inch, .72*inch, .72*inch, 1.05*inch, 3.01*inch], styles),
          P("来源：evaluation/reports/case_derived_400_*.md。该数据与项目知识资产存在重叠，因此仅用于内部回归。", styles["small"]),
          P("2. 210 条困难开发集：针对真实边界做定向验证", styles["h2"]),
          P("这批样本集中加入游戏交易、客服/屏幕共享/验证码混淆、贷款/征信、正常交易、多轮过程以及招聘、退改签、租房、老师收费等长尾类型。优化前离线诊断为风险 Top-1 56.84%、正常对照误报 90%；优化后离线与 HTTP 链路均达到 Top-1 100%、正常对照误报 0%。", styles["body"]),
          callout("关键解释：该结果证明“已知问题已闭环”，不证明未知真实分布上的泛化准确率为 100%。", styles, PALE_GOLD)]

    s += [PageBreak(), P("四、完整 HTTP 压测结果", styles["h1"]),
          P("本轮已实际启动本地服务，并通过真实 HTTP 风险接口发送全部 210 条请求，而不是直接调用规则函数。压测使用 10 个并发工作线程，验证了路由、请求解析、风险服务、规则引擎和响应序列化的完整链路。", styles["body"]),
          table([
              ["指标", "结果", "判读"], ["总请求", "210", "覆盖困难开发集全部样本"],
              ["成功请求", "210 / 210", "接口错误 0"], ["并发度", "10", "已验证小规模并发，不代表 50/100 并发容量"],
              ["平均延迟", "55.65 ms", "包含完整本地 HTTP 往返"],
              ["P50 / P95 / 最大值", "43.82 / 76.83 / 290.30 ms", "尾延迟可控，仍需更高并发下复测"],
              ["风险 Top-1 / Top-k", "100% / 100%", "190 条风险样本"],
              ["正常对照误报", "0%", "20 条正常对照"], ["warning 样本", "0", "未知特征不再导致规则整条跳过"],
          ], [1.45*inch, 1.8*inch, 3.25*inch], styles, PALE_GREEN),
          P("来源：evaluation/reports/user_augmented_210_http_evaluation.json；生成时间 2026-08-02 18:54:25（Asia/Shanghai）。", styles["small"]),
          P("离线与 HTTP 为什么都要测", styles["h2"]),
          P("• 离线评测定位规则本身的分类与误报问题，单条 P95 为 4.11 ms。", styles["bullet"]),
          P("• HTTP 评测覆盖真实服务链路，单条 P95 为 76.83 ms，可发现接口错误、序列化问题和运行时 warning。", styles["bullet"]),
          P("• 两套结果一致，说明本轮修复没有只停留在测试函数中。", styles["bullet"]),
          P("五、代表性问题如何被修复", styles["h1"]),
          table([
              ["困难场景", "原先容易混淆", "现在使用的行为组合", "期望输出"],
              ["游戏账号被找回/装备交易", "未知、客服、中奖", "游戏资产 + 账号/装备交付 + 找回/拒付/保证金", "游戏交易诈骗 + 平台申诉/留证"],
              ["客服要求远程或验证码", "统一判为冒充客服", "客服身份 + 远程控制/屏幕共享，或验证码 + 扣款", "按实际控制手段优先分类并给对应止损动作"],
              ["网恋对象拉投资", "普通投资或熟人借钱", "情感关系 + 投资引导 + 资金投入/无法提现", "情感交友诱导投资"],
              ["官方渠道正常退款/交易", "高风险误报", "官方入口 + 原路退款/合同 + 无私下转账 + 否定风险动作", "正常/未知风险，不强行贴诈骗类型"],
          ], [1.15*inch, 1.25*inch, 2.5*inch, 1.6*inch], styles, font_size=7.3)]

    s += [PageBreak(), P("六、当前实现成熟度：哪些已经有，哪些还没有", styles["h1"]),
          table([
              ["能力", "状态", "已有证据或当前缺口"],
              ["诈骗类型体系与知识资产", "已实现", "29 类诈骗类型、171 项特征、38 条风险规则；另有预防建议、案例、法条和官方来源等资产"],
              ["行为组合规则与冲突消解", "已实现", "覆盖游戏交易、屏幕共享、验证码、投资、征信、招聘、票务等相邻类别"],
              ["正常流程误报控制", "已实现（开发集）", "20 条困难正常对照误报 0%；需要更大盲测集确认"],
              ["结构化风险卡与动作建议", "已实现", "输出类型、分数、阶段、特征、候选类型及场景化干预动作"],
              ["完整 HTTP 回归压测", "已实现（10 并发）", "210 请求零错误，P95 76.83 ms"],
              ["关键规则单元测试", "已实现", "18/18 通过，覆盖冲突矩阵、多轮状态、否定表达和干预元数据"],
              ["独立冻结盲测", "尚未完成", "当前 210/400 条均属于开发或内部回归，不可用于宣称真实泛化精度"],
              ["50/100 并发与长稳测试", "尚未完成", "当前只验证 10 并发；需补 P50/P95/P99、吞吐和资源占用"],
              ["线上 LLM 稳定性评测", "尚未完成", "需重复运行，报告均值、方差、超时和降级表现"],
              ["真实用户效果指标", "尚未完成", "需试点统计多轮完成率、劝阻动作采纳率、举报/止付成功率"],
              ["专项安全红队", "尚未完成", "需覆盖提示注入、隐私泄露、方言/ASR 错字和对抗表达"],
          ], [1.7*inch, 1.25*inch, 3.55*inch], styles, font_size=7.4),
          P("七、为什么这个项目有参赛价值", styles["h1"])]
    for i, text_value in enumerate([
        "问题真实：样本来自用户自然表达，包含犹豫、情绪、错别字、信息缺失和跨类型线索，贴近真实求助而非标准题干。",
        "方案完整：不是单一分类器，而是从路由、特征、风险阶段到干预动作的一条可运行产品链路。",
        "改进可证明：400 条回归 Top-1 从 50.75% 提升到 98.00%；本轮困难集的低准确与高误报均被量化闭环。",
        "结果可解释：确定性规则、稳定类型 ID、候选类型和命中特征便于审计，也便于在安全场景中快速修正。",
        "态度可信：项目明确承认开发集边界，并给出独立盲测、容量测试和真实效果验证计划。",
    ], 1):
        s.append(P(f"{i}. {text_value}", styles["bullet"]))

    s += [PageBreak(), P("八、下一阶段验证计划", styles["h1"]),
          table([
              ["优先级", "验证任务", "验收指标"],
              ["P0", "冻结 500–1000 条独立双人盲标测试集；按案件族切分", "报告 Top-1、Macro-F1、每类召回、混淆矩阵和正常误报率"],
              ["P0", "增加正常交易、模糊表达、多轮状态变化", "正常误报率、风险召回与分阶段动作准确率"],
              ["P1", "10/50/100 并发阶梯压测与 30 分钟长稳", "吞吐、P50/P95/P99、错误率、CPU/内存"],
              ["P1", "在线 LLM 模式重复测试及确定性降级", "均值/方差、超时率、模板回退成功率"],
              ["P1", "小规模真实用户试点", "对话完成率、关键动作采纳率、满意度与误导投诉"],
              ["P2", "安全与鲁棒性红队", "提示注入、隐私泄露、ASR 错字、方言和对抗改写通过率"],
          ], [.72*inch, 3.25*inch, 2.53*inch], styles),
          P("九、结论", styles["h1"]),
          callout("可以向评委证明的价值是：项目已经把反诈知识转化为一套可运行、可解释、可压测、可持续回归的风险处置系统，并对最突出的分类混淆和正常误报问题完成了工程闭环。", styles, PALE_GREEN),
          Spacer(1, 7),
          P("目前还不能证明的是：系统在全新真实分布上的准确率已经达到 100%，或在大规模并发和长期真实用户环境中已经稳定。把这部分作为下一阶段验证，而不是包装成现有成绩，反而使项目证据更可信。", styles["body"]),
          P("附录 A：证据索引与复现入口", styles["h1"]),
          table([
              ["证据", "项目内路径 / 命令"],
              ["210 条 HTTP 结果", "evaluation/reports/user_augmented_210_http_evaluation.json"],
              ["210 条离线结果", "evaluation/reports/user_augmented_210_rule_evaluation.json"],
              ["400 条迭代结果", "evaluation/reports/case_derived_400_evaluation.md\nevaluation/reports/case_derived_400_http_p0_behavior_v3.md"],
              ["数据边界说明", "evaluation/annotations/user_annotation_manifest.json"],
              ["方向三基准", "reports/evaluation/direction3_evaluation.md"],
              ["复跑 210 条评测", "python scripts/run_user_annotation_evaluation.py --mode offline\npython scripts/run_user_annotation_evaluation.py --mode http --base-url http://127.0.0.1:8001 --workers 10"],
              ["复跑关键单测", "python -m unittest test.test_risk_engine -v"],
          ], [1.45*inch, 5.05*inch], styles, font_size=7.0),
          P("审阅提示：所有百分比均保留两位小数；延迟为本机本地服务测量，不能直接外推到生产部署。", styles["small"])]

    doc.build(s)
    print(PDF_PATH)


if __name__ == "__main__":
    build()
