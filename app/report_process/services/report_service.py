import uuid
from datetime import datetime
from typing import Any, Dict

from app.clients.mongo_business_utils import count_report_tickets_for_day, create_report_ticket, write_audit_log
from app.query_process.services.risk_service import check_url_content, evaluate_risk_text, risk_level_from_score
from app.report_process.services.desensitize_service import desensitize_text


EVIDENCE_CHECKLIST = [
    "聊天记录截图或导出文件",
    "对方账号、昵称、手机号、收款账户",
    "链接、二维码、App 名称或安装包来源",
    "转账订单号、交易流水、付款凭证",
    "对方要求继续转账、补单、缴费的关键话术",
]


def _next_report_id() -> str:
    day_text = datetime.now().strftime("%Y%m%d")
    try:
        seq = count_report_tickets_for_day(day_text) + 1
        return f"FS-{day_text}-{seq:05d}"
    except Exception:
        return f"FS-{day_text}-{uuid.uuid4().hex[:6].upper()}"


def create_report(request_data: Dict[str, Any]) -> Dict[str, Any]:
    risk_input = " ".join(
        [
            str(request_data.get("content", "")),
            str(request_data.get("note", "")),
            str(request_data.get("platform", "")),
            "已发生转账" if request_data.get("has_paid") else "",
        ]
    )
    risk = evaluate_risk_text(risk_input)
    url_risk = check_url_content(str(request_data.get("content", "")))
    score = max(int(risk["risk_score"]), int(url_risk["risk_score"]))
    risk_level = risk_level_from_score(score)
    advice = risk["advice"] if int(risk["risk_score"]) >= int(url_risk["risk_score"]) else url_risk["advice"]

    report = {
        "report_id": _next_report_id(),
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "report_type": request_data.get("report_type", ""),
        "platform": request_data.get("platform", ""),
        "content": desensitize_text(request_data.get("content", "")),
        "has_paid": bool(request_data.get("has_paid", False)),
        "amount": desensitize_text(request_data.get("amount", "")),
        "contact": desensitize_text(request_data.get("contact", "")),
        "note": desensitize_text(request_data.get("note", "")),
        "risk_score": score,
        "risk_level": risk_level,
        "scam_type": risk["scam_type"],
        "matched_rules": risk["matched_rules"],
        "url_rules": url_risk["risk_rules"],
        "advice": advice,
        "evidence_checklist": EVIDENCE_CHECKLIST,
    }

    create_report_ticket(report)
    write_audit_log(
        "report_create",
        {
            "report_id": report["report_id"],
            "report_type": report["report_type"],
            "risk_level": report["risk_level"],
            "scam_type": report["scam_type"],
        },
    )
    return report
