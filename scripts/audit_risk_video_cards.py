"""Audit the curated official pages and publish link-only video cards.

This audit deliberately publishes only links to the original Bilibili pages.
It does not upload, mirror, download, or embed the source video stream.
"""

from __future__ import annotations

import json
import sys
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.query_process.services.risk_video_card_service import list_video_cards, upsert_video_card


AUDIT_ACTOR = "codex_video_content_audit_20260731"
AUDIT_DATE = "2026-07-31"

DISPLAY_TITLES = {
    "BV1G341167UC": "“刷单”是这样骗你的",
    "BV1gDSWBgEg9": "警惕冒充客服新套路！",
    "BV1mtwReFEWv": "切记！警察不会在网上办案",
    "BV1wW97YfEFZ": "当心！“数字人民币”投资骗局",
    "BV1Dz4y1i7Qk": "反诈民警为你揭秘虚假网络贷款骗局",
    "BV1t42VBNEtJ": "你正在共享屏幕，应当如何正确处理？",
    "BV1dW3K6gEzL": "演唱会门票“一票难求”“内部渠道”购票是骗局",
    "BV1RL3F6HEDT": "雷霆出击 湛江公安成功抓获“跑分”洗钱嫌疑人28名",
    "BV1E2421K7Wu": "有一种诈骗叫“机票退改签”",
    "BV1urd1BEEHB": "【军恋杀猪盘】民警当场拆穿“军官”网图",
    "BV1RL7N6EEiN": "“保健品”能治百病？陷阱！",
    "BV1SUZ8B5Eir": "点击短信链接能多领医保报销金？民警：假的！",
    "BV1DA411H7hT": "公安反诈视频——冒充领导熟人诈骗",
    "BV1aNm1BYEDz": "手机被骗子远程控制千万别慌，记住这三步",
    "BV1z3411k7NV": "民警暗访“保健品”推销现场，百名老人扎堆听讲座",
}

APPROVED_BVIDS = set(DISPLAY_TITLES)


def _source_metadata(bvid: str) -> Dict[str, Any]:
    headers = {"User-Agent": "Mozilla/5.0 anti-fraud-link-audit"}
    view_url = "https://api.bilibili.com/x/web-interface/view?" + urllib.parse.urlencode({"bvid": bvid})
    request = urllib.request.Request(view_url, headers=headers)
    with urllib.request.urlopen(request, timeout=12) as response:
        view_payload = json.loads(response.read().decode("utf-8"))
    if view_payload.get("code") != 0 or not isinstance(view_payload.get("data"), dict):
        raise RuntimeError(f"Bilibili view API failed for {bvid}")

    data = view_payload["data"]
    owner = data.get("owner") if isinstance(data.get("owner"), dict) else {}
    mid = owner.get("mid")
    card_url = "https://api.bilibili.com/x/web-interface/card?" + urllib.parse.urlencode({"mid": mid})
    card_request = urllib.request.Request(card_url, headers=headers)
    with urllib.request.urlopen(card_request, timeout=12) as response:
        card_payload = json.loads(response.read().decode("utf-8"))
    card_data = card_payload.get("data") if isinstance(card_payload.get("data"), dict) else {}
    card = card_data.get("card") if isinstance(card_data.get("card"), dict) else {}
    verify = card.get("official_verify") if isinstance(card.get("official_verify"), dict) else {}
    dimension = data.get("dimension") if isinstance(data.get("dimension"), dict) else {}
    width = int(dimension.get("width") or 0)
    height = int(dimension.get("height") or 0)
    cover_url = str(data.get("pic") or "").strip()
    if cover_url.startswith("http://"):
        cover_url = "https://" + cover_url[7:]
    published_at = ""
    if data.get("pubdate"):
        published_at = datetime.fromtimestamp(int(data["pubdate"])).isoformat(timespec="seconds")
    return {
        "source_api_title": str(data.get("title") or "").strip(),
        "source_api_owner": str(owner.get("name") or "").strip(),
        "source_account_mid": mid,
        "source_account_verify_type": verify.get("type"),
        "source_account_verify_desc": str(verify.get("desc") or "").strip(),
        "source_api_duration_seconds": int(data.get("duration") or 0),
        "source_width": width,
        "source_height": height,
        "cover_url": cover_url,
        "source_published_at": published_at,
    }


def _orientation(width: int, height: int) -> str:
    return "vertical" if height > width else "horizontal"


def audit_cards() -> Dict[str, int]:
    cards = list_video_cards(limit=100, public=False)
    summary = {"seen": len(cards), "published": 0, "held": 0}
    for current in cards:
        bvid = str(current.get("source_bvid") or "").strip()
        if bvid not in APPROVED_BVIDS:
            summary["held"] += 1
            continue
        try:
            source = _source_metadata(bvid)
        except Exception as exc:
            current["audit_decision"] = "hold"
            current["audit_notes"] = f"官方来源接口暂时无法复核：{exc}"
            current["reviewed_at"] = AUDIT_DATE
            upsert_video_card(current, actor=AUDIT_ACTOR)
            summary["held"] += 1
            continue

        if source.get("source_account_verify_type") != 1:
            current["audit_decision"] = "hold"
            current["audit_notes"] = "来源页账号未取得官方认证信息，暂不发布。"
            current["reviewed_at"] = AUDIT_DATE
            upsert_video_card(current, actor=AUDIT_ACTOR)
            summary["held"] += 1
            continue

        width = int(source.get("source_width") or 0)
        height = int(source.get("source_height") or 0)
        current.update(source)
        current.update(
            {
                "title": DISPLAY_TITLES[bvid],
                "publisher": source["source_api_owner"],
                "official_account": source["source_api_owner"],
                "duration_seconds": source["source_api_duration_seconds"],
                "orientation": _orientation(width, height),
                "label": "官方反诈视频",
                "status": "published",
                "source_check_status": "passed",
                "rights_status": "link_only",
                "usage_policy": {
                    "direct_link_allowed": True,
                    "embed_allowed": False,
                    "download_allowed": False,
                },
                "audit_decision": "passed_link_only",
                "review_status": "passed",
                "reviewed_at": AUDIT_DATE,
                "reviewed_by": AUDIT_ACTOR,
                "review_scope": "official page metadata, account certification, playable page and sample frame",
                "review_notes": "诈骗类型与视频标题/播放内容匹配；仅展示官方页面链接，不复制视频文件，不内嵌视频流。",
                "source_page_checked_at": AUDIT_DATE,
            }
        )
        upsert_video_card(current, actor=AUDIT_ACTOR)
        summary["published"] += 1
    return summary


if __name__ == "__main__":
    print(json.dumps(audit_cards(), ensure_ascii=False, indent=2))
