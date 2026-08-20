"""Import curated risk-video candidates from the markdown source list.

The import is intentionally conservative: candidates enter MongoDB as
``pending_review`` and are never published by this script.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

# Running this file directly places ``scripts`` on sys.path, not the project
# root where the application packages live.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.anti_fraud.taxonomy import fraud_type_id_for, standard_name_for
from app.query_process.services.risk_video_card_service import upsert_video_card


DEFAULT_SOURCE = PROJECT_ROOT / "doc" / "risk_intervention_video_download_links.md"
VIDEO_URL_RE = re.compile(r"https?://[^\s|)]+", re.IGNORECASE)
BVID_RE = re.compile(r"(BV[0-9A-Za-z]+)")
DURATION_RE = re.compile(r"([0-9]+(?:\.[0-9]+)?)\s*秒")
TYPE_PREFIX_RE = re.compile(r"^\s*\d+\s*")


def _cells(line: str) -> List[str]:
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def _is_separator(cells: Iterable[str]) -> bool:
    return bool(cells) and all(re.fullmatch(r":?-{3,}:?", cell.replace(" ", "")) for cell in cells)


def _normalise_type_name(value: str) -> str:
    return TYPE_PREFIX_RE.sub("", value or "").strip()


def _orientation(value: str) -> str:
    text = str(value or "")
    if "竖" in text:
        return "vertical"
    if "横" in text:
        return "horizontal"
    return "vertical"


def _duration_seconds(value: str) -> int:
    match = DURATION_RE.search(str(value or ""))
    if not match:
        return 0
    try:
        return max(0, int(round(float(match.group(1)))))
    except ValueError:
        return 0


def _bvid(source_url: str) -> str:
    match = BVID_RE.search(source_url or "")
    return match.group(1) if match else ""


def _local_metadata(source_url: str) -> Dict[str, str]:
    for path in (PROJECT_ROOT / "anti_fraud_video_candidates").rglob("source.txt"):
        try:
            content = path.read_text(encoding="utf-8")
        except OSError:
            continue
        if source_url not in content:
            continue
        metadata: Dict[str, str] = {"source_file": str(path.relative_to(PROJECT_ROOT))}
        for line in content.splitlines():
            if "：" not in line:
                continue
            key, value = line.split("：", 1)
            metadata[key.strip()] = value.strip()
        review_path = path.with_name("review.txt")
        if review_path.exists():
            metadata["review_file"] = str(review_path.relative_to(PROJECT_ROOT))
            try:
                metadata["local_review_status"] = review_path.read_text(encoding="utf-8").splitlines()[0].strip()
            except (OSError, IndexError):
                pass
        return metadata
    return {}


def _bilibili_metadata(bvid: str) -> Dict[str, Any]:
    if not bvid:
        return {}
    query = urllib.parse.urlencode({"bvid": bvid})
    request = urllib.request.Request(
        f"https://api.bilibili.com/x/web-interface/view?{query}",
        headers={"User-Agent": "Mozilla/5.0 anti-fraud-video-import"},
    )
    try:
        with urllib.request.urlopen(request, timeout=12) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except Exception:
        return {}
    if not isinstance(payload, dict) or payload.get("code") != 0:
        return {}
    data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
    cover_url = str(data.get("pic") or "").strip()
    if cover_url.startswith("http://"):
        cover_url = "https://" + cover_url[7:]
    owner = data.get("owner") if isinstance(data.get("owner"), dict) else {}
    return {
        "cover_url": cover_url,
        "source_api_title": str(data.get("title") or "").strip(),
        "source_api_owner": str(owner.get("name") or "").strip(),
        "source_api_duration_seconds": int(data.get("duration") or 0),
    }


def parse_candidates(source_path: Path, *, fetch_covers: bool = True) -> List[Dict[str, Any]]:
    candidates: List[Dict[str, Any]] = []
    tier = ""
    lines = source_path.read_text(encoding="utf-8").splitlines()
    for line in lines:
        if line.startswith("## "):
            heading = line[3:].strip()
            tier = "priority" if heading == "优先候选" else "backup" if heading == "可作为备选" else ""
            continue
        if tier not in {"priority", "backup"} or not line.lstrip().startswith("|"):
            continue
        cells = _cells(line)
        if len(cells) < 5 or _is_separator(cells) or cells[0] in {"类型", "对应类型"}:
            continue
        source_url_match = VIDEO_URL_RE.search(cells[3])
        if not source_url_match:
            continue
        source_url = source_url_match.group(0).rstrip("/.,")
        type_name = _normalise_type_name(cells[0])
        scam_id = fraud_type_id_for(type_name)
        if not scam_id:
            raise ValueError(f"未找到诈骗类型 taxonomy 映射: {type_name}")
        bvid = _bvid(source_url)
        if not bvid:
            raise ValueError(f"视频链接缺少 BV 号: {source_url}")
        local = _local_metadata(source_url)
        api_metadata = _bilibili_metadata(bvid) if fetch_covers else {}
        duration = _duration_seconds(cells[4]) or int(api_metadata.get("source_api_duration_seconds") or 0)
        priority = 100 if tier == "priority" else 50
        document: Dict[str, Any] = {
            "video_id": f"rv_{scam_id}_{bvid}",
            "scam_id": scam_id,
            "title": api_metadata.get("source_api_title") or cells[1].strip() or "官方反诈视频",
            "cover_url": api_metadata.get("cover_url", ""),
            "source_url": source_url,
            "platform": "bilibili",
            "publisher": api_metadata.get("source_api_owner") or local.get("官方发布机构") or cells[2],
            "official_account": api_metadata.get("source_api_owner") or local.get("官方账号名称") or cells[2],
            "duration_seconds": duration,
            "orientation": _orientation(cells[4]),
            "label": "官方反诈视频候选",
            "status": "pending_review",
            "source_check_status": "unchecked",
            "rights_status": "unknown",
            "priority": priority,
            "usage_policy": {
                "direct_link_allowed": False,
                "embed_allowed": False,
                "download_allowed": False,
            },
            "display_policy": {
                "knowledge_auto": True,
                "risk_auto": True,
            },
            "candidate_tier": tier,
            "source_bvid": bvid,
            "source_collection_note": cells[5] if len(cells) > 5 else cells[4],
            "source_markdown": str(source_path.relative_to(PROJECT_ROOT)),
            "source_review_status": "pending_local_review",
            "imported_at": datetime.now().isoformat(timespec="seconds"),
            **local,
            **api_metadata,
        }
        candidates.append(document)
    return candidates


def import_candidates(candidates: List[Dict[str, Any]], *, dry_run: bool = False) -> int:
    if dry_run:
        return len(candidates)
    for item in candidates:
        upsert_video_card(item, actor="risk_video_markdown_import")
    return len(candidates)


def main() -> int:
    parser = argparse.ArgumentParser(description="Import risk intervention video candidates")
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--no-fetch-covers", action="store_true")
    args = parser.parse_args()

    source_path = args.source.resolve()
    candidates = parse_candidates(source_path, fetch_covers=not args.no_fetch_covers)
    count = import_candidates(candidates, dry_run=args.dry_run)
    summary = {
        "source": str(source_path.relative_to(PROJECT_ROOT)),
        "count": count,
        "priority": sum(item["candidate_tier"] == "priority" for item in candidates),
        "backup": sum(item["candidate_tier"] == "backup" for item in candidates),
        "status": "pending_review",
        "cover_count": sum(bool(item.get("cover_url")) for item in candidates),
        "dry_run": args.dry_run,
        "video_ids": [item["video_id"] for item in candidates],
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
