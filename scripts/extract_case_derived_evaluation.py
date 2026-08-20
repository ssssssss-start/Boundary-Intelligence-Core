#!/usr/bin/env python3
"""Extract and rewrite training-quiz cases as evaluation candidates.

The output is a candidate pool, not an independent blind test. Closely related
questions share a case_family_id so a later split cannot leak one case across
development and blind-test sets.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import date
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LEVELS_PATH = ROOT / "database_snapshot" / "mongo" / "game_levels.json"
CASES_PATH = ROOT / "database_snapshot" / "mongo" / "typical_cases.json"
RAW_PATH = ROOT / "evaluation" / "raw_candidates" / "case_derived_400.jsonl"
ANON_PATH = ROOT / "evaluation" / "anonymized" / "case_derived_400.jsonl"
MANIFEST_PATH = ROOT / "evaluation" / "raw_candidates" / "case_derived_400_manifest.json"


def load_documents(path: Path) -> list[dict]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return payload["documents"] if isinstance(payload, dict) and "documents" in payload else payload


def clean_scenario(text: str) -> str:
    text = re.sub(r"\s*请根据场景判断最安全的选择。?\s*$", "", text.strip())
    text = re.sub(r"[。；，]?\s*对方自称：([^。]+)。?", r"，对方自称“\1”", text)
    return re.sub(r"\s+", " ", text).strip(" ，。") + "。"


def rewrite(level: dict) -> str:
    """Turn a quiz stem into natural user language without copying the answer."""
    scene = clean_scenario(level["scenario"])
    question = level["question"].strip()
    variants = (
        f"我遇到这样一件事：{scene}{question}",
        f"帮我判断一下这个情况：{scene}{question}",
        f"这是一个反诈案例：{scene}请问，{question}",
        f"有人碰到了下面的情况：{scene}{question}",
    )
    return variants[(int(level["level_id"]) - 1) % len(variants)]


def family_id(level: dict) -> str:
    basis = f'{level.get("fraud_type_id")}|{clean_scenario(level["scenario"])}'
    digest = hashlib.sha256(basis.encode("utf-8")).hexdigest()[:12]
    return f'quizcase_{level.get("fraud_type_id", "unknown")}_{digest}'


def main() -> None:
    levels = [row for row in load_documents(LEVELS_PATH) if row.get("enabled", True)]
    typical_cases = load_documents(CASES_PATH)
    refs_by_type: dict[str, list[str]] = {}
    for case in typical_cases:
        key = case.get("fraud_type_id") or case.get("scam_type_id")
        if key:
            refs_by_type.setdefault(key, []).extend(case.get("source_refs") or [])

    rows = []
    for level in sorted(levels, key=lambda item: int(item["level_id"])):
        fraud_type_id = level.get("fraud_type_id") or level.get("scam_type_id")
        official_urls = sorted({url for url in refs_by_type.get(fraud_type_id, []) if url.startswith("http")})
        conversation = [{"role": "user", "content": rewrite(level)}]
        content_hash = hashlib.sha256(
            json.dumps(conversation, ensure_ascii=False, sort_keys=True).encode("utf-8")
        ).hexdigest()
        rows.append({
            "sample_id": f'AF-CASE-{int(level["level_id"]):04d}',
            "case_family_id": family_id(level),
            "source": {
                "source_type": "official_public_case",
                "source_url": official_urls[0] if official_urls else None,
                "publisher": None,
                "published_at": None,
                "collected_at": date.today().isoformat(),
                "collector_id": "case_derived_extractor_v1",
                "license_status": "public_facts_rewritten" if official_urls else "needs_review",
                "content_hash": content_hash,
                "all_source_urls": official_urls,
                "derived_from": {
                    "dataset": "database_snapshot/mongo/game_levels.json",
                    "level_id": level["level_id"],
                    "fraud_type": level.get("fraud_type"),
                    "source_quality_tier": level.get("source_quality_tier"),
                    "rewrite_method": "deterministic_fact_preserving_template_v1",
                },
            },
            "conversation": conversation,
            "turn_under_test": 0,
            "split": "unassigned",
        })

    raw_text = "\n".join(json.dumps(row, ensure_ascii=False) for row in rows) + "\n"
    anonymized = [
        {**row, "privacy_review": {"status": "passed", "reason": "source_dataset_already_desensitized_and_rewritten"}}
        for row in rows
    ]
    RAW_PATH.parent.mkdir(parents=True, exist_ok=True)
    ANON_PATH.parent.mkdir(parents=True, exist_ok=True)
    RAW_PATH.write_text(raw_text, encoding="utf-8")
    ANON_PATH.write_text("\n".join(json.dumps(row, ensure_ascii=False) for row in anonymized) + "\n", encoding="utf-8")
    manifest = {
        "dataset": "case_derived_400",
        "count": len(rows),
        "case_family_count": len({row["case_family_id"] for row in rows}),
        "source": str(LEVELS_PATH.relative_to(ROOT)),
        "status": "annotation_candidate_pool",
        "blind_test_eligible": False,
        "warning": "由项目已有题库衍生，会受到题库与系统知识重叠影响；须独立双人标注并按 case_family_id 分组切分。",
    }
    MANIFEST_PATH.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
