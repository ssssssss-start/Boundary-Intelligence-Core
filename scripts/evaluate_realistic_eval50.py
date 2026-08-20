#!/usr/bin/env python3
"""Validate and evaluate the realistic 50-case anti-fraud development set."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import statistics
import sys
import time
import urllib.request
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.query_process.services.risk_service import evaluate_risk_text


DEFAULT_DATASET = ROOT / "evaluation" / "realistic_v1" / "realistic_eval_50.jsonl"
UNKNOWN_TYPES = {"", "未知", "暂未识出诈骗风险", "暂未识别诈骗风险"}
EXPECTED_DIMENSIONS = {
    "明确诈骗": 8,
    "尚未转账": 8,
    "正在操作或已付款": 8,
    "正常对照": 8,
    "信息不足": 8,
    "混合困难": 8,
    "跨轮状态变化": 1,
    "语音转写混合": 1,
}
RISK_LEVEL_BANDS = {
    "无明显风险": (0, 29),
    "信息不足": (0, 29),
    "低风险提醒": (1, 29),
    "中风险警示": (30, 79),
    "高风险立即劝阻": (80, 100),
}


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def conversation_text(row: dict[str, Any]) -> str:
    return "\n".join(
        f"{turn.get('role', 'user')}：{turn.get('content', '')}" for turn in row.get("conversation") or []
    )


def normalized_story(text: str) -> str:
    text = text.lower()
    text = re.sub(r"https?://\S+", "链接", text)
    text = re.sub(r"\d+(?:\.\d+)?(?:万|千|百|块|元|w|k)?", "金额", text)
    text = re.sub(r"[\W_]+", "", text, flags=re.UNICODE)
    return text


def char_ngrams(text: str, n: int = 3) -> set[str]:
    return {text[index : index + n] for index in range(max(0, len(text) - n + 1))}


def similarity(left: str, right: str) -> float:
    left_norm, right_norm = normalized_story(left), normalized_story(right)
    if not left_norm or not right_norm:
        return 0.0
    left_grams, right_grams = char_ngrams(left_norm), char_ngrams(right_norm)
    union = left_grams | right_grams
    jaccard = len(left_grams & right_grams) / len(union) if union else 0.0
    sequence = SequenceMatcher(None, left_norm, right_norm).ratio()
    return max(jaccard, sequence)


def validate(rows: list[dict[str, Any]]) -> dict[str, Any]:
    required = {
        "sample_id", "case_family_id", "conversation", "user_intent", "fraud_type", "risk_level",
        "current_stage", "risk_evidence", "confusable_types", "expected_disposition",
        "follow_up_questions", "reference_response", "difficulty",
        "用户对话", "用户意图", "诈骗类型", "风险等级", "当前阶段", "关键风险证据",
        "容易混淆的类别", "标准处理结果", "建议追问", "标准劝阻回复", "难度等级",
    }
    bilingual_fields = {
        "conversation": "用户对话",
        "user_intent": "用户意图",
        "fraud_type": "诈骗类型",
        "risk_level": "风险等级",
        "current_stage": "当前阶段",
        "risk_evidence": "关键风险证据",
        "confusable_types": "容易混淆的类别",
        "expected_disposition": "标准处理结果",
        "follow_up_questions": "建议追问",
        "reference_response": "标准劝阻回复",
        "difficulty": "难度等级",
    }
    errors: list[str] = []
    for row in rows:
        missing = sorted(required - set(row))
        if missing:
            errors.append(f"{row.get('sample_id', '?')}: 缺少字段 {','.join(missing)}")
        for machine_field, review_field in bilingual_fields.items():
            if machine_field in row and review_field in row and row[machine_field] != row[review_field]:
                errors.append(f"{row.get('sample_id', '?')}: {machine_field} 与 {review_field} 不一致")
        if row.get("risk_level") == "信息不足":
            if row.get("fraud_type") is not None:
                errors.append(f"{row.get('sample_id')}: 信息不足样本 fraud_type 必须为 null")
            if not row.get("follow_up_questions"):
                errors.append(f"{row.get('sample_id')}: 信息不足样本缺少追问")
    sample_ids = [row.get("sample_id") for row in rows]
    family_ids = [row.get("case_family_id") for row in rows]
    story_hashes = [hashlib.sha256(normalized_story(conversation_text(row)).encode()).hexdigest() for row in rows]
    dimensions = Counter(row.get("test_dimension") for row in rows)
    if len(rows) != 50:
        errors.append(f"样本数应为 50，实际 {len(rows)}")
    if len(set(sample_ids)) != len(rows):
        errors.append("sample_id 不唯一")
    if len(set(family_ids)) != len(rows):
        errors.append("case_family_id 不唯一")
    if len(set(story_hashes)) != len(rows):
        errors.append("存在规范化文本重复")
    if dict(dimensions) != EXPECTED_DIMENSIONS:
        errors.append(f"测试维度分布不符合设计：{dict(dimensions)}")
    return {
        "passed": not errors,
        "errors": errors,
        "sample_count": len(rows),
        "case_family_count": len(set(family_ids)),
        "dimension_distribution": dict(dimensions),
    }


def prior_rows() -> list[dict[str, Any]]:
    paths = [
        ROOT / "evaluation" / "annotations" / "user_augmented_210.jsonl",
        ROOT / "evaluation" / "anonymized" / "case_derived_400.jsonl",
        ROOT / "evaluation" / "anonymized" / "pilot_100.jsonl",
    ]
    rows: list[dict[str, Any]] = []
    for path in paths:
        if path.exists():
            for row in load_jsonl(path):
                row = dict(row)
                row["_source_file"] = str(path.relative_to(ROOT))
                rows.append(row)
    return rows


def novelty_check(rows: list[dict[str, Any]], threshold: float = 0.72) -> dict[str, Any]:
    old = prior_rows()
    flagged: list[dict[str, Any]] = []
    maximum = 0.0
    for row in rows:
        new_text = conversation_text(row)
        best_score, best_row = 0.0, None
        for candidate in old:
            score = similarity(new_text, conversation_text(candidate))
            if score > best_score:
                best_score, best_row = score, candidate
        maximum = max(maximum, best_score)
        if best_score >= threshold and best_row is not None:
            flagged.append({
                "sample_id": row["sample_id"],
                "score": round(best_score, 4),
                "prior_sample_id": best_row.get("sample_id", ""),
                "source_file": best_row.get("_source_file", ""),
                "new_text": new_text,
                "prior_text": conversation_text(best_row),
            })
    return {
        "prior_sample_count": len(old),
        "threshold": threshold,
        "maximum_similarity": round(maximum, 4),
        "flagged_count": len(flagged),
        "flagged_pairs": flagged,
    }


def post_json(url: str, payload: dict[str, Any]) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def canonical_actual(result: dict[str, Any]) -> str:
    return str(result.get("primary_type") or result.get("fraud_type") or result.get("scam_type") or "")


def evaluate_row(row: dict[str, Any], base_url: str) -> dict[str, Any]:
    text = conversation_text(row)
    started = time.perf_counter()
    try:
        result = post_json(f"{base_url.rstrip('/')}/risk/check", {"user_text": text}) if base_url else evaluate_risk_text(text)
        error = ""
    except Exception as exc:
        result, error = {}, f"{type(exc).__name__}: {exc}"
    score = int(result.get("risk_score", 0) or 0)
    actual = canonical_actual(result)
    candidates = [actual, *(result.get("candidate_types") or []), *(result.get("possible_fraud_types") or [])]
    candidates = list(dict.fromkeys(item for item in candidates if item))
    expected = row.get("fraud_type")
    dimension = row.get("test_dimension")
    is_normal = dimension == "正常对照"
    is_clarification = dimension == "信息不足"
    band = RISK_LEVEL_BANDS[row["risk_level"]]
    return {
        "sample_id": row["sample_id"],
        "case_family_id": row["case_family_id"],
        "focus_category": row.get("focus_category"),
        "test_dimension": dimension,
        "expected_type": expected,
        "expected_risk_level": row["risk_level"],
        "actual_type": actual,
        "candidate_types": candidates,
        "risk_score": score,
        "actual_risk_level": result.get("risk_level", ""),
        "risk_features": result.get("risk_features") or [],
        "matched_rules": result.get("matched_rules") or [],
        "warnings": result.get("warnings") or [],
        "type_top1_pass": bool(expected) and actual == expected,
        "type_topk_pass": bool(expected) and expected in candidates,
        "risk_detection_pass": bool(expected) and score >= 30,
        "normal_pass": is_normal and score < 30,
        "normal_type_clean": is_normal and actual in UNKNOWN_TYPES,
        "clarification_pass": is_clarification and score < 30 and actual in UNKNOWN_TYPES,
        "risk_level_pass": band[0] <= score <= band[1],
        "latency_ms": (time.perf_counter() - started) * 1000,
        "error": error,
        "text": text,
    }


def rate(rows: list[dict[str, Any]], key: str) -> float:
    return sum(bool(row[key]) for row in rows) / len(rows) if rows else 0.0


def summarize(evaluated: list[dict[str, Any]]) -> dict[str, Any]:
    risk = [row for row in evaluated if row["expected_type"]]
    normal = [row for row in evaluated if row["test_dimension"] == "正常对照"]
    clarification = [row for row in evaluated if row["test_dimension"] == "信息不足"]
    latency = [row["latency_ms"] for row in evaluated]
    per_type: dict[str, Any] = {}
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in risk:
        grouped[row["expected_type"]].append(row)
    for fraud_type, items in sorted(grouped.items()):
        per_type[fraud_type] = {
            "count": len(items),
            "top1_accuracy": rate(items, "type_top1_pass"),
            "risk_recall": rate(items, "risk_detection_pass"),
        }
    return {
        "total": len(evaluated),
        "risk_count": len(risk),
        "normal_count": len(normal),
        "clarification_count": len(clarification),
        "type_top1_accuracy": rate(risk, "type_top1_pass"),
        "type_topk_recall": rate(risk, "type_topk_pass"),
        "risk_detection_recall": rate(risk, "risk_detection_pass"),
        "normal_false_positive_rate": 1.0 - rate(normal, "normal_pass"),
        "normal_forced_type_rate": 1.0 - rate(normal, "normal_type_clean"),
        "clarification_forced_decision_rate": 1.0 - rate(clarification, "clarification_pass"),
        "risk_level_accuracy": rate(evaluated, "risk_level_pass"),
        "warning_samples": sum(bool(row["warnings"]) for row in evaluated),
        "errors": sum(bool(row["error"]) for row in evaluated),
        "latency_ms": {
            "mean": statistics.mean(latency) if latency else 0.0,
            "p95": sorted(latency)[round((len(latency) - 1) * 0.95)] if latency else 0.0,
            "max": max(latency, default=0.0),
        },
        "per_type": per_type,
    }


def markdown(report: dict[str, Any]) -> str:
    s = report["summary"]
    lines = [
        f"# 真实场景 50 条评测：{report['label']}", "",
        f"- 模式：{report['mode']}（并发数 {report['workers']}）",
        f"- 结构校验：{'通过' if report['validation']['passed'] else '失败'}",
        f"- 与既有 {report['novelty']['prior_sample_count']} 条样本近似度阈值告警：{report['novelty']['flagged_count']} 对",
        "- 口径：信息不足样本要求风险分低于 30 且不强判类型；正常样本误报按风险分不低于 30 计算。", "",
        "## 核心指标", "", "| 指标 | 结果 |", "|---|---:|",
        f"| 风险类型 Top-1 | {s['type_top1_accuracy']:.2%} |",
        f"| 风险类型 Top-k | {s['type_topk_recall']:.2%} |",
        f"| 风险检出召回 | {s['risk_detection_recall']:.2%} |",
        f"| 正常对照误报率 | {s['normal_false_positive_rate']:.2%} |",
        f"| 正常对照类型强判率 | {s['normal_forced_type_rate']:.2%} |",
        f"| 信息不足强判率 | {s['clarification_forced_decision_rate']:.2%} |",
        f"| 风险等级区间准确率 | {s['risk_level_accuracy']:.2%} |",
        f"| warning 样本 | {s['warning_samples']} |", "",
        "## 分类型", "", "| 诈骗类型 | 数量 | Top-1 | 风险召回 |", "|---|---:|---:|---:|",
    ]
    for fraud_type, item in s["per_type"].items():
        lines.append(f"| {fraud_type} | {item['count']} | {item['top1_accuracy']:.2%} | {item['risk_recall']:.2%} |")
    lines.extend(["", "## 失败明细", ""])
    for row in report["failures"]:
        lines.append(
            f"- `{row['sample_id']}`（{row['test_dimension']}）：期望 `{row['expected_type'] or row['expected_risk_level']}`，"
            f"实际 `{row['actual_type'] or '未知'}` / {row['risk_score']} 分。"
        )
    if not report["failures"]:
        lines.append("无失败样本。")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--base-url", default="")
    parser.add_argument("--label", default="baseline")
    parser.add_argument("--workers", type=int, default=1, help="Concurrent HTTP workers; offline mode stays sequential")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "evaluation" / "realistic_v1" / "reports")
    args = parser.parse_args()

    rows = load_jsonl(args.dataset)
    validation = validate(rows)
    novelty = novelty_check(rows)
    if args.base_url and args.workers > 1:
        evaluated = []
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = [pool.submit(evaluate_row, row, args.base_url) for row in rows]
            for future in as_completed(futures):
                evaluated.append(future.result())
        evaluated.sort(key=lambda row: row["sample_id"])
    else:
        evaluated = [evaluate_row(row, args.base_url) for row in rows]
    summary = summarize(evaluated)
    failures = [
        row for row in evaluated
        if row["error"]
        or (row["expected_type"] and (not row["type_top1_pass"] or not row["risk_detection_pass"]))
        or (row["test_dimension"] == "正常对照" and not row["normal_pass"])
        or (row["test_dimension"] == "信息不足" and not row["clarification_pass"])
        or not row["risk_level_pass"]
    ]
    report = {
        "label": args.label,
        "mode": "http" if args.base_url else "offline",
        "workers": args.workers if args.base_url else 1,
        "dataset": str(args.dataset),
        "validation": validation,
        "novelty": novelty,
        "summary": summary,
        "confusions": [
            {"expected": expected, "actual": actual, "count": count}
            for (expected, actual), count in Counter(
                (row["expected_type"] or row["expected_risk_level"], row["actual_type"] or "未知")
                for row in failures
            ).most_common()
        ],
        "failures": failures,
        "results": evaluated,
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    json_path = args.output_dir / f"{args.label}.json"
    md_path = args.output_dir / f"{args.label}.md"
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    md_path.write_text(markdown(report), encoding="utf-8")
    print(json.dumps({"validation": validation, "novelty": novelty, "summary": summary, "report": str(md_path)}, ensure_ascii=False, indent=2))
    return 0 if validation["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
