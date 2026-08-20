#!/usr/bin/env python3
"""Evaluate the deterministic rule engine on the user-annotated development set."""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
import urllib.request
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.query_process.services.risk_service import evaluate_risk_text


DEFAULT_DATASET = ROOT / "evaluation" / "annotations" / "user_augmented_210.jsonl"
DEFAULT_JSON = ROOT / "evaluation" / "reports" / "user_augmented_210_rule_evaluation.json"
DEFAULT_MARKDOWN = ROOT / "evaluation" / "reports" / "user_augmented_210_rule_evaluation.md"
UNKNOWN_TYPES = {"", "未知", "暂未识出诈骗风险", "暂未识别诈骗风险"}


def percentile(values: List[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[round((len(ordered) - 1) * p)]


def load_rows(path: Path) -> List[Dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def post_json(url: str, payload: Dict[str, Any], timeout: int = 30) -> Dict[str, Any]:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def evaluate_row(row: Dict[str, Any], base_url: str = "") -> Dict[str, Any]:
    text = "\n".join(str(turn.get("content") or "") for turn in row.get("conversation") or [])
    started = time.perf_counter()
    error = ""
    try:
        result = post_json(f"{base_url.rstrip('/')}/risk/check", {"user_text": text}) if base_url else evaluate_risk_text(text)
    except Exception as exc:
        result = {}
        error = f"{type(exc).__name__}: {exc}"
    latency_ms = (time.perf_counter() - started) * 1000
    expected = row.get("labels", {}).get("fraud_type")
    is_control = not bool(row.get("labels", {}).get("is_personal_risk", True))
    actual = str(result.get("scam_type") or "")
    candidates = [actual, *(result.get("possible_fraud_types") or [])]
    candidates = [item for index, item in enumerate(candidates) if item and item not in candidates[:index]]
    score = int(result.get("risk_score", 0) or 0)
    return {
        "sample_id": row.get("sample_id", ""),
        "case_family_id": row.get("case_family_id", ""),
        "expected_type": expected,
        "actual_type": actual,
        "candidate_types": candidates,
        "risk_score": score,
        "risk_features": result.get("risk_features") or [],
        "warnings": result.get("warnings") or [],
        "top1_pass": not error and not is_control and actual == expected,
        "topk_pass": not error and not is_control and expected in candidates,
        "control_pass": not error and is_control and actual in UNKNOWN_TYPES and score < 30,
        "is_control": is_control,
        "latency_ms": latency_ms,
        "error": error,
        "text": text,
    }


def markdown_report(report: Dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# 用户补充 210 条规则引擎评测",
        "",
        f"- 生成时间：{report['generated_at']}",
        f"- 模式：{report['mode']}",
        "- 边界：原样本与重写样本共享案件族，本报告属于开发集回归，不是独立盲测。",
        "",
        "## 总体结果",
        "",
        "| 指标 | 结果 |",
        "|---|---:|",
        f"| 风险样本 | {summary['risk_count']} |",
        f"| 风险类型 Top-1 | {summary['top1_accuracy']:.2%} |",
        f"| 风险类型 Top-k | {summary['topk_recall']:.2%} |",
        f"| 正常对照样本 | {summary['control_count']} |",
        f"| 正常对照误报率 | {summary['control_false_positive_rate']:.2%} |",
        f"| 请求错误 | {summary['errors']} |",
        f"| 规则 warning 样本 | {summary['warning_samples']} |",
        f"| 单条 P95 | {summary['latency_ms']['p95']:.2f} ms |",
        "",
        "## 分类型结果",
        "",
        "| 类型 | 数量 | Top-1 | Top-k |",
        "|---|---:|---:|---:|",
    ]
    for fraud_type, metrics in report["per_type"].items():
        lines.append(
            f"| {fraud_type} | {metrics['count']} | {metrics['top1_accuracy']:.2%} | {metrics['topk_recall']:.2%} |"
        )
    lines.extend(["", "## 失败样本", ""])
    failures = report["failures"]
    if not failures:
        lines.append("当前开发集无失败样本。")
    else:
        for row in failures:
            lines.append(
                f"- `{row['sample_id']}`：期望 `{row['expected_type'] or '正常对照'}`，实际 `{row['actual_type']}`，风险分 {row['risk_score']}。"
            )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--json-output", type=Path, default=DEFAULT_JSON)
    parser.add_argument("--markdown-output", type=Path, default=DEFAULT_MARKDOWN)
    parser.add_argument("--base-url", default="", help="Set to evaluate the running /risk/check HTTP endpoint")
    parser.add_argument("--workers", type=int, default=10)
    args = parser.parse_args()

    source_rows = load_rows(args.dataset)
    if args.base_url:
        evaluated = []
        with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
            futures = [pool.submit(evaluate_row, row, args.base_url) for row in source_rows]
            for future in as_completed(futures):
                evaluated.append(future.result())
        evaluated.sort(key=lambda row: row["sample_id"])
    else:
        evaluated = [evaluate_row(row) for row in source_rows]
    risk_rows = [row for row in evaluated if not row["is_control"]]
    control_rows = [row for row in evaluated if row["is_control"]]
    latencies = [row["latency_ms"] for row in evaluated]

    grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for row in risk_rows:
        grouped[str(row["expected_type"] or "未知")].append(row)
    per_type = {
        fraud_type: {
            "count": len(rows),
            "top1_accuracy": sum(row["top1_pass"] for row in rows) / len(rows),
            "topk_recall": sum(row["topk_pass"] for row in rows) / len(rows),
        }
        for fraud_type, rows in sorted(grouped.items())
    }

    failures = [
        row
        for row in evaluated
        if (row["is_control"] and not row["control_pass"])
        or (not row["is_control"] and not row["top1_pass"])
    ]
    report = {
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "dataset": str(args.dataset),
        "mode": "http_development_regression" if args.base_url else "offline_deterministic_development_regression",
        "summary": {
            "total": len(evaluated),
            "errors": sum(bool(row["error"]) for row in evaluated),
            "warning_samples": sum(bool(row["warnings"]) for row in evaluated),
            "risk_count": len(risk_rows),
            "control_count": len(control_rows),
            "top1_accuracy": sum(row["top1_pass"] for row in risk_rows) / len(risk_rows) if risk_rows else 0.0,
            "topk_recall": sum(row["topk_pass"] for row in risk_rows) / len(risk_rows) if risk_rows else 0.0,
            "control_false_positive_rate": (
                sum(not row["control_pass"] for row in control_rows) / len(control_rows) if control_rows else 0.0
            ),
            "latency_ms": {
                "mean": statistics.mean(latencies) if latencies else 0.0,
                "p50": percentile(latencies, 0.50),
                "p95": percentile(latencies, 0.95),
                "max": max(latencies, default=0.0),
            },
        },
        "per_type": per_type,
        "confusions": [
            {"expected": expected, "actual": actual, "count": count}
            for (expected, actual), count in Counter(
                (row["expected_type"] or "正常对照", row["actual_type"] or "未知") for row in failures
            ).most_common()
        ],
        "failures": failures,
    }

    args.json_output.parent.mkdir(parents=True, exist_ok=True)
    args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
    args.json_output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    args.markdown_output.write_text(markdown_report(report), encoding="utf-8")
    print(json.dumps({"summary": report["summary"], "report": str(args.markdown_output)}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
