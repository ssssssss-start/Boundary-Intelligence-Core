#!/usr/bin/env python3
"""Run the reproducible, no-network Direction 3 benchmark and write reports."""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.modules.knowledge_assistant.service import _local_unified_route, classify_education_intent
from app.query_process.services.risk_service import evaluate_risk_text


DEFAULT_DATASET = ROOT / "evaluation" / "direction3_benchmark.json"
DEFAULT_OUTPUT = ROOT / "reports" / "evaluation"


def percentile(values: List[float], percent: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * percent)))
    return ordered[index]


def classification_metrics(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    labels = sorted({row["expected"] for row in rows} | {row["actual"] for row in rows})
    confusion = {label: {candidate: 0 for candidate in labels} for label in labels}
    per_label: Dict[str, Dict[str, float]] = {}
    for row in rows:
        confusion[row["expected"]][row["actual"]] += 1
    for label in labels:
        tp = sum(1 for row in rows if row["expected"] == label and row["actual"] == label)
        fp = sum(1 for row in rows if row["expected"] != label and row["actual"] == label)
        fn = sum(1 for row in rows if row["expected"] == label and row["actual"] != label)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        per_label[label] = {
            "precision": precision,
            "recall": recall,
            "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
            "support": sum(1 for row in rows if row["expected"] == label),
        }
    correct = sum(row["expected"] == row["actual"] for row in rows)
    return {
        "total": len(rows),
        "correct": correct,
        "accuracy": correct / len(rows) if rows else 0.0,
        "macro_f1": statistics.mean(item["f1"] for item in per_label.values()) if per_label else 0.0,
        "per_label": per_label,
        "confusion_matrix": confusion,
    }


def run_cases(
    cases: Iterable[Dict[str, Any]],
    classifier: Callable[[str], str],
) -> tuple[List[Dict[str, Any]], Dict[str, float]]:
    rows: List[Dict[str, Any]] = []
    latencies: List[float] = []
    for case in cases:
        started = time.perf_counter()
        try:
            actual = classifier(case["text"])
            error = ""
        except Exception as exc:  # benchmark must report failures instead of aborting
            actual = "__error__"
            error = f"{type(exc).__name__}: {exc}"
        elapsed_ms = (time.perf_counter() - started) * 1000
        latencies.append(elapsed_ms)
        rows.append({**case, "actual": actual, "passed": actual == case["expected"], "latency_ms": elapsed_ms, "error": error})
    timing = {
        "mean_ms": statistics.mean(latencies) if latencies else 0.0,
        "p50_ms": percentile(latencies, 0.50),
        "p95_ms": percentile(latencies, 0.95),
        "max_ms": max(latencies, default=0.0),
    }
    return rows, timing


def knowledge_inventory() -> Dict[str, int]:
    inventory: Dict[str, int] = {}
    for path in sorted((ROOT / "data" / "knowledge").glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            inventory[path.name] = len(data)
        except Exception:
            inventory[path.name] = -1
    levels = json.loads((ROOT / "app" / "modules" / "training_camp" / "data" / "seed_game_levels.json").read_text(encoding="utf-8"))
    inventory["training_levels"] = len(levels)
    return inventory


def markdown_report(result: Dict[str, Any]) -> str:
    route = result["route"]["metrics"]
    scam = result["scam_type"]["metrics"]
    intent = result["knowledge_intent"]["metrics"]
    lines = [
        "# 方向三：面向反诈教育的智能客服评测报告",
        "",
        f"- 生成时间：{result['generated_at']}",
        f"- 基准版本：{result['benchmark_version']}",
        "- 评测模式：离线、确定性、无外部网络与无LLM调用",
        "- 说明：该结果是工程回归基线，不替代独立人工标注的大规模盲测。",
        "",
        "## 核心指标",
        "",
        "| 指标 | 样本数 | Accuracy | Macro-F1 | P95延迟 |",
        "|---|---:|---:|---:|---:|",
        f"| 场景路由 | {route['total']} | {route['accuracy']:.2%} | {route['macro_f1']:.2%} | {result['route']['timing']['p95_ms']:.2f} ms |",
        f"| 诈骗类型 | {scam['total']} | {scam['accuracy']:.2%} | {scam['macro_f1']:.2%} | {result['scam_type']['timing']['p95_ms']:.2f} ms |",
        f"| 知识意图 | {intent['total']} | {intent['accuracy']:.2%} | {intent['macro_f1']:.2%} | {result['knowledge_intent']['timing']['p95_ms']:.2f} ms |",
        "",
        "## 风险场景安全指标",
        "",
        f"- 风险场景召回率：{result['safety']['risk_recall']:.2%}",
        f"- 非风险场景误报率：{result['safety']['non_risk_false_positive_rate']:.2%}",
        f"- 指定五类骗局覆盖率：{result['safety']['required_scam_coverage']:.2%}",
        "",
        "## 知识库与游戏化资产",
        "",
    ]
    lines.extend(f"- `{name}`：{count}" for name, count in result["inventory"].items())
    lines.extend(["", "## 失败样本", ""])
    failures = []
    for section in ("route", "scam_type", "knowledge_intent"):
        failures.extend((section, row) for row in result[section]["cases"] if not row["passed"])
    if not failures:
        lines.append("当前基准无失败样本。")
    else:
        lines.extend(
            f"- `{section}/{row['id']}`：期望 `{row['expected']}`，实际 `{row['actual']}`；输入：{row['text']}"
            for section, row in failures
        )
    lines.extend([
        "",
        "## 结论与边界",
        "",
        "本报告验证本地确定性路由、风险类型规则和知识意图分类的可重复基线。正式参赛报告还应增加：",
        "",
        "1. 独立人员盲标的500–1000条真实风格对话；",
        "2. LLM在线模式重复运行、均值和方差；",
        "3. 多轮对话完成率、举报成功率与劝阻行动采纳率；",
        "4. 10/50/100并发下的端到端P50/P95/P99；",
        "5. 对抗输入、提示词注入和隐私泄露专项测试。",
        "",
    ])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    dataset = json.loads(args.dataset.read_text(encoding="utf-8"))

    route_rows, route_timing = run_cases(
        dataset["route_cases"],
        lambda text: str(_local_unified_route(text).get("workflow_mode") or ""),
    )
    scam_rows, scam_timing = run_cases(
        dataset["scam_cases"],
        lambda text: str(evaluate_risk_text(text).get("scam_type") or ""),
    )
    intent_rows, intent_timing = run_cases(dataset["knowledge_intent_cases"], classify_education_intent)
    route_metrics = classification_metrics(route_rows)
    scam_metrics = classification_metrics(scam_rows)
    intent_metrics = classification_metrics(intent_rows)

    risk_rows = [row for row in route_rows if row.get("group") == "risk"]
    non_risk_rows = [row for row in route_rows if row.get("group") != "risk"]
    required = set(dataset["metadata"]["required_scam_types"])
    covered = {row["expected"] for row in scam_rows if row["passed"]}
    result = {
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "benchmark_version": dataset["metadata"]["version"],
        "mode": "offline_deterministic",
        "route": {"metrics": route_metrics, "timing": route_timing, "cases": route_rows},
        "scam_type": {"metrics": scam_metrics, "timing": scam_timing, "cases": scam_rows},
        "knowledge_intent": {"metrics": intent_metrics, "timing": intent_timing, "cases": intent_rows},
        "safety": {
            "risk_recall": sum(row["actual"] == "risk_case_flow" for row in risk_rows) / len(risk_rows),
            "non_risk_false_positive_rate": sum(row["actual"] == "risk_case_flow" for row in non_risk_rows) / len(non_risk_rows),
            "required_scam_coverage": len(required & covered) / len(required),
            "required_scam_types": sorted(required),
        },
        "inventory": knowledge_inventory(),
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "direction3_evaluation.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    (args.output_dir / "direction3_evaluation.md").write_text(markdown_report(result), encoding="utf-8")
    print(json.dumps({
        "route_accuracy": route_metrics["accuracy"],
        "scam_accuracy": scam_metrics["accuracy"],
        "knowledge_intent_accuracy": intent_metrics["accuracy"],
        "risk_recall": result["safety"]["risk_recall"],
        "non_risk_false_positive_rate": result["safety"]["non_risk_false_positive_rate"],
        "report": str(args.output_dir / "direction3_evaluation.md"),
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
