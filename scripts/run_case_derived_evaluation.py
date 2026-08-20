#!/usr/bin/env python3
"""Evaluate the running service with the 400 case-derived candidates."""

from __future__ import annotations

import argparse
import json
import re
import statistics
import time
import urllib.request
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "evaluation/raw_candidates/case_derived_400.jsonl"
LEVELS = ROOT / "database_snapshot/mongo/game_levels.json"
REGISTRY = ROOT / "database_snapshot/mongo/fraud_type_registry.json"
OUT_JSON = ROOT / "evaluation/reports/case_derived_400_evaluation.json"
OUT_MD = ROOT / "evaluation/reports/case_derived_400_evaluation.md"


def post_json(url: str, payload: dict, timeout: int = 90) -> tuple[dict, float]:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    start = time.perf_counter()
    with urllib.request.urlopen(request, timeout=timeout) as response:
        data = json.loads(response.read().decode("utf-8"))
    return data, (time.perf_counter() - start) * 1000


def percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    values = sorted(values)
    return values[round((len(values) - 1) * p)]


ALIAS_TO_ID: dict[str, str] = {}


def normalize_text(value: str) -> str:
    return (value or "").replace(" ", "").replace("/", "").lower()


def load_aliases() -> None:
    docs = json.loads(REGISTRY.read_text(encoding="utf-8"))["documents"]
    for row in docs:
        fraud_id = row["fraud_type_id"]
        for name in [row.get("standard_name", ""), *(row.get("aliases") or [])]:
            if name:
                ALIAS_TO_ID[normalize_text(name)] = fraud_id


def canonical_type(value: str) -> str:
    normalized = normalize_text(value)
    if normalized in ALIAS_TO_ID:
        return ALIAS_TO_ID[normalized]
    matches = [(len(alias), fraud_id) for alias, fraud_id in ALIAS_TO_ID.items() if len(alias) >= 4 and alias in normalized]
    return max(matches)[1] if matches else normalized


def same_type(expected: str, actual: str) -> bool:
    return bool(expected and actual and canonical_type(expected) == canonical_type(actual))


def infer_type_from_answer(answer: str) -> str:
    match = re.search(r"(?:识别|判断为|重点留意)[：为]?([^，。\n]{2,30}(?:诈骗|风险))", answer)
    if not match:
        return ""
    fragment = normalize_text(match.group(1))
    matches = [(len(alias), fraud_id) for alias, fraud_id in ALIAS_TO_ID.items() if len(alias) >= 4 and alias in fragment]
    return max(matches)[1] if matches else ""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8001")
    parser.add_argument("--workers", type=int, default=10)
    parser.add_argument("--skip-e2e", action="store_true")
    parser.add_argument("--fraud-type", default="", help="仅评测指定题库诈骗类型")
    parser.add_argument("--report-name", default="case_derived_400_evaluation")
    args = parser.parse_args()
    load_aliases()

    candidates = [json.loads(line) for line in DATASET.read_text(encoding="utf-8").splitlines() if line.strip()]
    levels = json.loads(LEVELS.read_text(encoding="utf-8"))["documents"]
    by_id = {int(item["level_id"]): item for item in levels}
    cases = []
    for row in candidates:
        level_id = int(row["source"]["derived_from"]["level_id"])
        level = by_id[level_id]
        cases.append({
            "sample_id": row["sample_id"],
            "text": row["conversation"][0]["content"],
            "expected_type": level["fraud_type"],
            "expected_answer": level["answer"],
            "question": level["question"],
        })
    if args.fraud_type:
        cases = [case for case in cases if case["expected_type"] == args.fraud_type]
        if not cases:
            raise SystemExit(f"没有找到诈骗类型：{args.fraud_type}")

    def risk_one(case: dict) -> dict:
        try:
            data, latency = post_json(f"{args.base_url}/risk/check", {"user_text": case["text"]}, timeout=30)
            # The stable taxonomy fields are authoritative.  Keep legacy
            # ``scam_type`` as a final fallback for older deployments and as
            # an additional candidate for compatibility reporting.
            primary_type = data.get("primary_type") or data.get("fraud_type") or data.get("scam_type", "")
            candidates_actual = [
                primary_type,
                *(data.get("candidate_types") or []),
                *(data.get("possible_fraud_types") or []),
                data.get("scam_type", ""),
            ]
            candidates_actual = [item for index, item in enumerate(candidates_actual) if item and item not in candidates_actual[:index]]
            return {**case, "actual_type": primary_type, "possible_types": candidates_actual,
                    "risk_score": data.get("risk_score", 0), "risk_level": data.get("risk_level", ""),
                    "intervention_goal": data.get("intervention_goal", ""), "next_actions": data.get("next_actions") or [],
                    "top1_pass": same_type(case["expected_type"], primary_type),
                    "topk_pass": any(same_type(case["expected_type"], item) for item in candidates_actual),
                    "latency_ms": latency, "error": ""}
        except Exception as exc:
            return {**case, "actual_type": "__error__", "possible_types": [], "risk_score": 0,
                    "risk_level": "", "intervention_goal": "", "next_actions": [], "top1_pass": False,
                    "topk_pass": False, "latency_ms": 0, "error": f"{type(exc).__name__}: {exc}"}

    risk_rows = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(risk_one, case) for case in cases]
        for future in as_completed(futures):
            risk_rows.append(future.result())
    risk_rows.sort(key=lambda row: row["sample_id"])

    per_type = {}
    grouped = defaultdict(list)
    for row in risk_rows:
        grouped[row["expected_type"]].append(row)
    for fraud_type, rows in sorted(grouped.items()):
        per_type[fraud_type] = {
            "count": len(rows),
            "top1_accuracy": sum(row["top1_pass"] for row in rows) / len(rows),
            "topk_recall": sum(row["topk_pass"] for row in rows) / len(rows),
            "mean_risk_score": statistics.mean(float(row["risk_score"] or 0) for row in rows),
        }

    e2e_rows = []
    if not args.skip_e2e:
        representatives = [rows[0] for _, rows in sorted(grouped.items())]

        def e2e_one(case: dict) -> dict:
            try:
                data, latency = post_json(f"{args.base_url}/knowledge/chat", {
                    "message": case["text"], "use_llm": False, "is_stream": False,
                    "session_id": f'eval-{case["sample_id"]}',
                }, timeout=120)
                answer = data.get("answer", "")
                fraud_type = data.get("primary_type") or data.get("fraud_type", "")
                for parent in ("risk_decision", "scam_understanding", "anti_fraud_engine", "risk_judgement_card"):
                    nested = data.get(parent)
                    if not fraud_type and isinstance(nested, dict):
                        fraud_type = nested.get("primary_type") or nested.get("fraud_type", "")
                fraud_type = fraud_type or infer_type_from_answer(answer)
                has_action = any(token in answer for token in ("不要", "停止", "先停", "暂停", "核实", "核验", "官方", "保留", "报警", "联系", "修改", "拒绝"))
                has_knowledge_points = sum(token in answer for token in ("1.", "2.", "3.")) >= 2
                return {"sample_id": case["sample_id"], "expected_type": case["expected_type"],
                        "actual_type": fraud_type, "type_pass": same_type(case["expected_type"], fraud_type),
                        "has_action": has_action, "has_knowledge_points": has_knowledge_points,
                        "has_next_question": bool(data.get("next_question")),
                        "answer": answer, "latency_ms": latency, "error": ""}
            except Exception as exc:
                return {"sample_id": case["sample_id"], "expected_type": case["expected_type"],
                        "actual_type": "__error__", "type_pass": False, "has_action": False,
                        "has_knowledge_points": False, "has_next_question": False, "answer": "", "latency_ms": 0,
                        "error": f"{type(exc).__name__}: {exc}"}

        with ThreadPoolExecutor(max_workers=3) as pool:
            futures = [pool.submit(e2e_one, case) for case in representatives]
            for future in as_completed(futures):
                e2e_rows.append(future.result())
        e2e_rows.sort(key=lambda row: row["sample_id"])

    latencies = [row["latency_ms"] for row in risk_rows if not row["error"]]
    result = {
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "dataset": "case_derived_400",
        "evaluation_scope": "internal_case_derived_regression",
        "limitations": ["题库与项目知识库存在重叠，不是独立盲测", "端到端回答质量仅使用自动启发式检查，仍需人工复核"],
        "risk_api": {
            "total": len(risk_rows), "errors": sum(bool(row["error"]) for row in risk_rows),
            "top1_accuracy": sum(row["top1_pass"] for row in risk_rows) / len(risk_rows),
            "topk_recall": sum(row["topk_pass"] for row in risk_rows) / len(risk_rows),
            "risk_detection_rate_score_ge_30": sum(float(row["risk_score"] or 0) >= 30 for row in risk_rows) / len(risk_rows),
            "mean_risk_score": statistics.mean(float(row["risk_score"] or 0) for row in risk_rows),
            "latency_ms": {"mean": statistics.mean(latencies) if latencies else 0, "p50": percentile(latencies, .5),
                           "p95": percentile(latencies, .95), "p99": percentile(latencies, .99), "max": max(latencies, default=0)},
            "per_type": per_type, "failures": [row for row in risk_rows if not row["top1_pass"]],
        },
        "e2e_sample": {
            "total": len(e2e_rows), "errors": sum(bool(row["error"]) for row in e2e_rows),
            "type_accuracy": sum(row["type_pass"] for row in e2e_rows) / len(e2e_rows) if e2e_rows else 0,
            "action_coverage": sum(row["has_action"] for row in e2e_rows) / len(e2e_rows) if e2e_rows else 0,
            "knowledge_point_coverage": sum(row["has_knowledge_points"] for row in e2e_rows) / len(e2e_rows) if e2e_rows else 0,
            "next_question_coverage": sum(row["has_next_question"] for row in e2e_rows) / len(e2e_rows) if e2e_rows else 0,
            "latency_ms": {"mean": statistics.mean([r["latency_ms"] for r in e2e_rows]) if e2e_rows else 0,
                           "p95": percentile([r["latency_ms"] for r in e2e_rows], .95)},
            "cases": e2e_rows,
        },
    }
    out_json = OUT_JSON.parent / f"{args.report_name}.json"
    out_md = OUT_MD.parent / f"{args.report_name}.md"
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    weakest = sorted(per_type.items(), key=lambda item: (item[1]["top1_accuracy"], item[0]))
    confusions = Counter((r["expected_type"], r["actual_type"]) for r in risk_rows if not r["top1_pass"])
    lines = ["# 案例衍生 400 条内部回归评测", "", f"- 生成时间：{result['generated_at']}",
             "- 边界：题库与知识库存在重叠，本报告不能作为独立盲测成绩。", "",
             "## 总体结果", "", "| 指标 | 结果 |", "|---|---:|",
             f"| 风险接口成功率 | {(1-result['risk_api']['errors']/len(risk_rows)):.2%} |",
             f"| 诈骗类型 Top-1 | {result['risk_api']['top1_accuracy']:.2%} |",
             f"| 诈骗类型 Top-k 召回 | {result['risk_api']['topk_recall']:.2%} |",
             f"| 风险检出率（分数≥30） | {result['risk_api']['risk_detection_rate_score_ge_30']:.2%} |",
             f"| 风险接口 P95 | {result['risk_api']['latency_ms']['p95']:.1f} ms |",
             f"| 端到端类型准确率（{len(e2e_rows)}类抽样） | {result['e2e_sample']['type_accuracy']:.2%} |",
             f"| 端到端处置动作覆盖 | {result['e2e_sample']['action_coverage']:.2%} |",
             f"| 端到端知识点结构覆盖 | {result['e2e_sample']['knowledge_point_coverage']:.2%} |",
             f"| 端到端 P95 | {result['e2e_sample']['latency_ms']['p95']:.1f} ms |", "",
             "## 分类型结果", "", "| 诈骗类型 | 数量 | Top-1 | Top-k | 平均风险分 |", "|---|---:|---:|---:|---:|"]
    lines += [f"| {name} | {m['count']} | {m['top1_accuracy']:.2%} | {m['topk_recall']:.2%} | {m['mean_risk_score']:.1f} |" for name, m in weakest]
    lines += ["", "## 主要混淆", ""]
    lines += [f"- {expected} → {actual or '未识别'}：{count} 条" for (expected, actual), count in confusions.most_common(15)] or ["- 无"]
    lines += ["", "## 优化方向", "",
              "1. P0：优先补齐 Top-1 最低的诈骗类型及主要混淆对，在规则中使用行为组合而非仅使用类型名称关键词。",
              "2. P0：修复风险规则加载 warnings 中的未知特征，避免规则被整体跳过。",
              "3. P1：将知识提问和本人正在受骗明确分流，避免案例科普题被统一升级为紧急劝阻。",
              "4. P1：端到端回答增加结构化安全检查：立即停止动作、官方核验、留证、已损失后的止付报警。",
              "5. P1：缩短大模型路由和生成链路；规则高置信时直接进入模板化首轮劝阻，大模型负责个性化补充。",
              "6. P2：在独立盲测集中补充正常交易、模糊表达、多轮状态变化、方言/ASR 错字和提示注入样本。", ""]
    out_md.write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps({"report": str(out_md), "json": str(out_json), "risk_top1": result["risk_api"]["top1_accuracy"],
                      "risk_topk": result["risk_api"]["topk_recall"], "e2e_type": result["e2e_sample"]["type_accuracy"]},
                     ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
