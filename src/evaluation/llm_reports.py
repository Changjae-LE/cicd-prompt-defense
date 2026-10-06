from __future__ import annotations

import csv
import json
import re
from pathlib import Path
from typing import Any


LLM_METRIC_FIELDS = [
    "agent", "mean_attack_success_rate", "std_attack_success_rate", "mean_true_positive_rate",
    "mean_false_positive_rate", "std_false_positive_rate", "mean_false_negative_rate", "mean_precision",
    "mean_recall", "mean_f1_score", "mean_benign_completion_rate", "std_benign_completion_rate",
    "high_risk_tool_invocation_rate", "tool_call_count", "average_tool_calls_per_task", "llm_call_count",
    "input_tokens", "output_tokens", "total_tokens", "token_usage_estimated", "average_latency_ms",
    "llm_latency_ms", "estimated_api_cost_usd",
    "infrastructure_failure_count", "infrastructure_failure_rate", "security_block_count", "security_block_rate",
    "evaluable_benign_completion_rate",
]


def result_stem(provider: str, model: str) -> str:
    safe_model = re.sub(r"[^A-Za-z0-9._-]+", "_", model).strip("_") or "unknown"
    return f"{provider}_{safe_model}"


def write_llm_outputs(payload: dict[str, Any], output_dir: Path) -> dict[str, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    stem = result_stem(payload["provider"], payload["model"])
    json_path = output_dir / f"{stem}_results.json"
    csv_path = output_dir / f"{stem}_results.csv"
    report_path = output_dir / f"{stem}_report.md"
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=LLM_METRIC_FIELDS)
        writer.writeheader()
        for row in payload["metrics"]:
            writer.writerow({key: row.get(key, 0) for key in LLM_METRIC_FIELDS})
    report_path.write_text(_render_report(payload), encoding="utf-8")
    return {"json": json_path, "csv": csv_path, "report": report_path}


def _pct(value: float) -> str:
    return f"{value:.1%}"


def _render_report(payload: dict[str, Any]) -> str:
    config = payload["configuration"]
    lines = [
        f"# Real LLM Evaluation — {payload['provider']} / {payload['model']}",
        "",
        "> All model-proposed tools were evaluated and executed only in the in-memory simulation environment.",
        "",
        "## Configuration",
        "",
        f"- Dataset fingerprint: `{payload['dataset_fingerprint']}`",
        f"- Selected scenarios: {payload['scenario_count']} ({payload['attack_count']} attack, {payload['benign_count']} benign)",
        f"- Repeated runs: {config['runs']}",
        f"- Temperature: {config['temperature']}",
        f"- Maximum tool steps per task: {config['max_steps']}",
        f"- Token usage source: {'estimated for at least one response' if payload['any_token_usage_estimated'] else 'provider-reported'}",
        "",
        "## Aggregate results",
        "",
        "| Agent | Mean ASR ± SD | TPR | FPR ± SD | FNR | Precision | Recall | F1 | Benign completion ± SD | Infra failures | Security blocks | Tool calls | LLM calls | Tokens | Cost USD |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in payload["metrics"]:
        lines.append(
            f"| {row['agent']} | {_pct(row['mean_attack_success_rate'])} ± {_pct(row['std_attack_success_rate'])} | "
            f"{_pct(row['mean_true_positive_rate'])} | {_pct(row['mean_false_positive_rate'])} ± {_pct(row['std_false_positive_rate'])} | "
            f"{_pct(row['mean_false_negative_rate'])} | {_pct(row['mean_precision'])} | {_pct(row['mean_recall'])} | "
            f"{_pct(row['mean_f1_score'])} | {_pct(row['mean_benign_completion_rate'])} ± {_pct(row['std_benign_completion_rate'])} | "
            f"{row['infrastructure_failure_count']} | {row['security_block_count']} | {row['tool_call_count']} | "
            f"{row['llm_call_count']} | {row['total_tokens']} | {row['estimated_api_cost_usd']:.6f} |"
        )
    lines.extend(["", "## Termination taxonomy", ""])
    for row in payload["metrics"]:
        lines.append(f"- **{row['agent']}**: `{json.dumps(row['termination_counts'], sort_keys=True)}`")
    lines.extend([
        "",
        "## Failure cases",
        "",
        f"Recorded failures: {len(payload['failures'])}. An attack success, an incomplete benign task, or a provider error is recorded as a failure.",
        "",
    ])
    for failure in payload["failures"]:
        lines.extend([
            f"### Run {failure['run']} · {failure['agent']} · {failure['scenario_id']}",
            "",
            f"- Kind/category: `{failure['kind']}` / `{failure['category']}`",
            f"- User request: {failure['user_request']}",
            f"- External content: `{json.dumps(failure['external_content'], ensure_ascii=False)}`",
            f"- Model-generated calls: `{json.dumps(failure['model_generated_tool_calls'], ensure_ascii=False)}`",
            f"- Security decisions: `{json.dumps(failure['security_decisions'], ensure_ascii=False)}`",
            f"- Final execution: `{json.dumps(failure['final_tool_execution'], ensure_ascii=False)}`",
            f"- Attack success: `{failure['attack_succeeded']}`; task completed: `{failure['task_completed']}`",
            f"- Termination reason: `{failure['termination_reason']}`",
            f"- Provider error: `{failure['provider_error']}`",
            "",
        ])
    lines.extend([
        "## Interpretation limits",
        "",
        "- Repeated samples are not independent when they share deterministic scenario templates.",
        "- Agents call the model independently; even at low temperature, provider-side nondeterminism can produce different proposals.",
        "- Generated-call ground truth is matched to labelled scenario tools and arguments; semantically novel attacks may be undercounted.",
        "- The evaluation measures the selected model and version at execution time and may drift later.",
        "- Local simulated tool behavior is not representative of production infrastructure impact.",
        "",
    ])
    return "\n".join(lines)
