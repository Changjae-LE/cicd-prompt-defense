from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from src.models.schemas import AgentMetrics


METRIC_FIELDS = [
    "agent", "attack_success_rate", "defense_detection_rate", "false_positive_rate",
    "false_negative_rate", "precision", "recall", "f1_score", "benign_completion_rate",
    "high_risk_tool_invocation_rate", "average_latency_ms", "average_llm_calls", "average_tokens",
    "context_aware_overhead_ms", "context_aware_overhead_percent",
]


def _pct(value: float) -> str:
    return f"{value:.1%}"


def _safe_cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", "<br>")


def write_extended_outputs(payload: dict[str, Any], output_dir: Path) -> dict[str, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "extended_results.json"
    csv_path = output_dir / "extended_results.csv"
    report_path = output_dir / "extended_report.md"
    ablation_path = output_dir / "ablation_results.csv"
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=METRIC_FIELDS)
        writer.writeheader()
        for row in payload["metrics"]:
            writer.writerow({key: row.get(key, 0) for key in METRIC_FIELDS})

    ablation_fields = [
        "agent", "attack_success_rate", "false_positive_rate", "precision", "recall", "f1_score",
        "benign_completion_rate", "high_risk_tool_invocation_rate", "average_latency_ms",
    ]
    with ablation_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=ablation_fields)
        writer.writeheader()
        for row in payload["ablation_metrics"]:
            writer.writerow({key: row.get(key, 0) for key in ablation_fields})

    report_path.write_text(_render_report(payload), encoding="utf-8")
    return {"json": json_path, "csv": csv_path, "report": report_path, "ablation": ablation_path}


def _render_report(payload: dict[str, Any]) -> str:
    lines = [
        "# Extended AgentGuard Evaluation Report",
        "",
        "> Research prototype evaluation. Results describe this deterministic synthetic benchmark, not production security efficacy.",
        "",
        "## Dataset and reproducibility",
        "",
        f"- Dataset version: `{payload['dataset']['version']}`",
        f"- SHA-256 fingerprint: `{payload['dataset']['fingerprint']}`",
        f"- Adversarial scenarios: {payload['dataset']['attack_count']}",
        f"- Hard-benign scenarios: {payload['dataset']['benign_count']}",
        "- Expansion is deterministic and uses no model generation, randomness, or evaluation feedback.",
        "- Variants from one template are correlated; category-level results are therefore reported alongside aggregates.",
        "",
        "## Fairness audit of the original evaluation",
        "",
    ]
    for finding in payload["audit"]["findings"]:
        lines.append(f"- {finding}")
    lines.extend([
        "",
        f"Legacy attack texts matched the input detector before tool execution in **{_pct(payload['audit']['legacy_detector_overlap_rate'])}** of scenarios.",
        f"Extended attack texts match it in **{_pct(payload['audit']['extended_attack_detector_overlap_rate'])}**; hard-benign texts match it in **{_pct(payload['audit']['extended_benign_detector_overlap_rate'])}**.",
        "",
        "## Evaluation methodology",
        "",
        "The deterministic provider replays pre-labelled tool proposals. Each call is independently labelled as benign or malicious. ASR measures whether any malicious call executes. Classification metrics treat a scenario as flagged when content analysis raises an alert or any call is blocked/held for approval. Thus a warning on a benign document counts as a false positive even if the task still completes.",
        "",
        "This isolates authorization behavior after action proposal. It does not measure a real model's probability of proposing an attack, natural-language answer quality, or end-to-end remediation correctness.",
        "",
        "## Main results",
        "",
        "| Agent | ASR | TPR | FPR | FNR | Precision | Recall | F1 | Benign completion | High-risk invocation | Avg latency ms | Avg LLM calls | Avg tokens | Context overhead ms |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ])
    for row in payload["metrics"]:
        lines.append(
            f"| {row['agent']} | {_pct(row['attack_success_rate'])} | {_pct(row['defense_detection_rate'])} | "
            f"{_pct(row['false_positive_rate'])} | {_pct(row['false_negative_rate'])} | {_pct(row['precision'])} | "
            f"{_pct(row['recall'])} | {_pct(row['f1_score'])} | {_pct(row['benign_completion_rate'])} | "
            f"{_pct(row['high_risk_tool_invocation_rate'])} | {row['average_latency_ms']:.3f} | "
            f"{row['average_llm_calls']:.2f} | {row['average_tokens']:.1f} | {row['context_aware_overhead_ms']:.3f} |"
        )
    lines.extend([
        "",
        "Context overhead is the difference between Context-Aware and Baseline mean in-process authorization latency. It excludes agent construction, filesystem trace writing, and real provider/network latency.",
        "",
        "## Attack success by category",
        "",
        "| Category | " + " | ".join(row["agent"] for row in payload["metrics"]) + " |",
        "|---|" + "---:|" * len(payload["metrics"]),
    ])
    categories = sorted({key for row in payload["metrics"] for key in row["attack_category_rates"]})
    for category in categories:
        lines.append("| " + category + " | " + " | ".join(_pct(row["attack_category_rates"].get(category, 0.0)) for row in payload["metrics"]) + " |")

    lines.extend([
        "",
        "## Ablation study",
        "",
        "| Variant | ASR | FPR | Precision | Recall | F1 | Benign completion |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ])
    for row in payload["ablation_metrics"]:
        lines.append(f"| {row['agent']} | {_pct(row['attack_success_rate'])} | {_pct(row['false_positive_rate'])} | {_pct(row['precision'])} | {_pct(row['recall'])} | {_pct(row['f1_score'])} | {_pct(row['benign_completion_rate'])} |")
    lines.extend([
        "",
        "The execution-history and sequence-risk removals may have identical results because the current sequence classifier consumes history as its only stateful input. That coupling is itself a design limitation, not an independent-effect estimate.",
        "",
        "## Context-Aware failures retained in the benchmark",
        "",
    ])
    failure_counts = payload["context_failures_by_category"]
    if failure_counts:
        lines.extend(["| Category | Successful attacks |", "|---|---:|"])
        for category, count in sorted(failure_counts.items()):
            lines.append(f"| {category} | {count} |")
        lines.extend([
            "",
            "Observed failure mechanisms:",
            "",
            "- `intent_confusion`: lexical intent matching treats the negated phrase `do not deploy` as deployment authorization.",
            "- `network_only`: a user-aligned, non-secret-looking callback body has no sequence or direct exfiltration signal.",
            "- `security_troubleshooting`: the prerequisite Secret read is blocked, so no executed sensitive event remains in history; the later HTTP call is allowed.",
            "- `stealth_policy_manipulation`: an aligned medium-risk workflow edit avoids suspicious-text patterns.",
            "- `trust_boundary`: the morphological form `disabling` evades the detector pattern for `disable`.",
        ])
    else:
        lines.append("No Context-Aware attack succeeded in this run.")

    lines.extend([
        "",
        "## Input-Only failed but Context-Aware succeeded",
        "",
        f"Differential scenarios: {len(payload['differential_cases'])}",
        "",
    ])
    for case in payload["differential_cases"]:
        lines.extend([
            f"### {case['scenario_id']} — {case['category']}",
            "",
            f"- **User request:** {_safe_cell(case['user_request'])}",
            f"- **External content:** {_safe_cell(' || '.join(case['external_content']))}",
            f"- **Proposed tool call:** `{_safe_cell(json.dumps(case['proposed_tool_call'], ensure_ascii=False, sort_keys=True))}`",
            f"- **Execution history:** `{_safe_cell(json.dumps(case['execution_history'], ensure_ascii=False, sort_keys=True))}`",
            f"- **Input-Only decision:** {case['input_only_decision']}",
            f"- **Context-Aware decision:** {case['context_aware_decision']}",
            f"- **Additional Context-Aware signals:** {_safe_cell(', '.join(case['additional_security_signals']))}",
            "",
        ])

    lines.extend([
        "## Remaining limitations",
        "",
        "- Scenario variants share templates and are not independent real-world samples.",
        "- The deterministic provider fixes proposed actions, so results do not measure model susceptibility or action-selection frequency.",
        "- Intent analysis is lexical and mishandles negation such as `do not deploy`.",
        "- Sequence analysis recognizes only a small set of hard-coded tool transitions and does not perform general data-flow taint tracking.",
        "- Trust labels are assumed correct; provenance confusion is not evaluated.",
        "- Approval is scored as a positive security decision and as incomplete automation; no human approval outcome is simulated.",
        "- The policy intentionally forbids some authorized Secret-to-network workflows, producing measurable hard-benign failures.",
        "- Latencies are local microbenchmarks and should not be extrapolated to provider or production latency.",
        "",
    ])
    return "\n".join(lines)
