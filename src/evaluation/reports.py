from __future__ import annotations

import csv
import json
from pathlib import Path

from src.models.schemas import AgentMetrics


DISPLAY = {"baseline": "None", "input-filter": "Input Filter", "context-aware": "Context-Aware"}


def write_reports(metrics: list[AgentMetrics], output_dir: Path) -> dict[str, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "results.json"
    csv_path = output_dir / "results.csv"
    report_path = output_dir / "report.md"
    rows = [item.model_dump(mode="json") for item in metrics]
    json_path.write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")
    flat_keys = [key for key in rows[0] if key != "attack_category_rates"] if rows else []
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=flat_keys)
        writer.writeheader()
        writer.writerows([{key: row[key] for key in flat_keys} for row in rows])

    lines = [
        "# AgentGuard Evaluation Report",
        "",
        "> Research prototype results from a deterministic, simulated CI/CD environment.",
        "",
        "## Primary comparison",
        "",
        "| Defense | Attack Success Rate | False Positive Rate | Benign Completion Rate |",
        "|---|---:|---:|---:|",
    ]
    for item in metrics:
        lines.append(f"| {DISPLAY.get(item.agent, item.agent)} | {item.attack_success_rate:.1%} | {item.false_positive_rate:.1%} | {item.benign_completion_rate:.1%} |")
    lines.extend(["", "## Additional metrics", "", "| Defense | TPR | FNR | Task Completion | High-Risk Invocation | Avg Blocked | Avg Latency (ms) |", "|---|---:|---:|---:|---:|---:|---:|"])
    for item in metrics:
        lines.append(f"| {DISPLAY.get(item.agent, item.agent)} | {item.defense_detection_rate:.1%} | {item.false_negative_rate:.1%} | {item.task_completion_rate:.1%} | {item.high_risk_tool_invocation_rate:.1%} | {item.average_blocked_calls:.2f} | {item.average_latency_ms:.2f} |")
    categories = sorted({category for item in metrics for category in item.attack_category_rates})
    lines.extend(["", "## Attack success rate by category", "", "| Category | " + " | ".join(DISPLAY.get(item.agent, item.agent) for item in metrics) + " |", "|---|" + "---:|" * len(metrics)])
    for category in categories:
        lines.append("| " + category + " | " + " | ".join(f"{item.attack_category_rates.get(category, 0):.1%}" for item in metrics) + " |")
    lines.extend(["", "## Interpretation", "", "Lower attack success and false-positive rates are better. Benign completion measures utility preservation. These results characterize the included synthetic scenarios only and are not a production security guarantee."])
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {"json": json_path, "csv": csv_path, "report": report_path}

