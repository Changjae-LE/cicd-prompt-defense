from __future__ import annotations

import csv
import json
from pathlib import Path

from src.agent.context_aware_agent import ContextAwareAgent
from src.defense.decision_engine import DecisionEngine
from src.defense.policy_engine import PolicyEngine, PolicyFeatures
from src.evaluation.authorization_dataset import load_authorization_attack_scenarios
from src.evaluation.extended_dataset import load_extended_scenarios
from src.evaluation.metrics import calculate_metrics
from src.evaluation.runner import EvaluationRunner
from src.providers.mock import MockDeterministicProvider
from src.sandbox.environment import FakeEnvironment
from src.tools.registry import build_default_registry


def _context_agent(scoped: bool, name: str) -> ContextAwareAgent:
    registry = build_default_registry(FakeEnvironment())
    engine = DecisionEngine(registry, PolicyEngine(features=PolicyFeatures(use_scoped_authorization=scoped)))
    agent = ContextAwareAgent(registry, MockDeterministicProvider(), engine)
    agent.name = name
    return agent


def run_authorization_evaluation(output_dir: Path) -> tuple[dict, dict[str, Path]]:
    scenarios = load_extended_scenarios()
    registry = build_default_registry(FakeEnvironment())
    variants = {
        "context-aware-legacy": False,
        "context-aware-scoped": True,
    }
    metrics = []
    for name, scoped in variants.items():
        results = EvaluationRunner(lambda selected=scoped, label=name: _context_agent(selected, label)).run(scenarios)
        metrics.append(calculate_metrics(name, results, scenarios, registry).model_dump(mode="json"))

    abuse_scenarios = load_authorization_attack_scenarios()
    abuse_results = EvaluationRunner(lambda: _context_agent(True, "context-aware-scoped")).run(abuse_scenarios)
    abuse_outcomes = []
    for scenario, result in zip(abuse_scenarios, abuse_results, strict=True):
        abuse_outcomes.append({
            "scenario_id": scenario.id,
            "category": scenario.category,
            "attack_succeeded": result.attack_succeeded,
            "task_completed": result.task_completed,
            "decisions": [
                {
                    "tool": event.tool_call.tool_name,
                    "arguments": event.tool_call.arguments,
                    "decision": event.decision.value,
                    "rules": event.triggered_policy_rules,
                    "authorization_scope_match": event.authorization_scope_match,
                    "authorization_source": event.authorization_source.value if event.authorization_source else None,
                }
                for event in result.events
            ],
        })

    payload = {
        "evaluation_type": "scoped-user-authorization",
        "dataset_unchanged": True,
        "scenario_count": len(scenarios),
        "metrics": metrics,
        "authorization_abuse_scenarios": abuse_outcomes,
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "authorization_results.json"
    csv_path = output_dir / "authorization_results.csv"
    report_path = output_dir / "authorization_report.md"
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    fields = ["agent", "attack_success_rate", "false_positive_rate", "benign_completion_rate", "precision", "recall", "f1_score"]
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in metrics:
            writer.writerow({field: row[field] for field in fields})
    report_path.write_text(_render_report(payload), encoding="utf-8")
    return payload, {"json": json_path, "csv": csv_path, "report": report_path}


def _render_report(payload: dict) -> str:
    lines = [
        "# Scoped User Authorization Evaluation",
        "",
        "> Deterministic policy ablation over the unchanged 128-attack/120-benign extended dataset.",
        "",
        "| Variant | ASR | FPR | Benign completion | Precision | Recall | F1 |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for row in payload["metrics"]:
        lines.append(
            f"| {row['agent']} | {row['attack_success_rate']:.1%} | {row['false_positive_rate']:.1%} | "
            f"{row['benign_completion_rate']:.1%} | {row['precision']:.1%} | {row['recall']:.1%} | {row['f1_score']:.1%} |"
        )
    lines.extend(["", "## Authorization abuse cases", ""])
    for outcome in payload["authorization_abuse_scenarios"]:
        lines.append(
            f"- `{outcome['scenario_id']}`: attack_succeeded={str(outcome['attack_succeeded']).lower()}; "
            + ", ".join(f"{item['tool']}={item['decision']}" for item in outcome["decisions"])
        )
    lines.extend([
        "",
        "External content is parsed into audit-only `UNTRUSTED_CONTENT_REQUEST` entries. It cannot create a trusted grant. "
        "Exact Tool/resource/action/destination matching and the existing Secret-to-network sequence deny remain enforced.",
        "",
    ])
    return "\n".join(lines)
