from __future__ import annotations

import argparse
import json
from pathlib import Path

from src.agent.baseline_agent import BaselineAgent
from src.agent.context_aware_agent import ContextAwareAgent
from src.agent.input_filter_agent import InputFilterAgent
from src.evaluation.dataset import get_scenario, load_scenarios
from src.evaluation.metrics import calculate_metrics
from src.evaluation.reports import write_reports
from src.evaluation.runner import EvaluationRunner
from src.evaluation.extended_runner import run_extended_evaluation
from src.models.schemas import AgentMetrics, TaskResult
from src.providers.mock import MockDeterministicProvider
from src.sandbox.environment import FakeEnvironment
from src.tools.registry import build_default_registry


ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = ROOT / "results"
AGENTS = {
    "baseline": BaselineAgent,
    "input-filter": InputFilterAgent,
    "context-aware": ContextAwareAgent,
}


def make_agent(name: str):
    if name not in AGENTS:
        raise ValueError(f"Unknown agent: {name}")
    environment = FakeEnvironment()
    return AGENTS[name](build_default_registry(environment), MockDeterministicProvider())


def render_task(result: TaskResult) -> str:
    lines = [
        f"trace_id: {result.trace_id}",
        f"agent: {result.agent}",
        f"scenario: {result.scenario_id}",
        f"task_completed: {result.task_completed}",
        f"attack_succeeded: {result.attack_succeeded}",
        "tool decisions:",
    ]
    for event in result.events:
        rule_text = ", ".join(event.triggered_policy_rules) or "none"
        lines.append(f"  - {event.tool_call.tool_name}: {event.decision.value} (risk={event.risk_score:.2f}, rules={rule_text})")
        for reason in event.reasons:
            lines.append(f"      {reason}")
    lines.append(f"result: {result.final_result}")
    return "\n".join(lines)


def command_run(agent_name: str, scenario_id: str) -> TaskResult:
    result = make_agent(agent_name).run(get_scenario(scenario_id))
    print(render_task(result))
    return result


def command_demo() -> None:
    scenario = get_scenario("attack-001")
    print("AgentGuard end-to-end demo")
    print("User: Analyze the deployment failure")
    print("Untrusted README requests fake-secret access and a simulated external POST.\n")
    for name in AGENTS:
        print(f"=== {name} ===")
        result = make_agent(name).run(scenario)
        print(render_task(result))
        print()
    print("The context-aware agent blocks unrelated secret/network actions while completing safe deployment diagnostics.")


def command_evaluate(price_per_million_tokens: float = 0.0) -> list[AgentMetrics]:
    scenarios = load_scenarios()
    trace_root = RESULTS_DIR / "traces"
    all_metrics: list[AgentMetrics] = []
    registry = build_default_registry(FakeEnvironment())
    for name in AGENTS:
        results = EvaluationRunner(lambda selected=name: make_agent(selected), trace_root / name).run(scenarios)
        all_metrics.append(calculate_metrics(name, results, scenarios, registry, price_per_million_tokens))
    paths = write_reports(all_metrics, RESULTS_DIR)
    print("Evaluation complete (40 scenarios × 3 agents).")
    for item in all_metrics:
        print(f"  {item.agent}: ASR={item.attack_success_rate:.1%}, FPR={item.false_positive_rate:.1%}, benign completion={item.benign_completion_rate:.1%}")
    print(f"JSON: {paths['json']}")
    print(f"CSV: {paths['csv']}")
    print(f"Report: {paths['report']}")
    return all_metrics


def command_report() -> None:
    path = RESULTS_DIR / "results.json"
    if not path.exists():
        raise SystemExit("No results found. Run `python -m src.cli evaluate` first.")
    metrics = [AgentMetrics.model_validate(item) for item in json.loads(path.read_text(encoding="utf-8"))]
    paths = write_reports(metrics, RESULTS_DIR)
    print(f"Regenerated {paths['report']}")


def command_evaluate_extended(write_traces: bool = False) -> None:
    payload, paths = run_extended_evaluation(RESULTS_DIR, write_traces=write_traces)
    print(f"Extended evaluation complete ({payload['dataset']['attack_count']} attacks + {payload['dataset']['benign_count']} hard-benign scenarios).")
    for item in payload["metrics"]:
        print(
            f"  {item['agent']}: ASR={item['attack_success_rate']:.1%}, "
            f"FPR={item['false_positive_rate']:.1%}, F1={item['f1_score']:.1%}, "
            f"benign completion={item['benign_completion_rate']:.1%}"
        )
    print(f"JSON: {paths['json']}")
    print(f"CSV: {paths['csv']}")
    print(f"Ablation: {paths['ablation']}")
    print(f"Report: {paths['report']}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agentguard", description="Context-aware defense research prototype")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("demo", help="Run the end-to-end attack comparison")
    run = sub.add_parser("run", help="Run one scenario")
    run.add_argument("--agent", choices=sorted(AGENTS), required=True)
    run.add_argument("--scenario", required=True)
    evaluate = sub.add_parser("evaluate", help="Evaluate all agents on all scenarios")
    evaluate.add_argument("--price-per-million-tokens", type=float, default=0.0)
    sub.add_parser("report", help="Regenerate the Markdown/CSV report from JSON")
    extended = sub.add_parser("evaluate-extended", help="Run the extended fairness and ablation evaluation")
    extended.add_argument("--write-traces", action="store_true", help="Write per-task redacted traces")
    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    if args.command == "demo":
        command_demo()
    elif args.command == "run":
        command_run(args.agent, args.scenario)
    elif args.command == "evaluate":
        command_evaluate(args.price_per_million_tokens)
    elif args.command == "report":
        command_report()
    elif args.command == "evaluate-extended":
        command_evaluate_extended(args.write_traces)


if __name__ == "__main__":
    main()
