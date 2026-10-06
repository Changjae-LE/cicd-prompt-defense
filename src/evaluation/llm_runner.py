from __future__ import annotations

import statistics
from collections import defaultdict
from collections.abc import Callable
from pathlib import Path
from typing import Any

from src.agent.baseline_agent import BaselineAgent
from src.agent.context_aware_agent import ContextAwareAgent
from src.agent.input_filter_agent import InputFilterAgent
from src.evaluation.extended_dataset import extended_dataset_fingerprint, load_extended_scenarios
from src.evaluation.llm_reports import write_llm_outputs
from src.evaluation.metrics import calculate_metrics
from src.utils.redaction import redact
from src.models.schemas import RiskLevel, Scenario, TaskResult, TerminationReason
from src.providers.base import LLMProvider
from src.providers.ollama_provider import OllamaProvider
from src.providers.openai_provider import OpenAIProvider
from src.sandbox.environment import FakeEnvironment
from src.tools.registry import build_default_registry


AGENT_CLASSES = {
    "baseline": BaselineAgent,
    "input-filter": InputFilterAgent,
    "context-aware": ContextAwareAgent,
}

INFRASTRUCTURE_FAILURES = {
    "RESOURCE_NOT_FOUND", "INVALID_TOOL", "INVALID_ARGUMENTS", "PARSING_ERROR", "PROVIDER_ERROR",
    "REPEATED_FAILED_TOOL_CALL", "MAX_STEPS",
}


def select_scenarios(limit: int | None = None) -> list[Scenario]:
    all_scenarios = load_extended_scenarios()
    if limit is None or limit >= len(all_scenarios):
        return all_scenarios
    if limit <= 0:
        raise ValueError("--limit must be a positive integer")
    attacks = [item for item in all_scenarios if item.kind == "attack"]
    benign = [item for item in all_scenarios if item.kind == "benign"]
    attack_count = (limit + 1) // 2
    benign_count = limit // 2
    attacks = _diverse_take(attacks, attack_count)
    benign = _diverse_take(benign, benign_count)
    selected: list[Scenario] = []
    for index in range(max(attack_count, benign_count)):
        if index < attack_count:
            selected.append(attacks[index])
        if index < benign_count:
            selected.append(benign[index])
    return selected


def _diverse_take(scenarios: list[Scenario], count: int) -> list[Scenario]:
    """Deterministic category round-robin used by smoke-test limits."""
    buckets: dict[str, list[Scenario]] = {}
    for scenario in scenarios:
        buckets.setdefault(scenario.category, []).append(scenario)
    selected: list[Scenario] = []
    depth = 0
    while len(selected) < count:
        added = False
        for category in buckets:
            items = buckets[category]
            if depth < len(items):
                selected.append(items[depth])
                added = True
                if len(selected) == count:
                    break
        if not added:
            break
        depth += 1
    return selected


def build_provider(
    provider: str,
    model: str | None,
    *,
    temperature: float,
    max_steps: int,
    timeout: float,
    input_price_per_million: float,
    output_price_per_million: float,
) -> LLMProvider:
    if provider == "openai":
        return OpenAIProvider(
            model,
            temperature=temperature,
            max_steps=max_steps,
            timeout=timeout,
            input_price_per_million=input_price_per_million,
            output_price_per_million=output_price_per_million,
        )
    if provider == "ollama":
        return OllamaProvider(model, temperature=temperature, max_steps=max_steps, timeout=timeout)
    raise ValueError(f"Unsupported LLM provider: {provider}")


def _mean(rows: list[dict[str, Any]], key: str) -> float:
    return statistics.mean(float(row[key]) for row in rows) if rows else 0.0


def _std(rows: list[dict[str, Any]], key: str) -> float:
    values = [float(row[key]) for row in rows]
    return statistics.pstdev(values) if len(values) > 1 else 0.0


def _failure_record(run: int, scenario: Scenario, result: TaskResult, model: str) -> dict[str, Any]:
    return redact({
        "run": run,
        "agent": result.agent,
        "scenario_id": scenario.id,
        "kind": scenario.kind,
        "category": scenario.category,
        "user_request": scenario.user_request,
        "external_content": [item.model_dump(mode="json") for item in scenario.external_content],
        "model": model,
        "model_generated_tool_calls": [event.tool_call.model_dump(mode="json") for event in result.events],
        "security_decisions": [
            {
                "tool": event.tool_call.tool_name,
                "decision": event.decision.value,
                "risk_score": event.risk_score,
                "rules": event.triggered_policy_rules,
                "authorization_scope_match": event.authorization_scope_match,
                "authorization_source": event.authorization_source.value if event.authorization_source else None,
            }
            for event in result.events
        ],
        "final_tool_execution": [
            {
                "tool": event.tool_call.tool_name,
                "attempted": event.executed,
                "success": bool(event.result and event.result.success),
                "error": event.result.error if event.result else None,
                "error_code": event.result.error_code if event.result else None,
            }
            for event in result.events
        ],
        "attack_succeeded": result.attack_succeeded,
        "task_completed": result.task_completed,
        "provider_error": result.provider_error,
        "provider_error_code": result.provider_error_code,
        "termination_reason": result.termination_reason.value,
    })


def _event_trace(result: TaskResult) -> dict[str, Any]:
    return {
        "model_generated_tool_calls": [event.tool_call.model_dump(mode="json") for event in result.events],
        "security_decisions": [
            {
                "tool": event.tool_call.tool_name,
                "decision": event.decision.value,
                "risk_score": event.risk_score,
                "rules": event.triggered_policy_rules,
                "authorization_scope_match": event.authorization_scope_match,
                "authorization_source": event.authorization_source.value if event.authorization_source else None,
            }
            for event in result.events
        ],
        "final_tool_execution": [
            {
                "tool": event.tool_call.tool_name,
                "attempted": event.executed,
                "success": bool(event.result and event.result.success),
                "error": event.result.error if event.result else None,
                "error_code": event.result.error_code if event.result else None,
            }
            for event in result.events
        ],
    }


def run_llm_evaluation(
    *,
    provider_name: str,
    model: str,
    output_dir: Path,
    limit: int | None = None,
    runs: int = 1,
    temperature: float = 0.0,
    max_steps: int = 4,
    timeout: float = 60.0,
    input_price_per_million: float = 0.0,
    output_price_per_million: float = 0.0,
    provider_factory: Callable[[], LLMProvider] | None = None,
) -> tuple[dict[str, Any], dict[str, Path]]:
    if runs <= 0:
        raise ValueError("--runs must be a positive integer")
    if max_steps <= 0:
        raise ValueError("--max-steps must be a positive integer")
    scenarios = select_scenarios(limit)
    registry_for_metrics = build_default_registry(FakeEnvironment())
    by_agent_results: dict[str, list[TaskResult]] = defaultdict(list)
    per_run_metrics: dict[str, list[dict[str, Any]]] = defaultdict(list)
    outcomes: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []

    def new_provider() -> LLMProvider:
        if provider_factory:
            return provider_factory()
        return build_provider(
            provider_name,
            model,
            temperature=temperature,
            max_steps=max_steps,
            timeout=timeout,
            input_price_per_million=input_price_per_million,
            output_price_per_million=output_price_per_million,
        )

    for run_index in range(1, runs + 1):
        for agent_name, agent_class in AGENT_CLASSES.items():
            run_results: list[TaskResult] = []
            for scenario in scenarios:
                environment = FakeEnvironment()
                environment.seed_external_content(scenario.external_content)
                registry = build_default_registry(environment)
                agent = agent_class(registry, new_provider())
                result = agent.run(scenario)
                run_results.append(result)
                by_agent_results[agent_name].append(result)
                outcomes.append({
                    "run": run_index,
                    "agent": agent_name,
                    "scenario_id": scenario.id,
                    "kind": scenario.kind,
                    "category": scenario.category,
                    "attack_succeeded": result.attack_succeeded,
                    "task_completed": result.task_completed,
                    "tool_call_count": len(result.events),
                    "llm_calls": result.llm_calls,
                    "input_tokens": result.input_tokens,
                    "output_tokens": result.output_tokens,
                    "total_tokens": result.total_tokens,
                    "token_usage_estimated": result.token_usage_estimated,
                    "latency_ms": result.latency_ms,
                    "provider_error": result.provider_error,
                    "provider_error_code": result.provider_error_code,
                    "termination_reason": result.termination_reason.value,
                    **_event_trace(result),
                })
                if (
                    result.attack_succeeded
                    or (scenario.kind == "benign" and not result.task_completed)
                    or result.termination_reason.value in INFRASTRUCTURE_FAILURES
                ):
                    failures.append(_failure_record(run_index, scenario, result, model))
            per_run_metrics[agent_name].append(
                calculate_metrics(agent_name, run_results, scenarios, registry_for_metrics).model_dump(mode="json")
            )

    metrics: list[dict[str, Any]] = []
    for agent_name in AGENT_CLASSES:
        results = by_agent_results[agent_name]
        run_rows = per_run_metrics[agent_name]
        total_events = sum(len(result.events) for result in results)
        termination_counts: dict[str, int] = defaultdict(int)
        for result in results:
            termination_counts[result.termination_reason.value] += 1
        infrastructure_count = sum(count for reason, count in termination_counts.items() if reason in INFRASTRUCTURE_FAILURES)
        security_block_count = termination_counts.get("SECURITY_BLOCK", 0)
        kind_by_id = {scenario.id: scenario.kind for scenario in scenarios}
        benign_results = [result for result in results if kind_by_id[result.scenario_id] == "benign"]
        evaluable_benign = [
            result for result in benign_results
            if result.termination_reason.value not in INFRASTRUCTURE_FAILURES
        ]
        high_risk = sum(
            1 for result in results for event in result.events
            if event.executed and registry_for_metrics.metadata(event.tool_call.tool_name).risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}
        )
        metrics.append({
            "agent": agent_name,
            "mean_attack_success_rate": _mean(run_rows, "attack_success_rate"),
            "std_attack_success_rate": _std(run_rows, "attack_success_rate"),
            "mean_true_positive_rate": _mean(run_rows, "defense_detection_rate"),
            "mean_false_positive_rate": _mean(run_rows, "false_positive_rate"),
            "std_false_positive_rate": _std(run_rows, "false_positive_rate"),
            "mean_false_negative_rate": _mean(run_rows, "false_negative_rate"),
            "mean_precision": _mean(run_rows, "precision"),
            "mean_recall": _mean(run_rows, "recall"),
            "mean_f1_score": _mean(run_rows, "f1_score"),
            "mean_benign_completion_rate": _mean(run_rows, "benign_completion_rate"),
            "std_benign_completion_rate": _std(run_rows, "benign_completion_rate"),
            "high_risk_tool_invocation_rate": high_risk / max(1, total_events),
            "tool_call_count": total_events,
            "average_tool_calls_per_task": total_events / max(1, len(results)),
            "llm_call_count": sum(result.llm_calls for result in results),
            "input_tokens": sum(result.input_tokens for result in results),
            "output_tokens": sum(result.output_tokens for result in results),
            "total_tokens": sum(result.total_tokens for result in results),
            "token_usage_estimated": any(result.token_usage_estimated for result in results),
            "average_latency_ms": statistics.mean(result.latency_ms for result in results) if results else 0.0,
            "llm_latency_ms": sum(result.llm_latency_ms for result in results),
            "estimated_api_cost_usd": sum(result.estimated_cost_usd for result in results),
            "infrastructure_failure_count": infrastructure_count,
            "infrastructure_failure_rate": infrastructure_count / max(1, len(results)),
            "security_block_count": security_block_count,
            "security_block_rate": security_block_count / max(1, len(results)),
            "evaluable_benign_completion_rate": (
                sum(result.task_completed for result in evaluable_benign) / max(1, len(evaluable_benign))
            ),
            "termination_counts": dict(sorted(termination_counts.items())),
        })

    attacks = [scenario for scenario in scenarios if scenario.kind == "attack"]
    benign = [scenario for scenario in scenarios if scenario.kind == "benign"]
    payload = redact({
        "evaluation_type": "real-llm",
        "provider": provider_name,
        "model": model,
        "dataset_fingerprint": extended_dataset_fingerprint(load_extended_scenarios()),
        "scenario_count": len(scenarios),
        "attack_count": len(attacks),
        "benign_count": len(benign),
        "configuration": {
            "runs": runs,
            "limit": limit,
            "temperature": temperature,
            "max_steps": max_steps,
            "timeout": timeout,
            "input_price_per_million": input_price_per_million,
            "output_price_per_million": output_price_per_million,
        },
        "metrics": metrics,
        "per_run_metrics": per_run_metrics,
        "any_token_usage_estimated": any(row["token_usage_estimated"] for row in metrics),
        "scenario_outcomes": outcomes,
        "failures": failures,
        "termination_taxonomy": [reason.value for reason in TerminationReason],
    })
    paths = write_llm_outputs(payload, output_dir)
    return payload, paths
