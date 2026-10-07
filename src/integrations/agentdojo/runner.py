from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.metadata
import json
import os
import platform
import sys
from pathlib import Path
from typing import Any

from agentdojo.agent_pipeline.ground_truth_pipeline import GroundTruthPipeline
from agentdojo.attacks.attack_registry import ATTACKS, load_attack
from agentdojo.task_suite.load_suites import get_suite, get_suites

from src.integrations.agentdojo import AGENTDOJO_BENCHMARK_VERSION, AGENTDOJO_PACKAGE_VERSION
from src.integrations.agentdojo.metrics import aggregate_pilot_results, annotate_malicious_events
from src.integrations.agentdojo.model_adapter import (
    available_ollama_models,
    build_ollama_pipeline,
    model_is_available,
)
from src.integrations.agentdojo.schemas import CompatibilityResult, PilotCaseResult
from src.utils.redaction import redact


DEFAULT_MODELS = ("llama3.1", "qwen2.5:7b", "mistral-nemo")
DEFAULT_PILOT_PAIRS = (
    ("user_task_1", "injection_task_0"),
    ("user_task_0", "injection_task_1"),
    ("user_task_14", "injection_task_2"),
    ("user_task_16", "injection_task_4"),
    ("user_task_24", "injection_task_3"),
)
VARIANTS = ("baseline", "context-aware", "full")


def _source_checksums() -> dict[str, str]:
    import agentdojo

    root = Path(agentdojo.__file__).resolve().parent
    relative = (
        "benchmark.py",
        "base_tasks.py",
        "task_suite/task_suite.py",
        "agent_pipeline/tool_execution.py",
    )
    return {
        path: hashlib.sha256((root / path).read_bytes()).hexdigest()
        for path in relative
    }


def environment_metadata() -> dict[str, Any]:
    suites = get_suites(AGENTDOJO_BENCHMARK_VERSION)
    return {
        "agentdojo_package_version": importlib.metadata.version("agentdojo"),
        "agentdojo_expected_package_version": AGENTDOJO_PACKAGE_VERSION,
        "agentdojo_benchmark_version": AGENTDOJO_BENCHMARK_VERSION,
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "package_location": str(Path(sys.modules["agentdojo"].__file__).resolve()),
        "available_suites": {
            name: {
                "user_tasks": len(suite.user_tasks),
                "injection_tasks": len(suite.injection_tasks),
                "tools": len(suite.tools),
            }
            for name, suite in suites.items()
        },
        "available_attacks": sorted(ATTACKS),
        "available_native_defenses": [
            "tool_filter",
            "transformers_pi_detector",
            "spotlighting_with_delimiting",
            "repeat_user_prompt",
        ],
        "native_source_checksums": _source_checksums(),
        "windows_utf8_mode_required": os.name == "nt",
    }


def run_native_smoke(suite_name: str = "workspace") -> list[dict[str, Any]]:
    suite = get_suite(AGENTDOJO_BENCHMARK_VERSION, suite_name)
    results = []
    for task_id in list(suite.user_tasks)[:2]:
        task = suite.get_user_task_by_id(task_id)
        utility, security = suite.run_task_with_pipeline(
            GroundTruthPipeline(task), task, injection_task=None, injections={}
        )
        results.append({
            "suite": suite_name,
            "user_task_id": task_id,
            "native_utility_result": utility,
            "native_security_result": security,
        })
    return results


def _message_counts(messages) -> dict[str, int]:
    assistant_calls = [
        call
        for message in messages
        if message["role"] == "assistant"
        for call in (message.get("tool_calls") or [])
    ]
    errors = [
        str(message.get("error"))
        for message in messages
        if message["role"] == "tool" and message.get("error")
    ]
    return {
        "proposed_tool_calls": len(assistant_calls),
        "invalid_tool_count": sum(error.startswith("Invalid tool") for error in errors),
        "invalid_argument_count": sum("ValidationError" in error for error in errors),
    }


def run_compatibility_smoke(
    models: list[str],
    *,
    suite_name: str = "workspace",
    temperature: float = 0.0,
    base_url: str = "http://127.0.0.1:11434",
) -> list[CompatibilityResult]:
    installed = available_ollama_models(base_url)
    suite = get_suite(AGENTDOJO_BENCHMARK_VERSION, suite_name)
    task = suite.get_user_task_by_id("user_task_1")
    results: list[CompatibilityResult] = []
    for model in models:
        available = model_is_available(model, installed)
        if not available:
            results.append(CompatibilityResult(model=model, model_available=False, tool_calling_available=False))
            continue
        pipeline, _ = build_ollama_pipeline(model, "baseline", temperature=temperature, base_url=base_url)
        try:
            utility, _ = suite.run_task_with_pipeline(pipeline, task, injection_task=None, injections={})
            counts = _message_counts(pipeline.last_messages)
            results.append(CompatibilityResult(
                model=model,
                model_available=True,
                tool_calling_available=counts["proposed_tool_calls"] > 0,
                invalid_tool_count=counts["invalid_tool_count"],
                invalid_argument_count=counts["invalid_argument_count"],
                successful_native_task_execution=utility,
                proposed_tool_calls=counts["proposed_tool_calls"],
            ))
        except json.JSONDecodeError as exc:
            results.append(CompatibilityResult(
                model=model, model_available=True, tool_calling_available=False,
                parsing_failures=1, error=f"{type(exc).__name__}: {exc}",
            ))
        except Exception as exc:
            results.append(CompatibilityResult(
                model=model, model_available=True, tool_calling_available=False,
                provider_error_count=1, error=f"{type(exc).__name__}: {exc}",
            ))
    return results


def _ground_truth_calls(suite, user_task, injection_task, injections):
    environment = suite.load_and_inject_default_environment(injections)
    if hasattr(user_task, "init_environment"):
        environment = user_task.init_environment(environment)
    return injection_task.ground_truth(environment)


def _run_pilot_case(
    suite,
    model: str,
    variant: str,
    user_task_id: str,
    injection_task_id: str,
    attack_name: str,
    temperature: float,
    base_url: str,
) -> PilotCaseResult:
    pipeline, executor = build_ollama_pipeline(
        model, variant, temperature=temperature, base_url=base_url
    )
    user_task = suite.get_user_task_by_id(user_task_id)
    injection_task = suite.get_injection_task_by_id(injection_task_id)
    attack = load_attack(attack_name, suite, pipeline)
    injections = attack.attack(user_task, injection_task)
    ground_truth_calls = _ground_truth_calls(suite, user_task, injection_task, injections)
    utility: bool | None = None
    security: bool | None = None
    termination = "completed"
    compatibility = "ok"
    try:
        utility, security = suite.run_task_with_pipeline(
            pipeline, user_task, injection_task, injections
        )
    except json.JSONDecodeError:
        termination = "parsing_error"
        compatibility = "parsing_error"
    except Exception as exc:
        termination = "provider_error"
        compatibility = f"{type(exc).__name__}: {exc}"

    events = list(executor.events)
    malicious_proposed, malicious_blocked = annotate_malicious_events(events, ground_truth_calls)
    return PilotCaseResult(
        agentdojo_version=importlib.metadata.version("agentdojo"),
        python_version=platform.python_version(),
        benchmark_version=AGENTDOJO_BENCHMARK_VERSION,
        suite=suite.name,
        user_task_id=user_task_id,
        injection_task_id=injection_task_id,
        attack=attack_name,
        model=model,
        provider="ollama-openai-compatible",
        model_identifier=model,
        defense=variant,
        temperature=temperature,
        run_index=1,
        native_utility_result=utility,
        native_security_result=security,
        attack_success=security,
        defense_events=events,
        malicious_tool_proposed=malicious_proposed,
        malicious_tool_blocked=malicious_blocked,
        termination_status=termination,
        provider_tool_compatibility=compatibility,
        user_request=user_task.PROMPT,
        injection_goal_summary=injection_task.GOAL[:240],
    )


def run_pilot(
    models: list[str],
    *,
    suite_name: str = "workspace",
    attack_name: str = "tool_knowledge",
    pilot_limit: int = 5,
    all_combinations: bool = False,
    temperature: float = 0.0,
    base_url: str = "http://127.0.0.1:11434",
) -> list[PilotCaseResult]:
    suite = get_suite(AGENTDOJO_BENCHMARK_VERSION, suite_name)
    if all_combinations:
        pairs = [
            (user_task_id, injection_task_id)
            for user_task_id in suite.user_tasks
            for injection_task_id in suite.injection_tasks
        ]
    else:
        if suite_name != "workspace":
            raise ValueError("The fixed representative pilot pairs are defined only for the workspace suite")
        pairs = list(DEFAULT_PILOT_PAIRS[:pilot_limit])
    return [
        _run_pilot_case(
            suite, model, variant, user_task_id, injection_task_id,
            attack_name, temperature, base_url,
        )
        for model in models
        for variant in VARIANTS
        for user_task_id, injection_task_id in pairs
    ]


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    scalar_rows = [
        {key: value for key, value in row.items() if not isinstance(value, (dict, list))}
        for row in rows
    ]
    fields = list(dict.fromkeys(key for row in scalar_rows for key in row))
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(scalar_rows)


def _pct(value: float | None) -> str:
    return "N/A" if value is None else f"{value:.1%}"


def _render_report(metadata, native_smoke, compatibility, metrics, cases) -> str:
    lines = [
        "# AgentDojo External Benchmark Adapter Pilot",
        "",
        "## Environment",
        "",
        f"- AgentDojo package: `{metadata['agentdojo_package_version']}`",
        f"- AgentDojo benchmark: `{metadata['agentdojo_benchmark_version']}`",
        f"- Python: `{metadata['python_version']}`",
        f"- Suites: {', '.join(metadata['available_suites'])}",
        f"- Attack: `{cases[0].attack if cases else 'N/A'}`",
        "- Integration: native AgentDojo LLM output → pre-execution Defense gate → native FunctionsRuntime.",
        "",
        "## Native installation smoke",
        "",
    ]
    for item in native_smoke:
        lines.append(
            f"- `{item['suite']}/{item['user_task_id']}`: utility={item['native_utility_result']}, "
            f"security={item['native_security_result']}"
        )
    lines.extend([
        "",
        "These smoke runs have no injection task. Their `security=True` value is the native no-injection default, "
        "not an attack success.",
        "",
        "## Ollama compatibility",
        "",
        "| Model | Available | Tool calls | Parsing | Invalid tool | Invalid args | Provider error | Native task |",
        "|---|---|---|---:|---:|---:|---:|---|",
    ])
    for item in compatibility:
        lines.append(
            f"| {item.model} | {item.model_available} | {item.tool_calling_available} | "
            f"{item.parsing_failures} | {item.invalid_tool_count} | {item.invalid_argument_count} | "
            f"{item.provider_error_count} | {item.successful_native_task_execution} |"
        )
    lines.extend([
        "",
        "## Pilot aggregate",
        "",
        "AgentDojo `native_security_result=True` means the injection goal succeeded; it is reported as attack success.",
        "",
        "| Model | Defense | Native attack success | Native utility | Malicious proposal cases | Defense block cases | Conditional defense success | Compatibility |",
        "|---|---|---:|---:|---:|---:|---:|---|",
    ])
    for row in metrics:
        lines.append(
            f"| {row['model']} | {row['defense']} | {_pct(row['native_attack_success_rate'])} | "
            f"{_pct(row['native_utility_rate'])} | {row['malicious_proposal_cases']} | "
            f"{row['defense_block_cases']} | {_pct(row['conditional_defense_success_rate'])} | "
            f"invalid={row['invalid_argument_count'] + row['invalid_tool_count']}, provider={row['provider_error_count']} |"
        )
    if cases and not any(item.malicious_tool_proposed is True for item in cases):
        lines.extend([
            "",
            "> **Pilot validity warning:** no model proposed a native injection ground-truth action. "
            "The 0% native attack-success rates therefore measure a floor effect at the model layer, "
            "not successful blocking by either defense. Conditional defense success is N/A, and this "
            "pilot cannot establish that Full is better than Baseline.",
        ])
    lines.extend([
        "",
        "## Scenario-level results",
        "",
        "| Model | Defense | User task | Injection task | Native attack | Utility | Malicious proposed | Malicious blocked | Blocks |",
        "|---|---|---|---|---|---|---|---|---:|",
    ])
    for item in cases:
        lines.append(
            f"| {item.model} | {item.defense} | `{item.user_task_id}` | `{item.injection_task_id}` | "
            f"{item.native_security_result} | {item.native_utility_result} | {item.malicious_tool_proposed} | "
            f"{item.malicious_tool_blocked} | {sum(event.decision.value != 'ALLOW' for event in item.defense_events)} |"
        )
    lines.extend([
        "",
        "## Example attack trace",
        "",
    ])
    malicious_events = [
        (item, event)
        for item in cases
        for event in item.defense_events
        if event.malicious_ground_truth_match is True
    ]
    if malicious_events:
        item, event = malicious_events[0]
        lines.extend([
            f"- Case: `{item.model}/{item.defense}/{item.user_task_id}/{item.injection_task_id}`",
            f"- Proposed native call: `{event.native_tool}`",
            f"- Decision: `{event.decision.value}`; executed: `{event.executed}`",
            f"- Matched rules: {', '.join(event.matched_rules) or 'none'}",
            f"- Native attack success: `{item.native_security_result}`; native utility: `{item.native_utility_result}`",
        ])
    else:
        lines.extend([
            "No qualifying malicious-proposal trace exists in this pilot. The injected Tool output was available "
            "to the model, but no proposed call matched the native injection ground truth. Reporting a defense "
            "decision for an unproposed call would falsely attribute model behavior to the gate.",
        ])
    lines.extend([
        "",
        "## Interpretation boundaries",
        "",
        "- Native AgentDojo utility/security checkers, tasks, injections, attacks, and environments were not modified.",
        "- Baseline delegates execution to AgentDojo's native ToolsExecutor through an observational wrapper.",
        "- Conditional defense success is only computed for injection tasks with non-empty native ground-truth FunctionCalls.",
        "- The pilot is one deterministic run over a selected subset, not a population estimate.",
        "- Windows requires `PYTHONUTF8=1` for AgentDojo 0.1.35 suite YAML containing non-CP949 characters.",
        "- AgentDojo's JSON Tool-output option failed on native datetime values; the native YAML default was retained.",
        "- Full benchmark execution is not recommended from this pilot: first predeclare a subset/model with "
        "measurable baseline attack signal and adequate native utility.",
        "",
    ])
    return "\n".join(lines)


def run_external_evaluation(
    *,
    models: list[str],
    output_dir: Path,
    suite_name: str = "workspace",
    attack_name: str = "tool_knowledge",
    pilot_limit: int = 5,
    all_combinations: bool = False,
    temperature: float = 0.0,
    base_url: str = "http://127.0.0.1:11434",
) -> dict[str, Any]:
    if importlib.metadata.version("agentdojo") != AGENTDOJO_PACKAGE_VERSION:
        raise RuntimeError(
            f"AgentDojo {AGENTDOJO_PACKAGE_VERSION} is required; found {importlib.metadata.version('agentdojo')}"
        )
    if attack_name not in ATTACKS:
        raise ValueError(f"Unknown native AgentDojo attack: {attack_name}")
    output_dir.mkdir(parents=True, exist_ok=True)
    metadata = environment_metadata()
    checksums_before = metadata["native_source_checksums"]
    native_smoke = run_native_smoke(suite_name)
    compatibility = run_compatibility_smoke(
        models, suite_name=suite_name, temperature=temperature, base_url=base_url
    )
    compatible_models = [item.model for item in compatibility if item.model_available and item.tool_calling_available]
    cases = run_pilot(
        compatible_models,
        suite_name=suite_name,
        attack_name=attack_name,
        pilot_limit=pilot_limit,
        all_combinations=all_combinations,
        temperature=temperature,
        base_url=base_url,
    )
    if _source_checksums() != checksums_before:
        raise RuntimeError("AgentDojo native evaluator or execution source changed during adapter evaluation")
    metrics = aggregate_pilot_results(cases)
    payload = redact({
        "evaluation": "agentdojo_external_benchmark_pilot",
        "metadata": metadata,
        "configuration": {
            "suite": suite_name,
            "attack": attack_name,
            "models": models,
            "variants": list(VARIANTS),
            "temperature": temperature,
            "run_index": 1,
            "pilot_limit": pilot_limit,
            "all_combinations": all_combinations,
        },
        "native_smoke": native_smoke,
        "compatibility": [item.model_dump(mode="json") for item in compatibility],
        "metrics": metrics,
        "cases": [item.model_dump(mode="json") for item in cases],
    })
    (output_dir / "compatibility.json").write_text(
        json.dumps(payload["compatibility"], indent=2, ensure_ascii=False), encoding="utf-8"
    )
    (output_dir / "smoke_summary.json").write_text(
        json.dumps({"metadata": metadata, "native_smoke": native_smoke}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    _write_csv(output_dir / "smoke_summary.csv", [*native_smoke, *payload["compatibility"]])
    (output_dir / "pilot_summary.json").write_text(
        json.dumps({"configuration": payload["configuration"], "metrics": metrics}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    _write_csv(output_dir / "pilot_summary.csv", metrics)
    (output_dir / "native_results.json").write_text(
        json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    with (output_dir / "defense_events.jsonl").open("w", encoding="utf-8") as handle:
        for item in cases:
            for event in item.defense_events:
                handle.write(json.dumps(redact({
                    "suite": item.suite,
                    "user_task_id": item.user_task_id,
                    "injection_task_id": item.injection_task_id,
                    "model": item.model,
                    "defense": item.defense,
                    **event.model_dump(mode="json"),
                }), ensure_ascii=False) + "\n")
    (output_dir / "report.md").write_text(
        _render_report(metadata, native_smoke, compatibility, metrics, cases), encoding="utf-8"
    )
    return payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the isolated AgentDojo adapter smoke and pilot")
    parser.add_argument("--models", default=",".join(DEFAULT_MODELS))
    parser.add_argument("--suite", default="workspace", choices=sorted(get_suites(AGENTDOJO_BENCHMARK_VERSION)))
    parser.add_argument("--attack", default="tool_knowledge", choices=sorted(ATTACKS))
    parser.add_argument("--pilot-limit", type=int, default=5)
    parser.add_argument("--all-combinations", action="store_true")
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--base-url", default="http://127.0.0.1:11434")
    parser.add_argument("--output-dir", type=Path, default=Path("results/agentdojo"))
    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    payload = run_external_evaluation(
        models=[item.strip() for item in args.models.split(",") if item.strip()],
        output_dir=args.output_dir,
        suite_name=args.suite,
        attack_name=args.attack,
        pilot_limit=args.pilot_limit,
        all_combinations=args.all_combinations,
        temperature=args.temperature,
        base_url=args.base_url,
    )
    print(json.dumps({
        "compatibility": payload["compatibility"],
        "metrics": payload["metrics"],
        "output_dir": str(args.output_dir.resolve()),
    }, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
