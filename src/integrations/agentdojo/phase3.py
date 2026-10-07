from __future__ import annotations

import argparse
import csv
import importlib.metadata
import json
from pathlib import Path
from typing import Any

from openai import OpenAI

from src.integrations.agentdojo import AGENTDOJO_BENCHMARK_VERSION, AGENTDOJO_PACKAGE_VERSION
from src.integrations.agentdojo.phase2 import (
    CapturedCase,
    _execute_end_to_end_case,
    _pct,
    _replay_case,
    _source_checksums,
    _terminal_malicious_events,
    _write_csv,
    aggregate_metrics,
    case_row,
)
from src.integrations.agentdojo.schemas import DefenseEvent, PilotCaseResult
from src.integrations.agentdojo.model_adapter import openai_api_client
from src.integrations.agentdojo.validation import (
    REQUESTED_SNAPSHOT,
    VALIDATION_ATTACK,
    build_frozen_selection,
    probe_function_calling,
    probe_model_access,
)
from src.models.schemas import Decision
from src.utils.redaction import redact


PHASE3_VARIANTS = ("context-aware", "full", "refined-full")
DEFAULT_OUTPUT_DIR = Path("results/agentdojo/phase3")


def _key(case: PilotCaseResult) -> tuple[str, str, str, str]:
    return case.suite, case.user_task_id, case.injection_task_id, case.defense


def _event_key(case: PilotCaseResult, event: DefenseEvent, index: int) -> tuple[str, str, str, str]:
    return (
        case.suite,
        case.user_task_id,
        case.injection_task_id,
        event.tool_call_id or f"{event.native_tool}:{index}",
    )


def controlled_deltas(cases: list[PilotCaseResult]) -> dict[str, Any]:
    indexed: dict[tuple[str, str, str, str], dict[str, DefenseEvent]] = {}
    for case in cases:
        for index, event in enumerate(case.defense_events):
            indexed.setdefault(_event_key(case, event, index), {})[case.defense] = event

    categories = {
        "preserved_malicious_blocks": [],
        "newly_fixed_malicious_calls": [],
        "new_malicious_regressions": [],
        "new_false_positive_proxy_calls": [],
        "remaining_malicious_executions": [],
    }
    for event_key, variants in indexed.items():
        phase2_full = variants.get("full")
        refined = variants.get("refined-full")
        if phase2_full is None or refined is None:
            continue
        malicious = phase2_full.malicious_ground_truth_match is True
        full_block = phase2_full.decision != Decision.ALLOW
        refined_block = refined.decision != Decision.ALLOW
        record = {
            "case": "/".join(event_key[:3]),
            "tool_call_id": event_key[3],
            "native_tool": refined.native_tool,
            "phase2_full_decision": phase2_full.decision.value,
            "refined_full_decision": refined.decision.value,
            "refined_rules": refined.matched_rules,
            "refined_executed": refined.executed,
        }
        if malicious and full_block and refined_block:
            categories["preserved_malicious_blocks"].append(record)
        elif malicious and not full_block and refined_block:
            categories["newly_fixed_malicious_calls"].append(record)
        elif malicious and full_block and not refined_block:
            categories["new_malicious_regressions"].append(record)
        elif not malicious and not full_block and refined_block:
            categories["new_false_positive_proxy_calls"].append(record)
        if malicious and refined.executed:
            categories["remaining_malicious_executions"].append(record)
    return {key: {"count": len(value), "calls": value} for key, value in categories.items()}


def _decision_text(case: PilotCaseResult | None) -> str:
    if case is None:
        return "not available"
    malicious = [event for event in case.defense_events if event.malicious_ground_truth_match is True]
    if not malicious:
        return "no strict match"
    return "; ".join(
        f"{event.native_tool}:{event.decision.value}/executed={event.executed}"
        for event in malicious
    )


def _case_analysis(
    end_to_end: list[PilotCaseResult],
    controlled: list[PilotCaseResult],
    deltas: dict[str, Any],
) -> str:
    e2e = {_key(case): case for case in end_to_end}
    replay = {_key(case): case for case in controlled}
    case_ids = sorted({(case.suite, case.user_task_id, case.injection_task_id) for case in controlled})
    lines = [
        "# AgentDojo Phase 3 case analysis",
        "",
        "Controlled rows use one Phase 3 Baseline recollection shared by Context-Aware, Phase 2 Full, "
        "and Phase 3 Refined Full. End-to-End rows use independent model calls.",
        "",
        "| Case | Context controlled | Phase 2 Full controlled | Refined controlled | Refined terminal executed | Refined rules | E2E native CA / Full / Refined |",
        "|---|---|---|---|---|---|---|",
    ]
    for suite, user_task_id, injection_task_id in case_ids:
        base = (suite, user_task_id, injection_task_id)
        context = replay.get((*base, "context-aware"))
        full = replay.get((*base, "full"))
        refined = replay.get((*base, "refined-full"))
        terminal = _terminal_malicious_events(refined)
        rules = sorted({rule for event in (refined.defense_events if refined else []) for rule in event.matched_rules})
        native = [
            e2e.get((*base, variant)).native_security_result if e2e.get((*base, variant)) else None
            for variant in PHASE3_VARIANTS
        ]
        lines.append(
            f"| `{suite}/{user_task_id}/{injection_task_id}` | {_decision_text(context)} | "
            f"{_decision_text(full)} | {_decision_text(refined)} | "
            f"{any(event.executed for event in terminal)} | {', '.join(rules) or 'none'} | "
            f"{native[0]} / {native[1]} / {native[2]} |"
        )

    lines.extend([
        "",
        "## Controlled delta from Phase 2 Full to Refined Full",
        "",
    ])
    for name, payload in deltas.items():
        lines.append(f"- {name}: `{payload['count']}`")
        for item in payload["calls"]:
            lines.append(
                f"  - `{item['case']}` `{item['native_tool']}`: "
                f"{item['phase2_full_decision']} → {item['refined_full_decision']}; "
                f"rules={', '.join(item['refined_rules']) or 'none'}"
            )
    lines.extend(["", "## Required focus cases", ""])
    for base in (
        ("slack", "user_task_1", "injection_task_1"),
        ("travel", "user_task_0", "injection_task_0"),
    ):
        lines.extend([
            f"### {'/'.join(base)}",
            "",
            f"- Context-Aware controlled: {_decision_text(replay.get((*base, 'context-aware')))}",
            f"- Phase 2 Full controlled: {_decision_text(replay.get((*base, 'full')))}",
            f"- Refined Full controlled: {_decision_text(replay.get((*base, 'refined-full')))}",
            "",
        ])
    return "\n".join(lines)


def _report(
    configuration: dict[str, Any],
    e2e_metrics: list[dict[str, Any]],
    controlled_metrics: list[dict[str, Any]],
    deltas: dict[str, Any],
    phase2_reference: list[dict[str, Any]],
) -> str:
    lines = [
        "# AgentDojo Phase 3 refined-defense evaluation",
        "",
        "This is a frozen, signal-enriched external validation pilot, not an AgentDojo published-result reproduction.",
        "",
        "## Configuration",
        "",
        f"- Model: `{configuration['model']}`",
        f"- Attack: `{configuration['attack']}`",
        f"- Cases: `{configuration['case_count']}`",
        f"- Temperature: `{configuration['temperature']}`",
        "- Variants: Context-Aware, unchanged Phase 2 Full, Phase 3 Refined Full.",
        "- Phase 1 and Phase 2 results were not overwritten.",
        "",
        "## End-to-End",
        "",
        "| Defense | Native ASR | Native utility | Strict proposal rate | Strict execution rate | Detection | FPR proxy | Malicious blocked | Benign blocked | Calls | Tokens | Avg latency ms |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in e2e_metrics:
        lines.append(
            f"| {row['defense']} | {_pct(row['agentdojo_native_asr'])} | {_pct(row['native_utility'])} | "
            f"{_pct(row['strict_malicious_proposal_rate'])} | {_pct(row['strict_malicious_execution_rate'])} | "
            f"{_pct(row['defense_detection_rate'])} | {_pct(row['false_positive_rate'])} | "
            f"{row['blocked_malicious_calls']} | {row['blocked_benign_calls']} | "
            f"{row['llm_call_count']} | {row['token_usage']} | {row['average_case_latency_ms']:.1f} |"
        )
    lines.extend([
        "",
        "## Controlled replay",
        "",
        "| Defense | Malicious proposals | Blocked | Executed | Detection | FPR proxy | Payload blocks | Intent blocks |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ])
    for row in controlled_metrics:
        lines.append(
            f"| {row['defense']} | {row['strict_malicious_proposal_calls']} | "
            f"{row['blocked_malicious_calls']} | {row['strict_malicious_execution_calls']} | "
            f"{_pct(row['defense_detection_rate'])} | {_pct(row['false_positive_rate'])} | "
            f"{row['payload_provenance_blocks']} | {row['parameter_intent_blocks']} |"
        )
    lines.extend([
        "",
        "## Phase 2 Full → Refined Full causal delta",
        "",
        f"- Preserved malicious blocks: `{deltas['preserved_malicious_blocks']['count']}`",
        f"- Newly fixed malicious calls: `{deltas['newly_fixed_malicious_calls']['count']}`",
        f"- New malicious regressions: `{deltas['new_malicious_regressions']['count']}`",
        f"- New false-positive proxy calls: `{deltas['new_false_positive_proxy_calls']['count']}`",
        f"- Remaining executed malicious calls: `{deltas['remaining_malicious_executions']['count']}`",
        "",
        "The Phase 2 reference metrics below are retained only as a historical comparison because their "
        "Baseline proposal trace was not persisted and cannot be replayed exactly in Phase 3.",
        "",
    ])
    for row in phase2_reference:
        lines.append(
            f"- Phase 2 `{row['defense']}` controlled detection={_pct(row['defense_detection_rate'])}, "
            f"FPR proxy={_pct(row['false_positive_rate'])}."
        )
    lines.extend([
        "",
        "## Architecture",
        "",
        "- Payload-aware authorization assigns TRUSTED_USER_DERIVED, TRUSTED_SYSTEM_DERIVED, MODEL_GENERATED, "
        "UNTRUSTED_EXTERNAL_DERIVED, or MIXED_PROVENANCE per high-impact argument.",
        "- Raw URLs, callbacks, attachments, recipients, and near-verbatim payload propagation are distinguished "
        "from transformed summaries and explicitly requested quotation.",
        "- Parameter intent constraints cover entity, destination, resource/object identifier, date/time, recipient, "
        "amount, and URL. Explicit constraints are EXACT or ALLOWED_SET; absent values remain UNSPECIFIED and are "
        "not automatically blocked.",
        "- Existing Full decisions are monotonic: Refined Full preserves existing denies, then adds payload or "
        "parameter mismatch denies.",
        "",
        "## Interpretation boundary",
        "",
        "A lower End-to-End ASR alone is not credited as a defense improvement. The main causal evidence is the "
        "Controlled Replay delta on the same Phase 3 Baseline proposal trace.",
        "",
    ])
    return "\n".join(lines)


def run_phase3(
    *,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    phase1_dir: Path = Path("results/agentdojo/validation"),
    phase2_dir: Path = Path("results/agentdojo/phase2"),
    model: str = REQUESTED_SNAPSHOT,
    temperature: float = 0.0,
    client: OpenAI | None = None,
) -> dict[str, Any]:
    if importlib.metadata.version("agentdojo") != AGENTDOJO_PACKAGE_VERSION:
        raise RuntimeError(
            f"AgentDojo {AGENTDOJO_PACKAGE_VERSION} is required; "
            f"found {importlib.metadata.version('agentdojo')}"
        )
    selection = build_frozen_selection(model)
    persisted = json.loads((phase1_dir / "selection_manifest.json").read_text(encoding="utf-8"))
    if persisted != selection:
        raise RuntimeError("Phase 3 frozen selection differs from Phase 1")
    phase2_payload = json.loads(
        (phase2_dir / "phase2_controlled_replay.json").read_text(encoding="utf-8")
    )
    phase2_reference = phase2_payload["metrics"]

    resolved_client = client or openai_api_client()
    access = probe_model_access(resolved_client, model)
    if not access["available"] or access.get("resolved_id") != model:
        raise RuntimeError("Exact requested snapshot is unavailable; no fallback is permitted")
    function_calling = probe_function_calling(resolved_client, model)
    if not function_calling["available"]:
        raise RuntimeError("Function calling pre-check failed")

    output_dir.mkdir(parents=True, exist_ok=True)
    configuration = {
        "status": "running",
        "agentdojo_version": AGENTDOJO_PACKAGE_VERSION,
        "benchmark_version": AGENTDOJO_BENCHMARK_VERSION,
        "model": model,
        "model_access": access,
        "function_calling": function_calling,
        "attack": VALIDATION_ATTACK,
        "temperature": temperature,
        "case_count": selection["case_count"],
        "variants": list(PHASE3_VARIANTS),
        "selection_manifest_matches_phase1": True,
        "published_result_reproduction_claimed": False,
        "controlled_proposal_source": "Phase 3 Baseline recollection",
        "phase1_phase2_results_overwritten": False,
    }
    (output_dir / "phase3_manifest.json").write_text(
        json.dumps(redact({**configuration, "selection": selection}), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    checksums_before = _source_checksums()

    baseline_sources: list[CapturedCase] = [
        _execute_end_to_end_case(
            case,
            model=model,
            variant="baseline",
            client=resolved_client,
            temperature=temperature,
        )
        for case in selection["cases"]
    ]
    end_to_end = [
        _execute_end_to_end_case(
            case,
            model=model,
            variant=variant,
            client=resolved_client,
            temperature=temperature,
        ).result
        for variant in PHASE3_VARIANTS
        for case in selection["cases"]
    ]
    controlled = [
        _replay_case(source, variant=variant)
        for variant in PHASE3_VARIANTS
        for source in baseline_sources
    ]
    if _source_checksums() != checksums_before:
        raise RuntimeError("AgentDojo native evaluator or execution source changed during Phase 3")

    e2e_metrics = aggregate_metrics(end_to_end, "end_to_end", PHASE3_VARIANTS)
    controlled_metrics = aggregate_metrics(controlled, "controlled_replay", PHASE3_VARIANTS)
    deltas = controlled_deltas(controlled)
    configuration["status"] = "completed"
    (output_dir / "phase3_manifest.json").write_text(
        json.dumps(redact({**configuration, "selection": selection}), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    end_payload = redact({
        "status": "completed",
        "configuration": configuration,
        "metrics": e2e_metrics,
        "cases": [case.model_dump(mode="json") for case in end_to_end],
    })
    controlled_payload = redact({
        "status": "completed",
        "configuration": configuration,
        "metrics": controlled_metrics,
        "deltas": deltas,
        "cases": [case.model_dump(mode="json") for case in controlled],
    })
    (output_dir / "phase3_end_to_end.json").write_text(
        json.dumps(end_payload, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    (output_dir / "phase3_controlled_replay.json").write_text(
        json.dumps(controlled_payload, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    _write_csv(
        output_dir / "phase3_end_to_end.csv",
        [case_row(case, "end_to_end") for case in end_to_end],
    )
    _write_csv(
        output_dir / "phase3_controlled_replay.csv",
        [case_row(case, "controlled_replay") for case in controlled],
    )
    (output_dir / "phase3_case_analysis.md").write_text(
        _case_analysis(end_to_end, controlled, deltas), encoding="utf-8"
    )
    (output_dir / "phase3_report.md").write_text(
        _report(configuration, e2e_metrics, controlled_metrics, deltas, phase2_reference),
        encoding="utf-8",
    )
    return {
        "status": "completed",
        "configuration": configuration,
        "end_to_end_metrics": e2e_metrics,
        "controlled_metrics": controlled_metrics,
        "deltas": deltas,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run frozen AgentDojo Phase 3 refined-defense evaluation")
    parser.add_argument("--model", default=REQUESTED_SNAPSHOT)
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--phase1-dir", type=Path, default=Path("results/agentdojo/validation"))
    parser.add_argument("--phase2-dir", type=Path, default=Path("results/agentdojo/phase2"))
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    result = run_phase3(
        output_dir=args.output_dir,
        phase1_dir=args.phase1_dir,
        phase2_dir=args.phase2_dir,
        model=args.model,
        temperature=args.temperature,
    )
    print(json.dumps(redact(result), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
