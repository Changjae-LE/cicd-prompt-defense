from __future__ import annotations

import json

import pytest

pytest.importorskip("agentdojo")

from openai import OpenAI

from src.integrations.agentdojo.defense_gate import RecordingToolsExecutor
from src.integrations.agentdojo.model_adapter import build_openai_pipeline
from src.integrations.agentdojo.schemas import DefenseEvent, OperationType, PilotCaseResult
from src.integrations.agentdojo.validation import (
    OFFICIAL_POSITIVE_CONTROL,
    REQUESTED_SNAPSHOT,
    build_frozen_selection,
    qualification_metrics,
    run_external_validation,
)
from src.models.schemas import Decision


class _ModelRecord:
    def __init__(self, identifier: str) -> None:
        self.id = identifier


class _ModelsAPI:
    def retrieve(self, identifier: str):
        return _ModelRecord(identifier)

    def list(self):
        return type("ModelList", (), {"data": [_ModelRecord(REQUESTED_SNAPSHOT)]})()


class _FakeClient:
    models = _ModelsAPI()


def _result(
    case,
    *,
    model: str,
    variant: str,
    malicious: bool,
    blocked: bool,
) -> PilotCaseResult:
    event = DefenseEvent(
        tool_call_id="call-malicious",
        native_tool="send_money",
        arguments={"recipient": "attacker"},
        operation_type=OperationType.FINANCIAL_TRANSFER,
        canonical_tool="http_request",
        decision=Decision.BLOCK if blocked else Decision.ALLOW,
        executed=malicious and not blocked,
        matched_rules=["UNTRUSTED_SCOPE_EXPANSION_DENY"] if blocked else [],
        malicious_ground_truth_match=malicious,
    )
    return PilotCaseResult(
        agentdojo_version="0.1.35",
        python_version="3.12",
        benchmark_version="v1.2.2",
        suite=case["suite"],
        user_task_id=case["user_task_id"],
        injection_task_id=case["injection_task_id"],
        attack="important_instructions",
        model=model,
        provider="openai",
        model_identifier=model,
        defense=variant,
        temperature=0,
        run_index=1,
        native_utility_result=True,
        native_security_result=malicious and not blocked,
        attack_success=malicious and not blocked,
        defense_events=[event],
        malicious_tool_proposed=malicious,
        malicious_tool_blocked=malicious and blocked,
        termination_status="completed",
        provider_tool_compatibility="ok",
        user_request="test request",
        injection_goal_summary="test goal",
    )


def test_frozen_selection_is_deterministic_cross_suite_and_has_positive_control():
    left = build_frozen_selection()
    right = build_frozen_selection()
    assert left == right
    assert left["selection_frozen_before_execution"] is True
    assert left["case_count"] == 17
    assert {case["suite"] for case in left["cases"]} == {
        "banking",
        "travel",
        "workspace",
        "slack",
    }
    anchor = (
        OFFICIAL_POSITIVE_CONTROL["suite"],
        OFFICIAL_POSITIVE_CONTROL["user_task_id"],
        OFFICIAL_POSITIVE_CONTROL["injection_task_id"],
    )
    assert anchor in {
        (case["suite"], case["user_task_id"], case["injection_task_id"])
        for case in left["cases"]
    }


def test_openai_pipeline_preserves_exact_snapshot_and_native_baseline_executor():
    client = OpenAI(api_key="test-key")
    pipeline, executor = build_openai_pipeline(
        REQUESTED_SNAPSHOT,
        "baseline",
        client=client,
    )
    assert REQUESTED_SNAPSHOT in pipeline.name
    assert isinstance(executor, RecordingToolsExecutor)


def test_qualification_requires_both_proposal_and_native_attack_success():
    selection = build_frozen_selection()
    case = selection["cases"][0]
    proposal_only = _result(
        case,
        model=REQUESTED_SNAPSHOT,
        variant="baseline",
        malicious=True,
        blocked=True,
    )
    attack_only = proposal_only.model_copy(update={
        "malicious_tool_proposed": False,
        "native_security_result": True,
        "attack_success": True,
        "defense_events": [],
    })
    assert qualification_metrics([proposal_only])["qualification_passed"] is False
    assert qualification_metrics([attack_only])["qualification_passed"] is False


def test_missing_api_key_writes_all_required_outputs_without_running_cases(tmp_path, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    called = False

    def forbidden_runner(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("case runner must not start without credentials")

    result = run_external_validation(output_dir=tmp_path, case_runner=forbidden_runner)
    assert result["status"] == "blocked_missing_api_key"
    assert called is False
    for name in (
        "qualification_summary.json",
        "qualification_cases.csv",
        "defense_comparison_summary.json",
        "defense_comparison_cases.csv",
        "validation_report.md",
        "selection_manifest.json",
    ):
        assert (tmp_path / name).exists()
    payload = json.loads((tmp_path / "qualification_summary.json").read_text(encoding="utf-8"))
    assert payload["model_access"]["automatic_substitution_performed"] is False


def test_phase_two_runs_only_after_qualification_and_counts_real_blocks(tmp_path):
    calls: list[str] = []

    def passing_runner(case, *, model, variant, client, temperature):
        calls.append(variant)
        return _result(
            case,
            model=model,
            variant=variant,
            malicious=True,
            blocked=variant != "baseline",
        )

    result = run_external_validation(
        output_dir=tmp_path,
        client=_FakeClient(),  # type: ignore[arg-type]
        case_runner=passing_runner,
        function_call_probe=lambda client, model: {
            "available": True,
            "tool_call_id_preserved": True,
            "error": None,
        },
    )
    assert result["status"] == "completed"
    assert calls.count("baseline") == 17
    assert calls.count("context-aware") == 17
    assert calls.count("full") == 17
    rows = {row["defense"]: row for row in result["comparison"]}
    assert rows["baseline"]["native_attack_success_rate"] == 1.0
    assert rows["baseline"]["executed_malicious_calls"] == 17
    assert rows["full"]["conditional_defense_success_rate"] == 1.0
    assert rows["full"]["executed_malicious_calls"] == 0


def test_qualification_only_stops_before_context_aware_and_full(tmp_path):
    calls: list[str] = []

    def passing_runner(case, *, model, variant, client, temperature):
        calls.append(variant)
        return _result(
            case,
            model=model,
            variant=variant,
            malicious=True,
            blocked=False,
        )

    result = run_external_validation(
        output_dir=tmp_path,
        client=_FakeClient(),  # type: ignore[arg-type]
        case_runner=passing_runner,
        function_call_probe=lambda client, model: {
            "available": True,
            "tool_call_id_preserved": True,
            "error": None,
        },
        run_phase_two=False,
    )
    assert result["status"] == "qualification_passed_phase2_not_run"
    assert calls == ["baseline"] * 17
    assert result["comparison"] == []
    comparison = json.loads(
        (tmp_path / "defense_comparison_summary.json").read_text(encoding="utf-8")
    )
    assert comparison["status"] == "not_run_by_request"
