from __future__ import annotations

import pytest

pytest.importorskip("agentdojo")

from src.integrations.agentdojo.phase5 import (
    ErrorClass,
    ToolOutcome,
    classify_tool_error,
    reclassify_phase4,
    validity_gate,
)


def _classify(error: str, *, arguments=None, request="Find Alice"):
    return classify_tool_error(
        error,
        tool="test_tool",
        arguments=arguments or {},
        user_request=request,
    )


@pytest.mark.parametrize(
    ("error", "classification", "outcome"),
    [
        (
            "SECURITY_BLOCK: outside scope",
            ErrorClass.DEFENSE_BLOCK.value,
            ToolOutcome.BLOCKED_BY_DEFENSE.value,
        ),
        (
            "ValidationError: field required",
            ErrorClass.MODEL_ARGUMENT_ERROR.value,
            ToolOutcome.INVALID_ARGUMENT.value,
        ),
        (
            "ToolNotFoundError: missing",
            ErrorClass.ADAPTER_INTEGRATION_ERROR.value,
            ToolOutcome.INVALID_ARGUMENT.value,
        ),
        (
            "ValueError: No events found. Try with a different query.",
            ErrorClass.EMPTY_RESULT.value,
            ToolOutcome.EMPTY_RESULT.value,
        ),
        (
            "ValueError: Contact with email 'nobody@example.com' not found.",
            ErrorClass.ENTITY_NOT_FOUND.value,
            ToolOutcome.NOT_FOUND.value,
        ),
    ],
)
def test_structured_tool_outcome_preserves_distinct_error_classes(error, classification, outcome):
    result = _classify(error)
    assert result["classification"] == classification
    assert result["structured_outcome"] == outcome
    assert result["raw_error"] == error


def test_unanchored_missing_entity_is_attributed_to_model_behavior():
    result = _classify(
        "ValueError: Contact with email 'nobody@example.com' not found.",
        arguments={"query": "nobody@example.com"},
        request="Find Alice",
    )
    assert result["benchmark_native"] is True
    assert result["failure_domain"] == "MODEL_BEHAVIOR"
    assert result["model_generated_invalid_entity_or_argument"] is True


def test_user_anchored_empty_result_is_benchmark_environment_outcome():
    result = _classify(
        "ValueError: No events found. Try with a different query.",
        arguments={"query": "Project Apollo"},
        request="Find the Project Apollo event",
    )
    assert result["failure_domain"] == "BENCHMARK_ENVIRONMENT"
    assert result["model_generated_invalid_entity_or_argument"] is False


def test_validity_gate_does_not_merge_benchmark_runtime_with_adapter_failure():
    rows = [
        {
            "case_id": f"workspace/user_task_{index}/injection_task_0",
            "run_index": 1,
            "defense": "baseline",
            "evaluation_mode": "baseline_source",
            "classification": ErrorClass.EMPTY_RESULT.value,
            "model_generated_invalid_entity_or_argument": False,
        }
        for index in range(2)
    ]
    gate = validity_gate(
        rows=rows,
        actual_case_runs=20,
        proposal_mismatch_count=0,
        missing_ground_truth_count=0,
        replay_error_count=0,
    )
    assert gate["adapter_integration_error_rate"] == 0
    assert gate["benchmark_runtime_error_rate"] == 0.1
    assert gate["status"] == "PASS"


def test_adapter_failure_still_uses_original_five_percent_gate():
    rows = [
        {
            "case_id": "workspace/user_task_0/injection_task_0",
            "run_index": 1,
            "defense": "baseline",
            "evaluation_mode": "baseline_source",
            "classification": ErrorClass.ADAPTER_INTEGRATION_ERROR.value,
            "model_generated_invalid_entity_or_argument": False,
        }
    ]
    gate = validity_gate(
        rows=rows,
        actual_case_runs=10,
        proposal_mismatch_count=0,
        missing_ground_truth_count=0,
        replay_error_count=0,
    )
    assert gate["adapter_integration_error_rate"] == 0.1
    assert gate["status"] == "FAIL"


def test_existing_phase4_raw_errors_reclassify_without_modifying_source():
    rows, summary = reclassify_phase4(__import__("pathlib").Path("results/agentdojo/phase4/smoke"))
    assert rows
    assert summary["actual_case_runs"] == 80
    assert summary["provider_integration_error_rate"] == 0
    assert summary["benchmark_runtime_error_rate"] > 0
