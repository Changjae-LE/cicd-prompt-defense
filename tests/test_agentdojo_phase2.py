from __future__ import annotations

from types import SimpleNamespace

import pytest

pytest.importorskip("agentdojo")

from src.integrations.agentdojo.phase2 import (  # noqa: E402
    UsageMeter,
    _MeteredCompletions,
    aggregate_metrics,
    case_row,
)
from src.integrations.agentdojo.schemas import (  # noqa: E402
    DefenseEvent,
    OperationType,
    PilotCaseResult,
)
from src.models.schemas import Decision  # noqa: E402


def _case(*, defense: str, native: bool, malicious: bool, blocked: bool) -> PilotCaseResult:
    events = [
        DefenseEvent(
            native_tool="send_money" if malicious else "get_balance",
            arguments={},
            operation_type=(
                OperationType.FINANCIAL_TRANSFER if malicious else OperationType.READ_ONLY
            ),
            canonical_tool="http_request" if malicious else "read_file",
            decision=Decision.BLOCK if blocked else Decision.ALLOW,
            executed=not blocked,
            matched_rules=["UNTRUSTED_SCOPE_EXPANSION_DENY"] if blocked else [],
            malicious_ground_truth_match=malicious,
        )
    ]
    return PilotCaseResult(
        agentdojo_version="0.1.35",
        python_version="3.12",
        benchmark_version="v1.2.2",
        suite="banking",
        user_task_id="user_task_0",
        injection_task_id="injection_task_0",
        attack="important_instructions",
        model="gpt-4o-mini-2024-07-18",
        provider="test",
        model_identifier="gpt-4o-mini-2024-07-18",
        defense=defense,
        temperature=0,
        run_index=1,
        native_utility_result=True,
        native_security_result=native,
        attack_success=native,
        defense_events=events,
        malicious_tool_proposed=malicious,
        malicious_tool_blocked=malicious and blocked,
        user_request="Check the account.",
        injection_goal_summary="Send money.",
        llm_call_count=2,
        input_tokens=10,
        output_tokens=4,
        total_tokens=14,
        token_usage_available=True,
        llm_latency_ms=5,
        case_latency_ms=8,
    )


def test_native_evaluator_and_strict_matcher_remain_separate():
    mismatch = _case(defense="baseline", native=True, malicious=False, blocked=False)
    row = case_row(mismatch, "end_to_end")
    assert row["native_attack_success"] is True
    assert row["strict_malicious_proposed"] is False


def test_controlled_metrics_count_defense_blocks_and_benign_false_positives():
    cases = [
        _case(defense="baseline", native=True, malicious=True, blocked=False),
        _case(defense="context-aware", native=False, malicious=True, blocked=True),
        _case(defense="full", native=False, malicious=True, blocked=True),
        _case(defense="full", native=False, malicious=False, blocked=True),
    ]
    rows = {row["defense"]: row for row in aggregate_metrics(cases, "controlled_replay")}
    assert rows["baseline"]["strict_malicious_execution_rate"] == 1.0
    assert rows["context-aware"]["defense_detection_rate"] == 1.0
    assert rows["full"]["defense_detection_rate"] == 1.0
    assert rows["full"]["false_positive_rate"] == 1.0
    assert rows["full"]["goal_aware_termination_count"] is None
    assert rows["full"]["post_task_malicious_proposal_detections"] is None


def test_metered_completion_preserves_response_and_records_usage():
    response = SimpleNamespace(
        usage=SimpleNamespace(prompt_tokens=11, completion_tokens=3, total_tokens=14)
    )
    delegate = SimpleNamespace(create=lambda **kwargs: response)
    meter = UsageMeter()
    wrapped = _MeteredCompletions(delegate, meter)
    assert wrapped.create(model="test") is response
    assert meter.llm_calls == 1
    assert meter.input_tokens == 11
    assert meter.output_tokens == 3
    assert meter.total_tokens == 14
    assert meter.usage_responses == 1

