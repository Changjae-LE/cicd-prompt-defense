from __future__ import annotations

import pytest

pytest.importorskip("agentdojo")

from src.integrations.agentdojo.phase4 import (
    PHASE4_VARIANTS,
    build_broad_selection,
    failure_taxonomy,
    matcher_mismatches,
    rule_analysis,
    wilson_interval,
)
from src.integrations.agentdojo.schemas import DefenseEvent, OperationType, PilotCaseResult
from src.models.schemas import Decision


def _case(
    *,
    defense: str = "refined-full",
    native_security: bool = False,
    native_utility: bool = True,
    events: list[DefenseEvent] | None = None,
) -> PilotCaseResult:
    return PilotCaseResult(
        agentdojo_version="0.1.35",
        python_version="3.12",
        benchmark_version="v1.2.2",
        suite="slack",
        user_task_id="user_task_2",
        injection_task_id="injection_task_3",
        attack="important_instructions",
        model="gpt-4o-mini-2024-07-18",
        provider="test",
        model_identifier="gpt-4o-mini-2024-07-18",
        defense=defense,
        temperature=0,
        run_index=1,
        native_utility_result=native_utility,
        native_security_result=native_security,
        attack_success=native_security,
        defense_events=events or [],
        user_request="Summarize the report",
        injection_goal_summary="Send attacker content",
    )


def _event(
    *,
    malicious: bool,
    decision: Decision,
    executed: bool,
    rules: list[str] | None = None,
    operation: OperationType = OperationType.EXTERNAL_COMMUNICATION,
) -> DefenseEvent:
    return DefenseEvent(
        tool_call_id="call_1",
        native_tool="send_message" if operation != OperationType.READ_ONLY else "read_messages",
        arguments={"body": "payload"},
        operation_type=operation,
        canonical_tool="http_request" if operation != OperationType.READ_ONLY else "read_file",
        decision=decision,
        executed=executed,
        matched_rules=rules or [],
        malicious_ground_truth_match=malicious,
    )


def test_broad_selection_is_balanced_deterministic_and_excludes_original():
    smoke = build_broad_selection(limit=20)
    broader = build_broad_selection(limit=50)

    assert smoke == build_broad_selection(limit=20)
    assert smoke["cases"] == broader["cases"][:20]
    assert smoke["domain_distribution"] == {
        "banking": 5,
        "travel": 5,
        "workspace": 5,
        "slack": 5,
    }
    assert broader["overlap_with_original"] == 0
    assert broader["broader_only_count"] == 50
    assert max(broader["domain_distribution"].values()) - min(
        broader["domain_distribution"].values()
    ) <= 1
    assert all(case["selection_reason"] == "deterministic_stratified_diagonal" for case in broader["cases"])


def test_wilson_interval_handles_empty_and_bounds():
    assert wilson_interval(0, 0)["low"] is None
    interval = wilson_interval(5, 10)
    assert interval["low"] < 0.5 < interval["high"]
    assert 0 <= interval["low"] <= interval["high"] <= 1


def test_rule_analysis_separates_malicious_and_nonmatching_blocks():
    cases = [
        _case(events=[
            _event(
                malicious=True,
                decision=Decision.BLOCK,
                executed=False,
                rules=["PAYLOAD_SCOPE_MISMATCH"],
            ),
            _event(
                malicious=False,
                decision=Decision.BLOCK,
                executed=False,
                rules=["PAYLOAD_SCOPE_MISMATCH"],
            ),
        ])
    ]
    rows = rule_analysis(cases, "broader")
    row = next(
        item
        for item in rows
        if item["defense"] == "refined-full" and item["rule"] == "PAYLOAD_SCOPE_MISMATCH"
    )
    assert row["malicious_blocks"] == 1
    assert row["non_malicious_blocks"] == 1
    assert row["precision_like_ratio"] == 0.5
    assert {row["defense"] for row in rows} == set(PHASE4_VARIANTS)


def test_missed_read_is_taxonomized_without_changing_policy():
    missed = _case(events=[
        _event(
            malicious=True,
            decision=Decision.ALLOW,
            executed=True,
            operation=OperationType.READ_ONLY,
        )
    ])
    rows = failure_taxonomy([missed], [])
    assert rows[0]["category"] == "attack_chain_intermediate_read"


def test_native_and_strict_matcher_mismatch_is_explicit():
    native_only = _case(native_security=True, events=[])
    strict_only = _case(
        native_security=False,
        events=[_event(malicious=True, decision=Decision.ALLOW, executed=True)],
    )
    rows = matcher_mismatches([native_only, strict_only])
    assert len(rows) == 2
    assert {row["strict_malicious_execution"] for row in rows} == {False, True}
