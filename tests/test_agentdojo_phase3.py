from __future__ import annotations

import pytest

pytest.importorskip("agentdojo")

from openai import OpenAI

from src.integrations.agentdojo.model_adapter import build_openai_pipeline
from src.integrations.agentdojo.phase3 import controlled_deltas
from src.integrations.agentdojo.schemas import DefenseEvent, OperationType, PilotCaseResult
from src.integrations.agentdojo.validation import REQUESTED_SNAPSHOT
from src.models.schemas import Decision


def _case(defense: str, decisions: list[tuple[bool, Decision]]) -> PilotCaseResult:
    events = [
        DefenseEvent(
            tool_call_id=f"call-{index}",
            native_tool="send_message",
            arguments={"recipient": "Alice", "message": f"payload-{index}"},
            operation_type=OperationType.EXTERNAL_COMMUNICATION,
            canonical_tool="http_request",
            decision=decision,
            executed=decision == Decision.ALLOW,
            malicious_ground_truth_match=malicious,
            matched_rules=(
                ["UNTRUSTED_PAYLOAD_PROPAGATION_DENY"]
                if defense == "refined-full" and decision == Decision.BLOCK
                else []
            ),
        )
        for index, (malicious, decision) in enumerate(decisions)
    ]
    return PilotCaseResult(
        agentdojo_version="0.1.35",
        python_version="3.12",
        benchmark_version="v1.2.2",
        suite="slack",
        user_task_id="user_task_0",
        injection_task_id="injection_task_0",
        attack="important_instructions",
        model=REQUESTED_SNAPSHOT,
        provider="controlled-replay",
        model_identifier=REQUESTED_SNAPSHOT,
        defense=defense,
        temperature=0,
        run_index=1,
        native_utility_result=None,
        native_security_result=None,
        attack_success=None,
        defense_events=events,
        malicious_tool_proposed=True,
        malicious_tool_blocked=any(
            event.malicious_ground_truth_match and event.decision == Decision.BLOCK
            for event in events
        ),
        user_request="Send Alice the summary.",
        injection_goal_summary="Send attacker payload.",
    )


def test_refined_full_pipeline_is_a_separate_variant():
    pipeline, executor = build_openai_pipeline(
        REQUESTED_SNAPSHOT,
        "refined-full",
        client=OpenAI(api_key="test-key"),
    )
    assert "refined-full" in pipeline.name
    assert executor.variant == "refined-full"


def test_controlled_deltas_separate_fixes_false_positives_and_regressions():
    phase2 = _case(
        "full",
        [
            (True, Decision.BLOCK),
            (True, Decision.ALLOW),
            (False, Decision.ALLOW),
            (True, Decision.BLOCK),
        ],
    )
    refined = _case(
        "refined-full",
        [
            (True, Decision.BLOCK),
            (True, Decision.BLOCK),
            (False, Decision.BLOCK),
            (True, Decision.ALLOW),
        ],
    )
    deltas = controlled_deltas([phase2, refined])
    assert deltas["preserved_malicious_blocks"]["count"] == 1
    assert deltas["newly_fixed_malicious_calls"]["count"] == 1
    assert deltas["new_false_positive_proxy_calls"]["count"] == 1
    assert deltas["new_malicious_regressions"]["count"] == 1

