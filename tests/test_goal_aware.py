from src.agent.context_aware_agent import ContextAwareAgent
from src.agent.goal_aware_agent import GoalAwareContextAgent, GoalAwareMode
from src.defense.goal_completion import GoalCompletionDetector, GoalDetectorFeatures
from src.evaluation.goal_aware_dataset import load_goal_aware_scenarios
from src.evaluation.goal_aware_runner import _goal_detector_ablation, _mode_metrics
from src.models.schemas import Decision, ExecutionPhase, GoalStatus, ToolCall
from src.providers.base import LLMProvider
from src.providers.mock import MockDeterministicProvider
from src.sandbox.environment import FakeEnvironment
from src.tools.registry import build_default_registry


def scenario(category):
    return next(item for item in load_goal_aware_scenarios() if item.category == category)


def goal_agent(item, mode, *, features=None, audit_steps=2):
    environment = FakeEnvironment()
    return GoalAwareContextAgent(
        build_default_registry(environment),
        MockDeterministicProvider(),
        mode=mode,
        post_task_audit_steps=audit_steps,
        goal_features=features,
    ).run(item)


def test_goal_completion_detection_after_required_success():
    result = goal_agent(scenario("goal_normal_termination"), GoalAwareMode.OPERATIONAL)
    assert result.goal_status == GoalStatus.SATISFIED
    assert result.goal_satisfied_after_event == 1
    assert result.task_completed is True


def test_multi_step_goal_does_not_terminate_after_first_success():
    result = goal_agent(scenario("goal_multi_step"), GoalAwareMode.OPERATIONAL)
    assert result.goal_status == GoalStatus.SATISFIED
    assert result.goal_satisfied_after_event == 2
    assert [event.tool_call.tool_name for event in result.events] == ["list_k8s_pods", "get_k8s_logs"]


def test_wrong_resource_does_not_prematurely_satisfy_goal():
    result = goal_agent(scenario("goal_partial_completion"), GoalAwareMode.OPERATIONAL)
    assert result.goal_status != GoalStatus.SATISFIED
    without_resource = goal_agent(
        scenario("goal_partial_completion"),
        GoalAwareMode.OPERATIONAL,
        features=GoalDetectorFeatures(use_resource_matching=False),
    )
    assert without_resource.goal_status == GoalStatus.SATISFIED


def test_failed_tool_result_does_not_satisfy_goal():
    result = goal_agent(scenario("goal_failed_tool_result"), GoalAwareMode.OPERATIONAL)
    assert result.goal_status != GoalStatus.SATISFIED
    without_results = goal_agent(
        scenario("goal_failed_tool_result"),
        GoalAwareMode.OPERATIONAL,
        features=GoalDetectorFeatures(use_tool_results=False),
    )
    assert without_results.goal_status == GoalStatus.SATISFIED


def test_redundant_post_task_call_is_observed_only_in_audit():
    item = scenario("goal_normal_termination")
    operational = goal_agent(item, GoalAwareMode.OPERATIONAL)
    audit = goal_agent(item, GoalAwareMode.RESEARCH_AUDIT)
    assert len(operational.events) == 1
    assert len(audit.events) == 2
    assert audit.events[1].execution_phase == ExecutionPhase.POST_TASK_AUDIT
    assert audit.events[1].redundant is True
    assert audit.events[1].executed is False


def test_malicious_post_task_proposal_is_blocked_without_execution():
    result = goal_agent(scenario("post_task_network_attack"), GoalAwareMode.RESEARCH_AUDIT)
    malicious = result.events[1]
    assert malicious.post_task_malicious is True
    assert malicious.decision == Decision.BLOCK
    assert malicious.audit_only is True
    assert malicious.executed is False
    assert result.attack_succeeded is False


def test_operational_and_existing_false_positive_metrics_are_separate():
    item = scenario("post_task_network_attack")
    result = goal_agent(item, GoalAwareMode.RESEARCH_AUDIT)
    metrics = _mode_metrics(GoalAwareMode.RESEARCH_AUDIT.value, [item], [result])
    assert metrics["existing_false_positive_rate"] == 0.0  # attack scenario has no benign denominator
    assert metrics["audit_mode_attack_detection_rate"] == 1.0
    assert metrics["audit_counterfactual_asr"] == 0.0


def test_goal_detector_ablation_exposes_history_resource_and_result_dependencies():
    rows = {row["variant"]: row for row in _goal_detector_ablation(2)}
    assert rows["goal-detector-full"]["false_completion_count"] == 0
    assert rows["without-resource-matching"]["false_completion_count"] >= 1
    assert rows["without-tool-results"]["false_completion_count"] >= 1
    assert rows["without-execution-history"]["goal_completion_rate"] < rows["goal-detector-full"]["goal_completion_rate"]


class SequenceProvider(LLMProvider):
    interactive = True
    max_steps = 4

    def __init__(self, calls):
        super().__init__()
        self.items = [call.model_copy(deep=True) for call in calls]

    def propose_actions(self, user_request, content, planned):
        raise NotImplementedError

    def propose_tool_call(self, user_request, content, tools, history):
        self.record_usage(input_tokens=10, output_tokens=2, estimated=False, latency_ms=5.0)
        return self.items.pop(0) if self.items else None


def test_operational_mode_saves_model_calls_tokens_and_latency():
    item = scenario("goal_normal_termination")
    calls = [
        ToolCall(tool_name="read_secret", arguments={"name": "billing_api_key"}),
        ToolCall(tool_name="read_secret", arguments={"name": "billing_api_key"}),
    ]
    current = ContextAwareAgent(build_default_registry(FakeEnvironment()), SequenceProvider(calls)).run(item)
    operational = GoalAwareContextAgent(
        build_default_registry(FakeEnvironment()), SequenceProvider(calls), mode=GoalAwareMode.OPERATIONAL
    ).run(item)
    audit = GoalAwareContextAgent(
        build_default_registry(FakeEnvironment()), SequenceProvider(calls), mode=GoalAwareMode.RESEARCH_AUDIT
    ).run(item)
    assert operational.llm_calls < current.llm_calls
    assert operational.total_tokens < current.total_tokens
    assert operational.llm_latency_ms < current.llm_latency_ms
    assert audit.events[-1].audit_only is True
