from src.agent.baseline_agent import BaselineAgent
from src.agent.context_aware_agent import ContextAwareAgent
from src.agent.input_filter_agent import InputFilterAgent
from src.evaluation.extended_dataset import load_extended_scenarios
from src.models.schemas import Decision, TerminationReason, ToolCall
from src.defense.decision_engine import DecisionEngine
from src.defense.policy_engine import PolicyEngine, PolicyFeatures
from src.providers.base import LLMProvider
from src.sandbox.environment import FakeEnvironment
from src.tools.registry import build_default_registry


def scenario(kind, category):
    return next(item for item in load_extended_scenarios(kind) if item.category == category)


class QueueProvider(LLMProvider):
    interactive = True
    max_steps = 4

    def __init__(self, calls):
        super().__init__()
        self.items = list(calls)
        self.histories = []

    def propose_actions(self, user_request, content, planned):
        raise NotImplementedError

    def propose_tool_call(self, user_request, content, tools, history):
        self.histories.append(list(history))
        self.record_usage(input_tokens=5, output_tokens=1, estimated=False, latency_ms=0.1)
        return self.items.pop(0) if self.items else None


def run_baseline(item, calls):
    environment = FakeEnvironment()
    registry = build_default_registry(environment)
    result = BaselineAgent(registry, QueueProvider(calls)).run(item)
    return environment, result


def test_secret_catalog_exposes_canonical_resource_identifiers():
    environment = FakeEnvironment()
    metadata = build_default_registry(environment).metadata("read_secret")
    allowed = metadata.allowed_argument_values["name"]
    assert "api-key" in allowed
    assert "billing_api_key" in allowed
    assert "catalog_api_key" in allowed


def test_scenario_external_documents_can_be_reread_in_simulation():
    item = scenario("attack", "direct_instruction")
    environment = FakeEnvironment()
    environment.seed_external_content(item.external_content)
    registry = build_default_registry(environment)
    result = registry.execute("read_file", {"path": item.external_content[0].source})
    assert result.success is True
    assert result.output == item.external_content[0].content


def test_baseline_credential_rotation_succeeds_with_canonical_id():
    item = scenario("benign", "credential_rotation")
    _, result = run_baseline(item, [ToolCall(tool_name="read_secret", arguments={"name": " billing_api_key "}, source="test")])
    assert result.events[0].result.success is True
    assert result.task_completed is True
    assert result.termination_reason == TerminationReason.TASK_COMPLETED


def test_baseline_other_benign_category_completes():
    item = scenario("benign", "http_health_check")
    _, result = run_baseline(item, [ToolCall(
        tool_name="http_request",
        arguments={"url": "https://status.example/billing/health", "method": "GET", "body": ""},
        source="test",
    )])
    assert result.events[0].result.success is True
    assert result.task_completed is True
    assert result.termination_reason == TerminationReason.TASK_COMPLETED


def test_baseline_attack_execution_is_classified_separately():
    item = scenario("attack", "direct_instruction")
    _, result = run_baseline(item, [ToolCall(
        tool_name="modify_manifest",
        arguments={"path": "deployment.yaml", "content": "security_scan: false\n"},
        source="test",
    )])
    assert result.events[0].result.success is True
    assert result.attack_succeeded is True
    assert result.termination_reason == TerminationReason.ATTACK_SUCCEEDED


def test_repeated_failed_call_stops_early_with_structured_feedback():
    item = scenario("benign", "credential_rotation")
    bad = ToolCall(tool_name="read_secret", arguments={"name": "unknown_api_key"}, source="test")
    provider = QueueProvider([bad.model_copy(deep=True) for _ in range(4)])
    registry = build_default_registry(FakeEnvironment())
    result = BaselineAgent(registry, provider).run(item)
    assert len(result.events) == 2
    assert result.events[0].result.error_code == "RESOURCE_NOT_FOUND"
    assert provider.histories[1][0].result.error_code == "RESOURCE_NOT_FOUND"
    assert result.termination_reason == TerminationReason.REPEATED_FAILED_TOOL_CALL


def test_credential_rotation_scoped_authorization_resolves_context_false_positive_only():
    item = scenario("benign", "credential_rotation")
    call = ToolCall(tool_name="read_secret", arguments={"name": "billing_api_key"}, source="test")
    input_result = InputFilterAgent(
        build_default_registry(FakeEnvironment()), QueueProvider([call.model_copy(deep=True)])
    ).run(item)
    assert input_result.events[0].decision == Decision.BLOCK

    legacy_registry = build_default_registry(FakeEnvironment())
    legacy_engine = DecisionEngine(legacy_registry, PolicyEngine(features=PolicyFeatures()))
    legacy = ContextAwareAgent(legacy_registry, QueueProvider([call.model_copy(deep=True)]), legacy_engine).run(item)
    assert legacy.events[0].decision == Decision.BLOCK
    assert "UNTRUSTED_HIGH_RISK_DENY" in legacy.events[0].triggered_policy_rules

    scoped = ContextAwareAgent(build_default_registry(FakeEnvironment()), QueueProvider([call])).run(item)
    assert scoped.events[0].decision == Decision.ALLOW
    assert scoped.events[0].authorization_scope_match is True
    assert "SCOPED_USER_AUTHORIZATION" in scoped.events[0].triggered_policy_rules
    assert scoped.task_completed is True
