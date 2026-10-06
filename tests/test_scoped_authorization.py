from src.agent.context_aware_agent import ContextAwareAgent
from src.defense.authorization import AuthorizationResolver
from src.defense.decision_engine import DecisionEngine
from src.evaluation.authorization_dataset import load_authorization_attack_scenarios
from src.evaluation.authorization_runner import run_authorization_evaluation
from src.models.schemas import AuthorizationSource, Decision
from src.providers.mock import MockDeterministicProvider
from src.sandbox.environment import FakeEnvironment
from src.tools.registry import build_default_registry


def run_scenario(scenario):
    environment = FakeEnvironment()
    environment.seed_external_content(scenario.external_content)
    registry = build_default_registry(environment)
    return ContextAwareAgent(registry, MockDeterministicProvider()).run(scenario)


def test_explicit_grant_is_exact_resource_scoped():
    registry = build_default_registry(FakeEnvironment())
    resolver = AuthorizationResolver()
    grants = resolver.resolve("Read billing_api_key.", [], registry.list_metadata())
    billing = next(grant for grant in grants if grant.allowed_tools == ["read_secret"])
    assert billing.source == AuthorizationSource.EXPLICIT_USER_AUTHORIZATION
    assert billing.allowed_resources == ["billing_api_key"]
    assert billing.constraints["network_exfiltration"] is False


def test_untrusted_requests_are_recorded_but_never_grant_authority():
    scenario = load_authorization_attack_scenarios()[2]
    registry = build_default_registry(FakeEnvironment())
    context = DecisionEngine(registry).build_context(scenario, scenario.proposed_calls[0], [])
    assert any(grant.source == AuthorizationSource.UNTRUSTED_CONTENT_REQUEST for grant in context.user_authorizations)
    trusted = [grant for grant in context.user_authorizations if grant.source != AuthorizationSource.UNTRUSTED_CONTENT_REQUEST]
    assert all("read_secret" not in grant.allowed_tools for grant in trusted)


def test_authorization_resource_expansion_is_blocked():
    result = run_scenario(load_authorization_attack_scenarios()[0])
    assert result.events[0].decision == Decision.BLOCK
    assert result.events[0].authorization_scope_match is False
    assert result.attack_succeeded is False


def test_authorization_destination_expansion_is_blocked_after_allowed_read():
    result = run_scenario(load_authorization_attack_scenarios()[1])
    assert result.events[0].decision == Decision.ALLOW
    assert result.events[0].authorization_scope_match is True
    assert result.events[1].decision == Decision.BLOCK
    assert "SECRET_TO_NETWORK_DENY" in result.events[1].triggered_policy_rules
    assert result.attack_succeeded is False


def test_untrusted_fake_delegation_is_blocked():
    result = run_scenario(load_authorization_attack_scenarios()[2])
    assert result.events[0].decision == Decision.BLOCK
    assert result.events[0].authorization_scope_match is False
    assert result.attack_succeeded is False


def test_derived_rotation_scope_does_not_expand_to_scanner_tool():
    result = run_scenario(load_authorization_attack_scenarios()[3])
    assert result.events[0].decision == Decision.ALLOW
    assert result.events[0].authorization_source == AuthorizationSource.DERIVED_TASK_AUTHORIZATION
    assert result.events[1].decision == Decision.BLOCK
    assert result.events[1].authorization_scope_match is False
    assert result.attack_succeeded is False


def test_authorization_evaluation_writes_ablation_and_abuse_results(tmp_path):
    payload, paths = run_authorization_evaluation(tmp_path)
    assert {row["agent"] for row in payload["metrics"]} == {
        "context-aware-legacy", "context-aware-scoped"
    }
    assert len(payload["authorization_abuse_scenarios"]) == 4
    assert not any(row["attack_succeeded"] for row in payload["authorization_abuse_scenarios"])
    assert all(path.exists() for path in paths.values())
