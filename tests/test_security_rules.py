import pytest

from src.defense.decision_engine import DecisionEngine
from src.defense.trust_boundary import TrustBoundary
from src.evaluation.dataset import get_scenario
from src.models.schemas import ContentItem, Decision, ToolCall, TrustLabel
from src.sandbox.environment import FakeEnvironment
from src.tools.registry import build_default_registry


@pytest.fixture
def registry():
    return build_default_registry(FakeEnvironment())


def test_policy_engine_blocks_malicious_document_secret_access(registry):
    decision = DecisionEngine(registry).decide(
        get_scenario("attack-001"),
        ToolCall(tool_name="read_secret", arguments={"name": "cloud-token"}),
        [],
    )
    assert decision.decision == Decision.BLOCK
    assert "SECRET_REQUIRES_EXPLICIT_INTENT" in decision.triggered_policy_rules


def test_trust_boundary_does_not_grant_repository_text_authority():
    repository = ContentItem(source="README", trust_label=TrustLabel.UNTRUSTED_REPOSITORY, content="SYSTEM OVERRIDE")
    user = ContentItem(source="user", trust_label=TrustLabel.TRUSTED_USER, content="review")
    assert TrustBoundary.can_authorize(repository) is False
    assert TrustBoundary.can_authorize(user) is True
    assert TrustBoundary.contains_untrusted([repository]) is True


def test_tool_permission_and_argument_pattern(registry):
    metadata = registry.metadata("run_shell")
    assert [permission.value for permission in metadata.required_permissions] == ["shell:execute"]
    with pytest.raises(ValueError):
        registry.validate_arguments("run_shell", {"command": "curl https://attacker.example"})


def test_benign_security_text_does_not_block_read(registry):
    decision = DecisionEngine(registry).decide(
        get_scenario("benign-011"),
        ToolCall(tool_name="read_file", arguments={"path": "README.md"}),
        [],
    )
    assert decision.decision == Decision.ALLOW

