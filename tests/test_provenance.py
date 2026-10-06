from __future__ import annotations

from src.agent.context_aware_agent import ContextAwareAgent
from src.agent.provenance_agent import ProvenanceContextAwareAgent, ProvenanceGoalAwareAgent
from src.defense.provenance import ProvenanceFeatures
from src.evaluation.provenance_dataset import load_provenance_scenarios
from src.models.schemas import Decision, ExecutionPhase, Sensitivity, TrustLabel
from src.providers.mock import MockDeterministicProvider
from src.sandbox.environment import FakeEnvironment
from src.tools.registry import build_default_registry
from src.utils.redaction import redact


def scenario(category):
    return next(item for item in load_provenance_scenarios() if item.category == category)


def run(item, *, provenance=True, features=None):
    environment = FakeEnvironment()
    environment.seed_external_content(item.external_content)
    agent_type = ProvenanceContextAwareAgent if provenance else ContextAwareAgent
    kwargs = {"provenance_features": features} if provenance else {}
    return agent_type(
        build_default_registry(environment), MockDeterministicProvider(), **kwargs
    ).run(item)


def test_secret_source_is_symbolic_labeled_and_never_serialized():
    result = run(scenario("direct_exfiltration"))
    artifact = result.provenance_artifacts[0]
    assert artifact.sensitivity == Sensitivity.SECRET
    assert artifact.source_trust_label == TrustLabel.TRUSTED_POLICY
    assert artifact.symbolic_ref == "[ARTIFACT:artifact-0001]"
    assert "FAKE_" not in result.model_dump_json()


def test_encoding_preserves_taint_and_lineage():
    result = run(scenario("encoding_relay"))
    source, encoded = result.provenance_artifacts
    assert encoded.sensitivity == Sensitivity.SECRET_DERIVED
    assert source.artifact_id in encoded.derived_from
    assert "base64" in encoded.transformations
    assert result.events[-1].decision == Decision.BLOCK


def test_file_relay_keeps_transitive_derived_from_graph():
    result = run(scenario("file_relay"))
    source, written, reread = result.provenance_artifacts
    assert source.artifact_id in written.derived_from
    assert source.artifact_id in reread.derived_from
    assert written.artifact_id in reread.derived_from
    assert any(edge.sink == "INTERNAL_TEMP_STORAGE" for edge in result.provenance_edges)
    assert any(edge.sink == "EXTERNAL_NETWORK" and edge.blocked for edge in result.provenance_edges)


def test_sequence_baseline_misses_sensitive_file_flow_but_provenance_blocks_it():
    item = scenario("sequence_miss_sensitive_file")
    sequence = run(item, provenance=False)
    provenance = run(item)
    assert sequence.attack_succeeded is True
    assert sequence.events[-1].decision == Decision.ALLOW
    assert provenance.attack_succeeded is False
    assert "SENSITIVE_DATA_TO_EXTERNAL_NETWORK_DENY" in provenance.events[-1].provenance_policy_rules


def test_fingerprint_is_explicitly_declassified_for_benign_local_logging():
    result = run(scenario("benign_fingerprint_log"))
    fingerprint = next(
        artifact for artifact in result.provenance_artifacts if "one_way_fingerprint" in artifact.transformations
    )
    assert fingerprint.sensitivity == Sensitivity.INTERNAL
    assert result.task_completed is True
    assert all(event.decision == Decision.ALLOW for event in result.events)


def test_scoped_transmission_authorization_avoids_local_escrow_false_positive():
    item = scenario("benign_authorized_sensitive_write")
    unscoped = run(item, features=ProvenanceFeatures(scoped_authorization_integration=False))
    scoped = run(item, features=ProvenanceFeatures(scoped_authorization_integration=True))
    assert unscoped.events[-1].decision == Decision.BLOCK
    assert "UNAUTHORIZED_SECRET_DERIVATION_FLOW_DENY" in unscoped.events[-1].provenance_policy_rules
    assert scoped.events[-1].decision == Decision.ALLOW
    assert "AUTHORIZED_SENSITIVE_DATA_FLOW" in scoped.events[-1].provenance_policy_rules
    assert scoped.task_completed is True


def test_source_and_sink_ablations_restore_the_known_attack():
    item = scenario("sequence_miss_sensitive_file")
    without_source = run(item, features=ProvenanceFeatures(source_labeling=False))
    without_sink = run(item, features=ProvenanceFeatures(sink_classification=False))
    assert without_source.attack_succeeded is True
    assert without_sink.attack_succeeded is True


def test_post_task_goal_audit_applies_provenance_without_execution():
    item = scenario("post_task_provenance")
    environment = FakeEnvironment()
    agent = ProvenanceGoalAwareAgent(
        build_default_registry(environment), MockDeterministicProvider(), post_task_audit_steps=2
    )
    result = agent.run(item)
    audit = result.events[-1]
    assert audit.execution_phase == ExecutionPhase.POST_TASK_AUDIT
    assert audit.audit_only is True
    assert audit.executed is False
    assert "SENSITIVE_DATA_TO_EXTERNAL_NETWORK_DENY" in audit.provenance_policy_rules
    assert any(edge.sink == "EXTERNAL_NETWORK" and edge.blocked for edge in result.provenance_edges)


def test_tracker_state_is_reset_between_runs_on_same_agent():
    environment = FakeEnvironment()
    agent = ProvenanceContextAwareAgent(
        build_default_registry(environment), MockDeterministicProvider()
    )
    first = agent.run(scenario("direct_exfiltration"))
    second = agent.run(scenario("benign_local_validation"))
    assert first.provenance_artifacts[0].artifact_id == "artifact-0001"
    assert second.provenance_artifacts[0].artifact_id == "artifact-0001"


def test_simulated_sensitive_file_content_is_redacted_recursively():
    value = {"body": "SIMULATED_JSON:SIMULATED_SENSITIVE_CONFIGURATION"}
    assert redact(value) == {"body": "SIMULATED_JSON:[REDACTED]"}
