from __future__ import annotations

from src.agent.context_aware_agent import ContextAwareAgent
from src.agent.goal_aware_agent import GoalAwareContextAgent, GoalAwareMode
from src.defense.provenance import ProvenanceFeatures, ProvenancePolicy, ProvenanceTracker
from src.models.schemas import (
    Decision,
    ExecutionEvent,
    ExecutionPhase,
    Scenario,
    SecurityDecision,
    Sensitivity,
    ToolCall,
)


class ProvenanceAgentMixin:
    tracker: ProvenanceTracker
    provenance_policy: ProvenancePolicy

    def _initialize_provenance(self, features: ProvenanceFeatures | None) -> None:
        selected = features or ProvenanceFeatures()
        self.tracker = ProvenanceTracker(selected)
        self.provenance_policy = ProvenancePolicy(
            selected,
            security_policy=self.decision_engine.policy_engine.policy,
        )

    def _combined_decision(self, scenario: Scenario, call: ToolCall, history: list[ExecutionEvent]):
        base = self.authorize(scenario, call, history)
        flow = self.provenance_policy.evaluate(
            scenario,
            call,
            self.registry.list_metadata(),
            self.tracker,
            history,
        )
        decision = Decision.BLOCK if base.decision == Decision.BLOCK or flow.decision == Decision.BLOCK else base.decision
        risk = max(base.risk_score, 1.0 if flow.risk == "CRITICAL" else 0.8 if flow.risk == "HIGH" else 0.0)
        merged = SecurityDecision(
            decision=decision,
            risk_score=risk,
            reasons=base.reasons + flow.reasons,
            triggered_policy_rules=list(dict.fromkeys(base.triggered_policy_rules + flow.rules)),
            intent_mismatch=base.intent_mismatch,
            privilege_escalation=base.privilege_escalation,
            data_exfiltration_pattern=base.data_exfiltration_pattern or "SENSITIVE_DATA_TO_EXTERNAL_NETWORK_DENY" in flow.rules,
            authorization_scope_match=base.authorization_scope_match,
            authorization_source=base.authorization_source,
        )
        return merged, flow

    def _process_call(self, scenario: Scenario, call: ToolCall, history: list[ExecutionEvent]) -> ExecutionEvent:
        decision, flow = self._combined_decision(scenario, call, history)
        executed = decision.decision == Decision.ALLOW
        result = self.registry.execute(call.tool_name, call.arguments) if executed else None
        outputs = self.tracker.record_execution(call, result) if result else []
        if not executed:
            self.tracker.record_blocked_sink(call)
        if result:
            if outputs:
                result.output = self.tracker.safe_output(outputs, result.output)
                result.sensitive = result.sensitive or any(
                    item.sensitivity in {Sensitivity.SENSITIVE, Sensitivity.SECRET, Sensitivity.SECRET_DERIVED}
                    for item in outputs
                )
            elif result.sensitive:
                result.output = "[REDACTED]"
        return ExecutionEvent(
            tool_call=call,
            decision=decision.decision,
            executed=executed,
            result=result,
            risk_score=decision.risk_score,
            reasons=decision.reasons,
            triggered_policy_rules=decision.triggered_policy_rules,
            intent_mismatch=decision.intent_mismatch,
            privilege_escalation=decision.privilege_escalation,
            data_exfiltration_pattern=decision.data_exfiltration_pattern,
            authorization_scope_match=decision.authorization_scope_match,
            authorization_source=decision.authorization_source,
            input_artifact_ids=flow.input_artifact_ids,
            output_artifact_ids=[item.artifact_id for item in outputs],
            provenance_policy_rules=flow.rules,
        )

    def _attach_provenance(self, result):
        result.provenance_artifacts = list(self.tracker.artifacts.values())
        result.provenance_edges = list(self.tracker.edges)
        return result


class ProvenanceContextAwareAgent(ProvenanceAgentMixin, ContextAwareAgent):
    name = "context-aware-provenance"

    def __init__(self, registry, provider, *, provenance_features=None, decision_engine=None) -> None:
        ContextAwareAgent.__init__(self, registry, provider, decision_engine)
        self._initialize_provenance(provenance_features)

    def run(self, scenario: Scenario):
        self.tracker.configure(scenario)
        return self._attach_provenance(super().run(scenario))


class ProvenanceGoalAwareAgent(ProvenanceAgentMixin, GoalAwareContextAgent):
    name = "goal-aware-provenance-audit"

    def __init__(
        self,
        registry,
        provider,
        *,
        provenance_features=None,
        post_task_audit_steps: int = 2,
        decision_engine=None,
    ) -> None:
        GoalAwareContextAgent.__init__(
            self,
            registry,
            provider,
            mode=GoalAwareMode.RESEARCH_AUDIT,
            post_task_audit_steps=post_task_audit_steps,
            decision_engine=decision_engine,
        )
        self.name = "goal-aware-provenance-audit"
        self._initialize_provenance(provenance_features)

    def run(self, scenario: Scenario):
        self.tracker.configure(scenario)
        return self._attach_provenance(super().run(scenario))

    def _audit_event(self, scenario, call, history, goal):
        decision, flow = self._combined_decision(scenario, call, history)
        self.tracker.record_blocked_sink(call)
        return ExecutionEvent(
            tool_call=call,
            decision=decision.decision,
            executed=False,
            result=None,
            risk_score=decision.risk_score,
            reasons=decision.reasons,
            triggered_policy_rules=decision.triggered_policy_rules,
            intent_mismatch=decision.intent_mismatch,
            privilege_escalation=decision.privilege_escalation,
            data_exfiltration_pattern=decision.data_exfiltration_pattern,
            authorization_scope_match=decision.authorization_scope_match,
            authorization_source=decision.authorization_source,
            execution_phase=ExecutionPhase.POST_TASK_AUDIT,
            before_goal_completion=False,
            redundant=self.redundancy.is_redundant(call, history, goal),
            post_task_malicious=call.is_malicious,
            audit_only=True,
            input_artifact_ids=flow.input_artifact_ids,
            provenance_policy_rules=flow.rules,
        )
