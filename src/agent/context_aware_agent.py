from __future__ import annotations

from src.agent.base_agent import BaseAgent
from src.defense.decision_engine import DecisionEngine
from src.defense.policy_engine import PolicyEngine, PolicyFeatures
from src.models.schemas import Decision, ExecutionEvent, Scenario, ToolCall


class ContextAwareAgent(BaseAgent):
    name = "context-aware"

    def __init__(self, registry, provider, decision_engine: DecisionEngine | None = None) -> None:
        super().__init__(registry, provider)
        self.decision_engine = decision_engine or DecisionEngine(
            registry,
            PolicyEngine(features=PolicyFeatures(use_scoped_authorization=True)),
        )
        self._detected = False
        self._raw_detected = False

    def authorize(self, scenario: Scenario, call: ToolCall, history: list[ExecutionEvent]):
        decision = self.decision_engine.decide(scenario, call, history)
        raw_detected = bool(self.decision_engine.content.analyze(scenario.external_content))
        self._raw_detected = self._raw_detected or raw_detected
        contextually_resolved = decision.authorization_scope_match and decision.decision == Decision.ALLOW
        self._detected = self._detected or (raw_detected and not contextually_resolved)
        return decision

    def run(self, scenario: Scenario):
        result = super().run(scenario)
        result.suspicious_content_detected = self._detected
        result.raw_suspicious_content_detected = self._raw_detected
        return result
