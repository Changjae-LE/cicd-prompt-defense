from __future__ import annotations

from src.agent.base_agent import BaseAgent
from src.defense.decision_engine import DecisionEngine
from src.models.schemas import ExecutionEvent, Scenario, ToolCall


class ContextAwareAgent(BaseAgent):
    name = "context-aware"

    def __init__(self, registry, provider, decision_engine: DecisionEngine | None = None) -> None:
        super().__init__(registry, provider)
        self.decision_engine = decision_engine or DecisionEngine(registry)
        self._detected = False

    def authorize(self, scenario: Scenario, call: ToolCall, history: list[ExecutionEvent]):
        decision = self.decision_engine.decide(scenario, call, history)
        self._detected = self._detected or bool(self.decision_engine.content.analyze(scenario.external_content))
        return decision

    def run(self, scenario: Scenario):
        result = super().run(scenario)
        result.suspicious_content_detected = self._detected
        return result

