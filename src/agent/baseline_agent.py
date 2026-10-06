from __future__ import annotations

from src.agent.base_agent import BaseAgent
from src.models.schemas import Decision, ExecutionEvent, Scenario, SecurityDecision, ToolCall


class BaselineAgent(BaseAgent):
    name = "baseline"

    def authorize(self, scenario: Scenario, call: ToolCall, history: list[ExecutionEvent]) -> SecurityDecision:
        return SecurityDecision(decision=Decision.ALLOW, risk_score=0.0, reasons=["Baseline has no prompt-injection defense"])

