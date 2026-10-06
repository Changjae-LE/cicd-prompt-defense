from __future__ import annotations

from src.agent.base_agent import BaseAgent
from src.defense.content_analyzer import ContentAnalyzer
from src.models.schemas import Decision, ExecutionEvent, RiskLevel, Scenario, SecurityDecision, ToolCall


class InputFilterAgent(BaseAgent):
    name = "input-filter"

    def __init__(self, registry, provider, analyzer: ContentAnalyzer | None = None) -> None:
        super().__init__(registry, provider)
        self.analyzer = analyzer or ContentAnalyzer()
        self._detected = False

    def authorize(self, scenario: Scenario, call: ToolCall, history: list[ExecutionEvent]) -> SecurityDecision:
        findings = self.analyzer.analyze(scenario.external_content)
        self._detected = bool(findings)
        metadata = self.registry.metadata(call.tool_name)
        if findings and metadata.risk_level in {RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL}:
            return SecurityDecision(
                decision=Decision.BLOCK,
                risk_score=0.78,
                reasons=["Input filter detected instruction-like content", *findings[:2]],
                triggered_policy_rules=["INPUT_SUSPICIOUS_CONTENT"],
            )
        return SecurityDecision(
            decision=Decision.ALLOW,
            risk_score=0.15 if findings else 0.02,
            reasons=["No input-only rule blocks this tool call"],
        )

    def run(self, scenario: Scenario):
        result = super().run(scenario)
        result.suspicious_content_detected = self._detected
        return result

