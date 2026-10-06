from __future__ import annotations

from src.defense.content_analyzer import ContentAnalyzer
from src.defense.intent_analyzer import IntentAnalyzer
from src.defense.policy_engine import PolicyEngine
from src.models.schemas import ExecutionEvent, SecurityContext, SecurityDecision, ToolCall
from src.tools.registry import ToolRegistry


class DecisionEngine:
    def __init__(self, registry: ToolRegistry, policy_engine: PolicyEngine | None = None) -> None:
        self.registry = registry
        self.policy_engine = policy_engine or PolicyEngine()
        self.content = ContentAnalyzer()
        self.intent = IntentAnalyzer()

    def build_context(self, scenario, call: ToolCall, history: list[ExecutionEvent]) -> SecurityContext:
        metadata = self.registry.metadata(call.tool_name)
        resources = [resource for event in history if event.result for resource in event.result.accessed_resources]
        return SecurityContext(
            original_user_request=scenario.user_request,
            inferred_user_intent=self.intent.infer(scenario.user_request),
            external_content_sources=scenario.external_content,
            suspicious_external_instructions=self.content.analyze(scenario.external_content),
            proposed_tool=metadata,
            proposed_arguments=call.arguments,
            execution_history=history,
            previously_accessed_resources=resources,
            requested_permissions=metadata.required_permissions,
            security_policy=self.policy_engine.policy,
            resource_risk_level=metadata.risk_level,
        )

    def decide(self, scenario, call: ToolCall, history: list[ExecutionEvent]) -> SecurityDecision:
        context = self.build_context(scenario, call, history)
        return self.policy_engine.evaluate(context, call)

