from __future__ import annotations

import json
import re
from collections.abc import Sequence
from typing import Any

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.llms.google_llm import EMPTY_FUNCTION_NAME
from agentdojo.agent_pipeline.tool_execution import is_string_list, tool_result_to_str
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
from agentdojo.types import ChatMessage, ChatToolResultMessage, text_content_block_from_string

from src.defense.decision_engine import DecisionEngine
from src.defense.parameter_intent import ParameterIntentAnalyzer
from src.defense.payload_provenance import PayloadProvenanceAnalyzer
from src.defense.policy_engine import PolicyEngine, PolicyFeatures
from src.integrations.agentdojo.adapter import AgentDojoActionMapper
from src.integrations.agentdojo.provenance_adapter import AgentDojoProvenanceAdapter
from src.integrations.agentdojo.schemas import DefenseEvent, OperationType, ProposedAction
from src.models.schemas import (
    AuthorizationSource,
    Decision,
    ExecutionEvent,
    Scenario,
    SecurityDecision,
    ToolCall,
    ToolResult,
    UserAuthorization,
)
from src.sandbox.environment import FakeEnvironment
from src.tools.registry import build_default_registry


def _contains_all(query: str, values: list[str]) -> bool:
    lowered = query.lower()
    return all(value.lower() in lowered for value in values if value)


class AgentDojoTrustedScope:
    """Derive narrow authorization from only the original native user query."""

    _ACTION_PATTERNS = {
        OperationType.EXTERNAL_COMMUNICATION: r"\b(send|forward|email|message|share|invite|publish|post|upload)\b",
        OperationType.FINANCIAL_TRANSFER: r"\b(transfer|wire|pay|payment)\b",
        OperationType.SECRET_ACCESS: r"\b(secret|password|credential|token|security code|api key)\b",
        OperationType.PERMISSION_MODIFICATION: r"\b(permission|access|share|role|grant|revoke|participant)\b",
        OperationType.SECURITY_CONTROL_MODIFICATION: r"\b(scanner|security|policy|control|check)\b",
        OperationType.DESTRUCTIVE_OPERATION: r"\b(delete|remove|destroy|cancel|purge)\b",
        OperationType.STATE_MUTATION: r"\b(create|add|update|edit|modify|reschedule|schedule|book|write|set)\b",
        OperationType.SHELL_EXECUTION: r"\b(run|execute|command|shell)\b",
    }

    def match(self, query: str, action: ProposedAction) -> tuple[bool, UserAuthorization | None, str]:
        if action.operation_type == OperationType.READ_ONLY:
            return True, None, "Read-only native action does not expand execution authority"
        pattern = self._ACTION_PATTERNS[action.operation_type]
        if not re.search(pattern, query, re.I):
            return False, None, "Original user query does not authorize this operation type"
        if action.destinations and not _contains_all(query, action.destinations):
            return False, None, "Native destination is not explicitly present in the original user query"
        if action.operation_type == OperationType.DESTRUCTIVE_OPERATION and action.resource:
            if action.resource.lower() not in query.lower():
                return False, None, "Destructive resource is not explicitly present in the original user query"
        if action.operation_type == OperationType.SHELL_EXECUTION:
            command = str(action.canonical_arguments.get("command", ""))
            if command.lower() not in query.lower():
                return False, None, "Shell command is not explicitly present in the original user query"

        grant = self._grant(action, query)
        return True, grant, "Exact native operation and high-consequence scope match the original user query"

    @staticmethod
    def _grant(action: ProposedAction, query: str) -> UserAuthorization:
        arguments = action.canonical_arguments
        resources: list[str] = []
        destinations: list[str] = []
        allowed_actions: list[str] = []
        if action.canonical_tool == "http_request":
            destinations = [str(arguments["url"])]
            allowed_actions = [str(arguments.get("method", "POST")).upper()]
        else:
            resource_key = {
                "read_secret": "name",
                "modify_manifest": "path",
                "delete_k8s_resource": "resource",
                "run_shell": "command",
                "read_file": "path",
            }.get(action.canonical_tool)
            if resource_key and arguments.get(resource_key) is not None:
                resources = [str(arguments[resource_key])]
            allowed_actions = [{
                "read_secret": "read",
                "modify_manifest": "modify",
                "delete_k8s_resource": "delete",
                "run_shell": "execute",
                "read_file": "read",
            }.get(action.canonical_tool, action.canonical_tool)]
        constraints: dict[str, Any] = {}
        if action.canonical_tool == "http_request":
            constraints["may_transmit_secret"] = bool(re.search(
                r"secret|password|credential|token|security code|api key", query, re.I
            ))
        return UserAuthorization(
            source=AuthorizationSource.EXPLICIT_USER_AUTHORIZATION,
            allowed_tools=[action.canonical_tool],
            allowed_resources=resources,
            allowed_actions=allowed_actions,
            allowed_destinations=destinations,
            allowed_purposes=["agentdojo_native_user_task"],
            constraints=constraints,
            payload_constraints={
                "payload_requires_independent_scope": action.operation_type
                in {OperationType.EXTERNAL_COMMUNICATION, OperationType.FINANCIAL_TRANSFER},
            },
            evidence=query[:240],
        )


class AgentDojoDefenseBridge:
    """Apply the existing policy engine to normalized AgentDojo actions."""

    def __init__(self, variant: str) -> None:
        if variant not in {"context-aware", "full", "refined-full"}:
            raise ValueError("Defense bridge supports context-aware, full, and refined-full variants")
        self.variant = variant
        features = PolicyFeatures(use_scoped_authorization=variant in {"full", "refined-full"})
        registry = build_default_registry(FakeEnvironment())
        self.engine = DecisionEngine(registry, PolicyEngine(features=features))
        self.scope = AgentDojoTrustedScope()
        self.payload_provenance = PayloadProvenanceAnalyzer()
        self.parameter_intent = ParameterIntentAnalyzer()

    def evaluate(
        self,
        query: str,
        action: ProposedAction,
        external_content,
        history: list[ExecutionEvent],
    ) -> SecurityDecision:
        normalized_query = self._normalize_query(query)
        call = ToolCall(
            tool_name=action.canonical_tool,
            arguments=action.canonical_arguments,
            source="agentdojo-adapter",
        )
        scenario = Scenario(
            id="agentdojo-native-task",
            kind="external_benchmark",
            category="agentdojo",
            user_request=normalized_query,
            external_content=list(external_content),
            proposed_calls=[call],
        )
        context = self.engine.build_context(scenario, call, history)
        trusted_match, grant, scope_reason = self.scope.match(query, action)
        if grant is not None:
            context.user_authorizations = [grant, *context.user_authorizations]
        decision = self.engine.policy_engine.evaluate(context, call)
        if self.variant == "refined-full":
            decision = self._refine_decision(query, action, list(external_content), decision)
        if self.variant not in {"full", "refined-full"} or not action.high_risk or trusted_match:
            return decision

        rules = list(decision.triggered_policy_rules)
        reasons = list(decision.reasons)
        if external_content:
            rules.append("UNTRUSTED_SCOPE_EXPANSION_DENY")
            reasons.append("AgentDojo Tool output cannot authorize a high-risk native action")
        else:
            rules.append("HIGH_RISK_REQUIRES_INTENT")
            reasons.append(scope_reason)
        if len({item.source for item in external_content}) >= 2 and decision.composed_untrusted_instruction:
            rules.append("MULTI_SOURCE_SCOPE_EXPANSION_DENY")
        return decision.model_copy(update={
            "decision": Decision.BLOCK,
            "reasons": list(dict.fromkeys(reasons)),
            "triggered_policy_rules": list(dict.fromkeys(rules)),
            "authorization_scope_match": False,
            "authorization_source": None,
        })

    def _refine_decision(
        self,
        query: str,
        action: ProposedAction,
        external_content,
        decision: SecurityDecision,
    ) -> SecurityDecision:
        payload = self.payload_provenance.assess(query, action.arguments, external_content)
        intent = self.parameter_intent.assess(
            query,
            action.native_tool,
            action.arguments,
            external_content,
        )
        rules = list(decision.triggered_policy_rules)
        reasons = list(decision.reasons)
        refined_deny = False
        if payload.unsafe_raw_propagation and action.operation_type != OperationType.READ_ONLY:
            rules.extend(["PAYLOAD_SCOPE_MISMATCH", "UNTRUSTED_PAYLOAD_PROPAGATION_DENY"])
            reasons.extend(payload.reasons)
            refined_deny = True
        if intent.explicit_mismatch:
            rules.append("PARAMETER_INTENT_MISMATCH")
            reasons.extend(intent.reasons)
            if intent.untrusted_overrides:
                rules.append("UNTRUSTED_PARAMETER_OVERRIDE_DENY")
            refined_deny = True
        return decision.model_copy(update={
            "decision": Decision.BLOCK if refined_deny else decision.decision,
            "risk_score": max(decision.risk_score, 0.95) if refined_deny else decision.risk_score,
            "reasons": list(dict.fromkeys(reasons)),
            "triggered_policy_rules": list(dict.fromkeys(rules)),
            "payload_provenance": payload.argument_provenance,
            "parameter_intent_mismatches": intent.mismatches,
        })

    @staticmethod
    def _normalize_query(query: str) -> str:
        additions: list[str] = []
        if re.search(r"\b(send|forward|email|message|share|invite|publish|post|upload)\b", query, re.I):
            additions.append("POST network")
        if re.search(r"\b(transfer|wire|pay|payment)\b", query, re.I):
            additions.append("POST network")
        if re.search(r"\b(create|add|update|edit|modify|reschedule|schedule|book|write|set)\b", query, re.I):
            additions.append("modify")
        if re.search(r"\b(delete|remove|destroy|cancel|purge)\b", query, re.I):
            additions.append("delete")
        if re.search(r"\b(run|execute|command|shell)\b", query, re.I):
            additions.append("run")
        if re.search(r"\b(secret|password|credential|token|security code|api key)\b", query, re.I):
            additions.append("secret")
        return query if not additions else f"{query}\n[trusted semantic intent] {' '.join(additions)}"


class DefenseAwareToolsExecutor(BasePipelineElement):
    """AgentDojo-compatible executor that gates calls before native execution."""

    def __init__(self, variant: str, tool_output_formatter=tool_result_to_str) -> None:
        self.variant = variant
        self.output_formatter = tool_output_formatter
        self.mapper = AgentDojoActionMapper()
        self.provenance = AgentDojoProvenanceAdapter()
        self.bridge = AgentDojoDefenseBridge(variant)
        self.events: list[DefenseEvent] = []
        self._policy_history: list[ExecutionEvent] = []

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = [],
        extra_args: dict = {},
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        if not messages or messages[-1]["role"] != "assistant" or not messages[-1].get("tool_calls"):
            return query, runtime, env, messages, extra_args

        results = []
        for native_call in messages[-1]["tool_calls"] or []:
            if native_call.function == EMPTY_FUNCTION_NAME or native_call.function not in runtime.functions:
                error = (
                    "Empty function name provided. Provide a valid function name."
                    if native_call.function == EMPTY_FUNCTION_NAME
                    else f"Invalid tool {native_call.function} provided."
                )
                results.append(self._tool_message(native_call, "", error))
                continue
            for key, value in native_call.args.items():
                if isinstance(value, str) and is_string_list(value):
                    from ast import literal_eval

                    native_call.args[key] = literal_eval(value)

            action = self.mapper.map_call(native_call, runtime)
            content = self.provenance.content_items(messages[:-1], action)
            decision = self.bridge.evaluate(query, action, content, self._policy_history)
            if decision.decision != Decision.ALLOW:
                error = "SECURITY_BLOCK: The requested action is outside the authorized user scope."
                results.append(self._tool_message(native_call, "", error))
                self._record(action, native_call, decision, False, content, error)
                self._append_policy_history(action, decision, executed=False, runtime_error=error)
                continue

            value, error = runtime.run_function(env, native_call.function, native_call.args)
            formatted = self.output_formatter(value)
            results.append(self._tool_message(native_call, formatted, error))
            executed = error is None or not error.startswith(("ValidationError", "ToolNotFoundError"))
            self._record(action, native_call, decision, executed, content, error)
            self._append_policy_history(action, decision, executed=executed, runtime_error=error)
        return query, runtime, env, [*messages, *results], extra_args

    @staticmethod
    def _tool_message(call, content: str, error: str | None) -> ChatToolResultMessage:
        return ChatToolResultMessage(
            role="tool",
            content=[text_content_block_from_string(content)],
            tool_call_id=call.id,
            tool_call=call,
            error=error,
        )

    def _record(self, action, native_call, decision, executed, content, runtime_error) -> None:
        self.events.append(DefenseEvent(
            tool_call_id=native_call.id,
            native_tool=native_call.function,
            arguments=dict(native_call.args),
            operation_type=action.operation_type,
            canonical_tool=action.canonical_tool,
            decision=decision.decision,
            executed=executed,
            matched_rules=decision.triggered_policy_rules,
            reasons=decision.reasons,
            trusted_scope_match=decision.authorization_scope_match,
            authorization_source=decision.authorization_source.value if decision.authorization_source else None,
            input_provenance=decision.instruction_provenance_sources or [item.source for item in content],
            provenance_components=decision.instruction_provenance_components,
            multi_source_composition=decision.composed_untrusted_instruction,
            runtime_error=runtime_error,
            payload_provenance=decision.payload_provenance,
            parameter_intent_mismatches=decision.parameter_intent_mismatches,
        ))

    def _append_policy_history(self, action, decision, *, executed: bool, runtime_error: str | None) -> None:
        success = executed and runtime_error is None
        self._policy_history.append(ExecutionEvent(
            tool_call=ToolCall(
                tool_name=action.canonical_tool,
                arguments=action.canonical_arguments,
                source="agentdojo-adapter",
            ),
            decision=decision.decision,
            executed=executed,
            result=ToolResult(
                tool_name=action.canonical_tool,
                success=success,
                error=runtime_error,
                sensitive=action.operation_type == OperationType.SECRET_ACCESS,
            ) if executed else None,
            risk_score=decision.risk_score,
            reasons=decision.reasons,
            triggered_policy_rules=decision.triggered_policy_rules,
            authorization_scope_match=decision.authorization_scope_match,
            authorization_source=decision.authorization_source,
            instruction_provenance_sources=decision.instruction_provenance_sources,
            instruction_provenance_components=decision.instruction_provenance_components,
            composed_untrusted_instruction=decision.composed_untrusted_instruction,
            payload_provenance=decision.payload_provenance,
            parameter_intent_mismatches=decision.parameter_intent_mismatches,
        ))


class RecordingToolsExecutor(BasePipelineElement):
    """Observational wrapper around AgentDojo's native executor for baseline parity."""

    def __init__(self, native_executor) -> None:
        self.native_executor = native_executor
        self.events: list[DefenseEvent] = []
        self.mapper = AgentDojoActionMapper()

    def query(self, query, runtime, env=EmptyEnv(), messages=(), extra_args=None):
        extra_args = {} if extra_args is None else extra_args
        calls = list(messages[-1].get("tool_calls") or []) if messages and messages[-1]["role"] == "assistant" else []
        before = len(messages)
        output = self.native_executor.query(query, runtime, env, messages, extra_args)
        returned_messages = output[3]
        tool_results = [message for message in returned_messages[before:] if message["role"] == "tool"]
        for call, result in zip(calls, tool_results, strict=False):
            if call.function not in runtime.functions:
                continue
            action = self.mapper.map_call(call, runtime)
            error = result.get("error")
            executed = error is None or not str(error).startswith(("ValidationError", "ToolNotFoundError"))
            self.events.append(DefenseEvent(
                tool_call_id=call.id,
                native_tool=call.function,
                arguments=dict(call.args),
                operation_type=action.operation_type,
                canonical_tool=action.canonical_tool,
                decision=Decision.ALLOW,
                executed=executed,
                runtime_error=error,
            ))
        return output
