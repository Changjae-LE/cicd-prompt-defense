from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from src.models.schemas import Decision, PayloadProvenance


class OperationType(str, Enum):
    READ_ONLY = "read_only"
    EXTERNAL_COMMUNICATION = "external_communication"
    FINANCIAL_TRANSFER = "financial_transfer"
    SECRET_ACCESS = "secret_access"
    PERMISSION_MODIFICATION = "permission_modification"
    SECURITY_CONTROL_MODIFICATION = "security_control_modification"
    DESTRUCTIVE_OPERATION = "destructive_operation"
    STATE_MUTATION = "state_mutation"
    SHELL_EXECUTION = "shell_execution"


class ProposedAction(BaseModel):
    native_tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    operation_type: OperationType
    canonical_tool: str
    canonical_arguments: dict[str, Any] = Field(default_factory=dict)
    resource: str | None = None
    destination: str | None = None
    destinations: list[str] = Field(default_factory=list)
    http_method: str | None = None
    payload: str | None = None
    credential_identity: str | None = None
    mutation_target: str | None = None
    namespace: str | None = None
    path: str | None = None
    source_tool_description: str = ""

    @property
    def high_risk(self) -> bool:
        return self.operation_type != OperationType.READ_ONLY


class DefenseEvent(BaseModel):
    tool_call_id: str | None = None
    native_tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    operation_type: OperationType
    canonical_tool: str
    decision: Decision
    executed: bool
    matched_rules: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    trusted_scope_match: bool = False
    authorization_source: str | None = None
    input_provenance: list[str] = Field(default_factory=list)
    provenance_components: dict[str, list[str]] = Field(default_factory=dict)
    multi_source_composition: bool = False
    runtime_error: str | None = None
    malicious_ground_truth_match: bool | None = None
    payload_provenance: dict[str, PayloadProvenance] = Field(default_factory=dict)
    parameter_intent_mismatches: list[str] = Field(default_factory=list)


class CompatibilityResult(BaseModel):
    model: str
    model_available: bool
    tool_calling_available: bool
    parsing_failures: int = 0
    invalid_tool_count: int = 0
    invalid_argument_count: int = 0
    provider_error_count: int = 0
    successful_native_task_execution: bool = False
    proposed_tool_calls: int = 0
    error: str | None = None


class PilotCaseResult(BaseModel):
    agentdojo_version: str
    python_version: str
    benchmark_version: str
    suite: str
    user_task_id: str
    injection_task_id: str
    attack: str
    model: str
    provider: str
    model_identifier: str
    defense: str
    temperature: float
    run_index: int
    native_utility_result: bool | None
    native_security_result: bool | None
    attack_success: bool | None
    defense_events: list[DefenseEvent] = Field(default_factory=list)
    malicious_tool_proposed: bool | None = None
    malicious_tool_blocked: bool | None = None
    termination_status: str = "completed"
    provider_tool_compatibility: str = "ok"
    user_request: str
    injection_goal_summary: str
    llm_call_count: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    token_usage_available: bool = False
    llm_latency_ms: float = 0.0
    case_latency_ms: float = 0.0
