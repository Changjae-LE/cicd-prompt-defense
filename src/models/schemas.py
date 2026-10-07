from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class TrustLabel(str, Enum):
    TRUSTED_USER = "TRUSTED_USER"
    TRUSTED_POLICY = "TRUSTED_POLICY"
    UNTRUSTED_REPOSITORY = "UNTRUSTED_REPOSITORY"
    UNTRUSTED_LOG = "UNTRUSTED_LOG"
    UNTRUSTED_WEB = "UNTRUSTED_WEB"
    TOOL_OUTPUT = "TOOL_OUTPUT"


class Decision(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class TerminationReason(str, Enum):
    TASK_COMPLETED = "TASK_COMPLETED"
    ATTACK_SUCCEEDED = "ATTACK_SUCCEEDED"
    SECURITY_BLOCK = "SECURITY_BLOCK"
    RESOURCE_NOT_FOUND = "RESOURCE_NOT_FOUND"
    INVALID_TOOL = "INVALID_TOOL"
    INVALID_ARGUMENTS = "INVALID_ARGUMENTS"
    PARSING_ERROR = "PARSING_ERROR"
    PROVIDER_ERROR = "PROVIDER_ERROR"
    REPEATED_FAILED_TOOL_CALL = "REPEATED_FAILED_TOOL_CALL"
    MAX_STEPS = "MAX_STEPS"
    MODEL_STOPPED = "MODEL_STOPPED"
    GOAL_SATISFIED = "GOAL_SATISFIED"
    POST_TASK_AUDIT_COMPLETE = "POST_TASK_AUDIT_COMPLETE"


class GoalStatus(str, Enum):
    NOT_STARTED = "NOT_STARTED"
    IN_PROGRESS = "IN_PROGRESS"
    SATISFIED = "SATISFIED"
    FAILED = "FAILED"


class ExecutionPhase(str, Enum):
    TASK_EXECUTION = "TASK_EXECUTION"
    POST_TASK_AUDIT = "POST_TASK_AUDIT"


class Sensitivity(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    SENSITIVE = "SENSITIVE"
    SECRET = "SECRET"
    SECRET_DERIVED = "SECRET_DERIVED"


class DataArtifact(BaseModel):
    artifact_id: str
    symbolic_ref: str
    sensitivity: Sensitivity
    source_tool: str
    source_resource: str | None = None
    source_trust_label: TrustLabel | None = None
    derived_from: list[str] = Field(default_factory=list)
    transformations: list[str] = Field(default_factory=list)
    created_at_step: int
    safe_representation: str


class DataFlowEdge(BaseModel):
    source_artifact_id: str
    target_artifact_id: str | None = None
    sink: str | None = None
    tool_name: str
    step: int
    blocked: bool = False


class GoalRequirement(BaseModel):
    tool_name: str
    resource_argument: str | None = None
    allowed_resources: list[str] = Field(default_factory=list)
    minimum_successes: int = Field(default=1, ge=1)


class GoalDefinition(BaseModel):
    requirements: list[GoalRequirement] = Field(default_factory=list)
    require_all: bool = True
    description: str = ""


class Permission(str, Enum):
    REPOSITORY_READ = "repository:read"
    REPOSITORY_WRITE = "repository:write"
    LOG_READ = "logs:read"
    LOG_WRITE = "logs:write"
    K8S_READ = "k8s:read"
    K8S_WRITE = "k8s:write"
    SHELL_EXECUTE = "shell:execute"
    SECRET_READ = "secret:read"
    NETWORK_ACCESS = "network:access"


class AuthorizationSource(str, Enum):
    EXPLICIT_USER_AUTHORIZATION = "EXPLICIT_USER_AUTHORIZATION"
    TRUSTED_POLICY_AUTHORIZATION = "TRUSTED_POLICY_AUTHORIZATION"
    DERIVED_TASK_AUTHORIZATION = "DERIVED_TASK_AUTHORIZATION"
    UNTRUSTED_CONTENT_REQUEST = "UNTRUSTED_CONTENT_REQUEST"


class UserAuthorization(BaseModel):
    source: AuthorizationSource
    allowed_tools: list[str] = Field(default_factory=list)
    allowed_resources: list[str] = Field(default_factory=list)
    allowed_actions: list[str] = Field(default_factory=list)
    allowed_destinations: list[str] = Field(default_factory=list)
    allowed_purposes: list[str] = Field(default_factory=list)
    constraints: dict[str, Any] = Field(default_factory=dict)
    evidence: str = ""


class ContentItem(BaseModel):
    source: str
    trust_label: TrustLabel
    content: str


class ToolMetadata(BaseModel):
    name: str
    description: str
    required_permissions: list[Permission]
    risk_level: RiskLevel
    changes_state: bool = False
    accesses_secret: bool = False
    accesses_network: bool = False
    executes_command: bool = False
    allowed_argument_patterns: dict[str, str] = Field(default_factory=dict)
    allowed_argument_values: dict[str, list[str]] = Field(default_factory=dict)


class ToolCall(BaseModel):
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    source: str = "provider"
    rationale: str = ""
    is_malicious: bool = False


class ToolResult(BaseModel):
    tool_name: str
    success: bool
    output: Any = None
    error: str | None = None
    error_code: str | None = None
    accessed_resources: list[str] = Field(default_factory=list)
    sensitive: bool = False


class ExecutionEvent(BaseModel):
    tool_call: ToolCall
    decision: Decision
    executed: bool
    result: ToolResult | None = None
    risk_score: float = 0.0
    reasons: list[str] = Field(default_factory=list)
    triggered_policy_rules: list[str] = Field(default_factory=list)
    intent_mismatch: bool = False
    privilege_escalation: bool = False
    data_exfiltration_pattern: bool = False
    authorization_scope_match: bool = False
    authorization_source: AuthorizationSource | None = None
    execution_phase: ExecutionPhase = ExecutionPhase.TASK_EXECUTION
    before_goal_completion: bool = True
    redundant: bool = False
    post_task_malicious: bool = False
    audit_only: bool = False
    input_artifact_ids: list[str] = Field(default_factory=list)
    output_artifact_ids: list[str] = Field(default_factory=list)
    provenance_policy_rules: list[str] = Field(default_factory=list)


class SecurityContext(BaseModel):
    original_user_request: str
    inferred_user_intent: list[str]
    external_content_sources: list[ContentItem]
    suspicious_external_instructions: list[str]
    proposed_tool: ToolMetadata
    proposed_arguments: dict[str, Any]
    execution_history: list[ExecutionEvent]
    previously_accessed_resources: list[str]
    requested_permissions: list[Permission]
    security_policy: dict[str, Any]
    resource_risk_level: RiskLevel
    user_authorizations: list[UserAuthorization] = Field(default_factory=list)


class SecurityDecision(BaseModel):
    decision: Decision
    risk_score: float = Field(ge=0.0, le=1.0)
    reasons: list[str]
    triggered_policy_rules: list[str] = Field(default_factory=list)
    intent_mismatch: bool = False
    privilege_escalation: bool = False
    data_exfiltration_pattern: bool = False
    authorization_scope_match: bool = False
    authorization_source: AuthorizationSource | None = None


class Scenario(BaseModel):
    id: str
    kind: str
    category: str
    user_request: str
    external_content: list[ContentItem]
    proposed_calls: list[ToolCall]
    expected_safe_tools: list[str] = Field(default_factory=list)
    malicious_tools: list[str] = Field(default_factory=list)
    description: str = ""
    goal: GoalDefinition | None = None
    provenance_sources: dict[str, Sensitivity] = Field(default_factory=dict)


class TaskResult(BaseModel):
    trace_id: str
    scenario_id: str
    agent: str
    final_result: str
    events: list[ExecutionEvent]
    suspicious_content_detected: bool = False
    raw_suspicious_content_detected: bool = False
    task_completed: bool = False
    attack_succeeded: bool = False
    llm_calls: int = 0
    estimated_tokens: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    token_usage_estimated: bool = True
    llm_latency_ms: float = 0.0
    estimated_cost_usd: float = 0.0
    provider_error: str | None = None
    provider_error_code: str | None = None
    termination_reason: TerminationReason = TerminationReason.MODEL_STOPPED
    latency_ms: float = 0.0
    goal_status: GoalStatus = GoalStatus.NOT_STARTED
    goal_satisfied_after_event: int | None = None
    post_task_proposal_count: int = 0
    redundant_post_task_calls: int = 0
    malicious_post_task_proposals: int = 0
    blocked_post_task_proposals: int = 0
    provenance_artifacts: list[DataArtifact] = Field(default_factory=list)
    provenance_edges: list[DataFlowEdge] = Field(default_factory=list)


class AgentMetrics(BaseModel):
    agent: str
    attack_success_rate: float
    defense_detection_rate: float
    false_positive_rate: float
    false_negative_rate: float
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    task_completion_rate: float
    benign_completion_rate: float
    high_risk_tool_invocation_rate: float
    average_blocked_calls: float
    average_latency_ms: float
    average_llm_calls: float
    average_tokens: float
    estimated_cost_usd: float
    context_aware_overhead_ms: float = 0.0
    context_aware_overhead_percent: float = 0.0
    attack_category_rates: dict[str, float] = Field(default_factory=dict)
