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


class Permission(str, Enum):
    REPOSITORY_READ = "repository:read"
    REPOSITORY_WRITE = "repository:write"
    LOG_READ = "logs:read"
    K8S_READ = "k8s:read"
    K8S_WRITE = "k8s:write"
    SHELL_EXECUTE = "shell:execute"
    SECRET_READ = "secret:read"
    NETWORK_ACCESS = "network:access"


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


class SecurityDecision(BaseModel):
    decision: Decision
    risk_score: float = Field(ge=0.0, le=1.0)
    reasons: list[str]
    triggered_policy_rules: list[str] = Field(default_factory=list)
    intent_mismatch: bool = False
    privilege_escalation: bool = False
    data_exfiltration_pattern: bool = False


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


class TaskResult(BaseModel):
    trace_id: str
    scenario_id: str
    agent: str
    final_result: str
    events: list[ExecutionEvent]
    suspicious_content_detected: bool = False
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
    latency_ms: float = 0.0


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
