from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re

import yaml

from src.defense.history_analyzer import HistoryAnalyzer
from src.defense.authorization import AuthorizationResolver
from src.defense.intent_analyzer import IntentAnalyzer
from src.defense.risk_engine import RiskEngine
from src.defense.tool_call_analyzer import ToolCallAnalyzer
from src.defense.trust_boundary import TrustBoundary
from src.models.schemas import Decision, RiskLevel, SecurityContext, SecurityDecision, ToolCall


DEFAULT_POLICY_PATH = Path(__file__).resolve().parents[2] / "configs" / "security_policy.yaml"


@dataclass(frozen=True)
class PolicyFeatures:
    use_execution_history: bool = True
    use_intent_alignment: bool = True
    use_trust_boundary: bool = True
    use_sequence_risk: bool = True
    use_policy_engine: bool = True
    use_scoped_authorization: bool = False


class PolicyEngine:
    """Deterministic final enforcement. Provider output cannot bypass these rules."""

    def __init__(self, policy_path: Path | str = DEFAULT_POLICY_PATH, features: PolicyFeatures | None = None) -> None:
        self.policy = yaml.safe_load(Path(policy_path).read_text(encoding="utf-8"))
        self.features = features or PolicyFeatures()
        self.intent = IntentAnalyzer()
        self.history = HistoryAnalyzer()
        self.tool_calls = ToolCallAnalyzer()
        self.risk = RiskEngine(self.policy)
        self.authorization = AuthorizationResolver()

    def evaluate(self, context: SecurityContext, call: ToolCall) -> SecurityDecision:
        meta = context.proposed_tool
        if not self.features.use_policy_engine:
            return SecurityDecision(
                decision=Decision.ALLOW,
                risk_score=0.0,
                reasons=["Ablation: deterministic policy enforcement removed"],
            )
        mismatch = not self.intent.aligned(context.original_user_request, meta.name) if self.features.use_intent_alignment else False
        explicit = self.intent.explicit(context.original_user_request, meta.name) if self.features.use_intent_alignment else True
        untrusted = TrustBoundary.contains_untrusted(context.external_content_sources) if self.features.use_trust_boundary else False
        suspicious = bool(context.suspicious_external_instructions)
        high_risk = meta.risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}
        privilege_escalation = high_risk and (mismatch or not explicit)
        sequence_signals = self.history.analyze(context.execution_history, call) if self.features.use_execution_history else []
        active_sequence_signals = sequence_signals if self.features.use_sequence_risk else []
        exfiltration = self.tool_calls.data_exfiltration(call, meta, active_sequence_signals)
        privileged = self.tool_calls.privileged_change(call)
        untrusted_high = untrusted and suspicious and meta.risk_level in {RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL}
        authorization = self.authorization.match(context.user_authorizations, call)
        untrusted_authorization = self.authorization.match_untrusted(context.user_authorizations, call)
        scoped = self.features.use_scoped_authorization and authorization.matched
        sensitive_egress_authorization = (
            self.authorization.match_sensitive_egress(
                context.user_authorizations,
                call,
                context.execution_history,
            )
            if self.features.use_scoped_authorization and exfiltration
            else None
        )
        sensitive_egress_scoped = bool(
            sensitive_egress_authorization and sensitive_egress_authorization.matched
        )
        untrusted_scope_expansion = (
            self.features.use_scoped_authorization and untrusted_authorization.matched and not scoped
        )
        score = self.risk.score(
            meta.risk_level,
            suspicious=suspicious,
            mismatch=mismatch,
            escalation=privilege_escalation or privileged,
            sequence=bool(active_sequence_signals),
            untrusted_high_risk=untrusted_high,
        )
        rules: list[str] = []
        reasons: list[str] = []

        if exfiltration and not sensitive_egress_scoped:
            rules.append("SECRET_TO_NETWORK_DENY")
            reasons.append("Secret access followed by network transmission lacks an exact trusted egress grant")
        if exfiltration and sensitive_egress_scoped:
            rules.append("SCOPED_SECRET_EGRESS_AUTHORIZATION")
            reasons.append(sensitive_egress_authorization.reason)
        if meta.accesses_secret and not explicit and not scoped:
            rules.append("SECRET_REQUIRES_EXPLICIT_INTENT")
            reasons.append("Secret access is not explicitly required by the user")
        if untrusted_high and not scoped:
            rules.extend(["UNTRUSTED_HIGH_RISK_DENY", "EXTERNAL_CANNOT_OVERRIDE_POLICY"])
            reasons.append("Untrusted content cannot authorize a medium/high-risk action")
        if untrusted_high and scoped:
            rules.append("SCOPED_USER_AUTHORIZATION")
            reasons.append("Trusted user scope covers this exact Tool call; untrusted content did not expand the scope")
        if untrusted_scope_expansion:
            rules.append("UNTRUSTED_SCOPE_EXPANSION_DENY")
            reasons.append("Untrusted content requested a Tool call outside trusted user/task authorization scope")
        if high_risk and mismatch and not scoped:
            rules.append("HIGH_RISK_REQUIRES_INTENT")
            reasons.append("High-risk tool is unrelated to the original user intent")
        if privileged and not scoped:
            rules.append("HIGH_RISK_REQUIRES_INTENT")
            reasons.append("Arguments request privileged infrastructure configuration")
        if self._security_control_mutation(call) and not scoped:
            rules.append("SECURITY_CONTROL_SCOPE_DENY")
            reasons.append("Security-control mutation is outside exact trusted user and policy scope")
        if meta.executes_command and call.arguments.get("command") not in self.policy["shell_allowlist"]:
            rules.append("SHELL_ALLOWLIST_ONLY")
            reasons.append("Shell command is outside the policy allowlist")

        hard_deny = bool(set(rules) & {
            "SECRET_TO_NETWORK_DENY", "SECRET_REQUIRES_EXPLICIT_INTENT", "UNTRUSTED_HIGH_RISK_DENY",
            "HIGH_RISK_REQUIRES_INTENT", "SHELL_ALLOWLIST_ONLY",
            "UNTRUSTED_SCOPE_EXPANSION_DENY",
            "SECURITY_CONTROL_SCOPE_DENY",
        })
        if hard_deny:
            decision = Decision.BLOCK
        elif meta.name == "delete_k8s_resource":
            decision = Decision.REQUIRE_APPROVAL
            rules.append("DESTRUCTIVE_K8S_APPROVAL")
            reasons.append("Destructive Kubernetes action requires separate approval")
        elif score >= self.policy["thresholds"]["block"] and mismatch and not scoped:
            decision = Decision.BLOCK
        elif score >= self.policy["thresholds"]["require_approval"] and high_risk and not explicit and not scoped:
            decision = Decision.REQUIRE_APPROVAL
        else:
            decision = Decision.ALLOW
            reasons.append("Tool call is aligned with user intent and no deterministic deny rule matched")

        return SecurityDecision(
            decision=decision,
            risk_score=score,
            reasons=reasons,
            triggered_policy_rules=list(dict.fromkeys(rules)),
            intent_mismatch=mismatch,
            privilege_escalation=privilege_escalation or privileged,
            data_exfiltration_pattern=exfiltration,
            authorization_scope_match=scoped,
            authorization_source=(
                sensitive_egress_authorization.source
                if sensitive_egress_scoped and sensitive_egress_authorization
                else authorization.source if scoped else None
            ),
        )

    def _security_control_mutation(self, call: ToolCall) -> bool:
        if call.tool_name not in {"modify_manifest", "create_patch", "write_file"}:
            return False
        path = str(call.arguments.get("path", "")).lower()
        content = str(call.arguments.get("content", "")).lower()
        configured_paths = {
            str(item).lower()
            for item in self.policy.get("security_control_policy", {}).get("workflow_paths", [])
        }
        security_content = re.search(
            r"cluster-admin|clusterrolebinding|rolebinding|\brbac\b|"
            r"(?:disable|remove|omit|skip|replace)[^\n]{0,80}(?:scan|security check)|"
            r"(?:scan|security check)[^\n]{0,80}(?:disable|remove|omit|skip|replace)",
            content,
            re.I,
        )
        return path in configured_paths or bool(security_content)
