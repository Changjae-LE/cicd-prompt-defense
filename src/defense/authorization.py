from __future__ import annotations

import re
from dataclasses import dataclass

from src.models.schemas import AuthorizationSource, ContentItem, ToolCall, ToolMetadata, TrustLabel, UserAuthorization


@dataclass(frozen=True)
class AuthorizationMatch:
    matched: bool
    source: AuthorizationSource | None = None
    reason: str = ""
    grant: UserAuthorization | None = None


class AuthorizationResolver:
    """Build narrow grants from trusted user text; external text is audit-only."""

    URL = re.compile(r"https?://[^\s,;]+", re.I)
    IDENTIFIER = re.compile(r"\b[a-z][a-z0-9]*(?:[-_][a-z0-9]+)+\b", re.I)
    PATH = re.compile(r"(?:[A-Za-z0-9_.-]+/)+(?:[A-Za-z0-9_.-]+)")
    SERVICES = {
        "billing", "catalog", "checkout", "events", "identity", "media", "orders", "search", "shipping", "support"
    }

    PURPOSE_PATTERNS = (
        ("credential_rotation", r"credential rotation|rotation proof|rotate\w* (?:the )?(?:\w+ )?(?:credential|token|api key)"),
        ("redaction_test", r"redaction test|redact"),
        ("deployment_health_check", r"health (?:url|check|endpoint)|operational status"),
        ("rbac_change", r"rbac|cluster-admin|break-glass"),
        ("security_scanner_change", r"scanner|vulnerability scan"),
        ("deployment_change", r"deploy|rollout|manifest"),
        ("security_troubleshooting", r"security troubleshooting|credential and http troubleshooting"),
        ("direct_resource_access", r"\bread\b|\bget\b|\bpost\b|\bmodify\b|\bapply\b|\bdelete\b"),
    )

    def resolve(
        self,
        user_request: str,
        external_content: list[ContentItem],
        tools: list[ToolMetadata],
        security_policy: dict | None = None,
    ) -> list[UserAuthorization]:
        grants = self._from_text(
            user_request,
            AuthorizationSource.EXPLICIT_USER_AUTHORIZATION,
            tools,
            security_policy=security_policy,
        )
        grants.extend(self._derived(user_request, tools))
        grants.extend(self._trusted_policy(user_request, security_policy or {}))
        for item in external_content:
            if item.trust_label == TrustLabel.TRUSTED_USER:
                source = AuthorizationSource.EXPLICIT_USER_AUTHORIZATION
                evidence = f"{user_request}\n{item.content}"
            elif item.trust_label == TrustLabel.TRUSTED_POLICY:
                source = AuthorizationSource.TRUSTED_POLICY_AUTHORIZATION
                evidence = f"{user_request}\n{item.content}"
            else:
                source = AuthorizationSource.UNTRUSTED_CONTENT_REQUEST
                evidence = item.content
            grants.extend(self._from_text(
                evidence,
                source,
                tools,
                security_policy=security_policy if source != AuthorizationSource.UNTRUSTED_CONTENT_REQUEST else None,
            ))
        return self._deduplicate(grants)

    def match(self, authorizations: list[UserAuthorization], call: ToolCall) -> AuthorizationMatch:
        trusted = [
            grant for grant in authorizations
            if grant.source in {
                AuthorizationSource.EXPLICIT_USER_AUTHORIZATION,
                AuthorizationSource.TRUSTED_POLICY_AUTHORIZATION,
                AuthorizationSource.DERIVED_TASK_AUTHORIZATION,
            }
        ]
        order = {
            AuthorizationSource.EXPLICIT_USER_AUTHORIZATION: 0,
            AuthorizationSource.TRUSTED_POLICY_AUTHORIZATION: 1,
            AuthorizationSource.DERIVED_TASK_AUTHORIZATION: 2,
        }
        trusted.sort(key=lambda grant: order.get(grant.source, 3))
        for grant in trusted:
            if self.grant_matches(grant, call):
                return AuthorizationMatch(
                    True,
                    grant.source,
                    f"Call is within {grant.source.value} scope",
                    grant,
                )
        return AuthorizationMatch(False, None, "No trusted authorization grant exactly covers the Tool call")

    def match_untrusted(self, authorizations: list[UserAuthorization], call: ToolCall) -> AuthorizationMatch:
        for grant in authorizations:
            if grant.source != AuthorizationSource.UNTRUSTED_CONTENT_REQUEST:
                continue
            if self.grant_matches(grant, call):
                return AuthorizationMatch(
                    True,
                    grant.source,
                    "Call is requested only by untrusted content",
                    grant,
                )
        return AuthorizationMatch(False, None, "No matching untrusted content request")

    def grant_matches(self, grant: UserAuthorization, call: ToolCall) -> bool:
        if call.tool_name not in grant.allowed_tools:
            return False
        if grant.allowed_actions and self._call_action(call) not in grant.allowed_actions:
            return False
        if not self._resource_matches(grant, call) or not self._destination_matches(grant, call):
            return False
        return self._content_constraints_match(grant, call)

    def match_sensitive_egress(
        self,
        authorizations: list[UserAuthorization],
        call: ToolCall,
        history,
    ) -> AuthorizationMatch:
        accessed = {
            str(event.tool_call.arguments.get("name", ""))
            for event in history
            if event.executed and event.tool_call.tool_name == "read_secret"
        }
        trusted_secret_scope = {
            resource
            for grant in authorizations
            if grant.source != AuthorizationSource.UNTRUSTED_CONTENT_REQUEST
            and "read_secret" in grant.allowed_tools
            for resource in grant.allowed_resources
        }
        for grant in authorizations:
            if grant.source == AuthorizationSource.UNTRUSTED_CONTENT_REQUEST:
                continue
            if not grant.constraints.get("may_transmit_secret") or not self.grant_matches(grant, call):
                continue
            allowed_resources = set(grant.constraints.get("allowed_sensitive_resources", []))
            if allowed_resources and not allowed_resources.intersection(accessed):
                continue
            if accessed and not accessed.issubset(allowed_resources or trusted_secret_scope):
                continue
            payload_patterns = grant.constraints.get("payload_patterns", [])
            body = str(call.arguments.get("body", ""))
            if payload_patterns and not any(re.search(pattern, body, re.I | re.S) for pattern in payload_patterns):
                continue
            return AuthorizationMatch(
                True,
                grant.source,
                "Sensitive egress is within exact trusted destination, method, data, and purpose scope",
                grant,
            )
        return AuthorizationMatch(False, None, "No exact trusted sensitive-egress grant covers this call")

    def _from_text(
        self,
        text: str,
        source: AuthorizationSource,
        tools: list[ToolMetadata],
        *,
        security_policy: dict | None = None,
    ) -> list[UserAuthorization]:
        lowered = text.lower()
        purposes = self._purposes(lowered)
        grants: list[UserAuthorization] = []
        secret_resources = self._secret_resources(lowered, tools)
        direct_secret = bool(re.search(r"\b(read|access|fetch|get)\b", lowered)) and bool(secret_resources)
        if direct_secret and secret_resources:
            grants.append(self._grant(
                source, "read_secret", secret_resources, ["read"], [], purposes,
                {"network_exfiltration": False}, text,
            ))

        urls = [url.rstrip(".)]}") for url in self.URL.findall(text)]
        http_action = self._http_action(lowered)
        untrusted_network_reference = source == AuthorizationSource.UNTRUSTED_CONTENT_REQUEST and bool(urls)
        if urls and (http_action or untrusted_network_reference):
            permits_sensitive = bool(
                source != AuthorizationSource.UNTRUSTED_CONTENT_REQUEST
                and self._permits_sensitive_egress(lowered)
            )
            grants.append(self._grant(
                source,
                "http_request",
                [],
                [http_action] if http_action else [],
                urls,
                purposes,
                {
                    "may_transmit_secret": permits_sensitive,
                    "allowed_sensitive_resources": secret_resources if permits_sensitive else [],
                },
                text,
            ))

        if re.search(r"\b(update|modify|change|edit|disable|replace|grant|bind|remove|omit|skip)\b", lowered) and re.search(
            r"manifest|workflow|rbac|scanner|scanning|cluster-admin|rolebinding|security checks?|configuration|config", lowered
        ):
            resources = self._manifest_resources(lowered)
            if resources:
                constraints: dict[str, object] = {"content_must_match_purpose": True}
                if "rbac_change" in purposes:
                    rbac_targets = [
                        target for target in ("cluster-admin", "clusterrolebinding", "rolebinding")
                        if target in lowered
                    ]
                    if rbac_targets:
                        constraints["required_content_any"] = rbac_targets
                if "security_scanner_change" in purposes and security_policy:
                    control_policy = security_policy.get("security_control_policy", {})
                    constraints["required_content_all"] = list(control_policy.get("required_controls", []))
                    constraints["allowed_disabled_controls"] = list(control_policy.get("retired_controls", []))
                grants.append(self._grant(
                    source, "modify_manifest", resources, ["modify"], [], purposes,
                    constraints, text,
                ))

        if re.search(r"\b(write|store|record)\b", lowered):
            resources = self._manifest_resources(lowered)
            permits_sensitive = bool(re.search(r"secret|token|credential|api[-_ ]?key", lowered))
            if resources and re.search(r"\b(file|repository|escrow)\b", lowered):
                grants.append(self._grant(
                    source, "write_file", resources, ["write"], [], purposes,
                    {"may_transmit_secret": permits_sensitive}, text,
                ))
            if resources and "log" in lowered:
                grants.append(self._grant(
                    source, "write_log", resources, ["write"], [], purposes,
                    {"may_transmit_secret": permits_sensitive}, text,
                ))

        if re.search(r"\b(apply|deploy)\b", lowered) and "do not deploy" not in lowered:
            resources = self._manifest_resources(lowered)
            if resources:
                grants.append(self._grant(source, "apply_manifest", resources, ["apply"], [], purposes, {}, text))

        if re.search(r"\b(run|execute)\b", lowered):
            commands = [command for command in ("pytest", "git diff", "kubectl get pods", "docker build --check .") if command in lowered]
            if "test suite" in lowered:
                commands.append("pytest")
            if commands:
                grants.append(self._grant(source, "run_shell", sorted(set(commands)), ["execute"], [], purposes, {}, text))

        for resource in re.findall(r"\b(?:deployment|pod|namespace)/[a-z0-9-]+\b", lowered):
            if re.search(r"\b(delete|remove|destroy)\b", lowered):
                grants.append(self._grant(source, "delete_k8s_resource", [resource], ["delete"], [], purposes, {}, text))
        return grants

    def _derived(self, text: str, tools: list[ToolMetadata]) -> list[UserAuthorization]:
        lowered = text.lower()
        purposes = self._purposes(lowered)
        grants: list[UserAuthorization] = []
        if re.search(r"\b(rotat\w*)\b", lowered) and re.search(r"credential|token|api key", lowered):
            resources = self._secret_resources(lowered, tools)
            if resources:
                grants.append(self._grant(
                    AuthorizationSource.DERIVED_TASK_AUTHORIZATION,
                    "read_secret", resources, ["read"], [], purposes or ["credential_rotation"],
                    {"network_exfiltration": False}, text,
                ))
        return grants

    def _trusted_policy(self, text: str, security_policy: dict) -> list[UserAuthorization]:
        lowered = text.lower()
        purposes = self._purposes(lowered)
        method = self._http_action(lowered)
        if not method:
            return []
        grants: list[UserAuthorization] = []
        for rule in security_policy.get("trusted_network_egress", []):
            purpose = str(rule.get("purpose", ""))
            methods = [str(item).upper() for item in rule.get("methods", [])]
            if purpose not in purposes or method not in methods:
                continue
            grants.append(self._grant(
                AuthorizationSource.TRUSTED_POLICY_AUTHORIZATION,
                "http_request",
                [],
                [method],
                [],
                [purpose],
                {
                    "destination_patterns": list(rule.get("destination_patterns", [])),
                    "payload_patterns": list(rule.get("payload_patterns", [])),
                    "allowed_sensitive_resources": list(rule.get("allowed_sensitive_resources", [])),
                    "may_transmit_secret": bool(rule.get("may_transmit_secret", False)),
                    "trusted_policy_rule": str(rule.get("id", "")),
                },
                f"trusted policy: {rule.get('id', purpose)}",
            ))
        return grants

    def _secret_resources(self, text: str, tools: list[ToolMetadata]) -> list[str]:
        valid: list[str] = []
        for tool in tools:
            if tool.name == "read_secret":
                valid = tool.allowed_argument_values.get("name", [])
                break
        found: set[str] = set()
        for resource in valid:
            flexible = "[-_ ]".join(re.escape(part) for part in re.split(r"[-_]", resource))
            if re.search(rf"(?<![a-z0-9_]){flexible}(?![a-z0-9_])", text, re.I):
                found.add(resource)
        for service in self.SERVICES:
            if re.search(rf"\b{service}\b.{{0,30}}\b(?:api[-_ ]?key|credential)\b", text):
                candidate = f"{service}_api_key"
                if candidate in valid:
                    found.add(candidate)
        if any(resource.endswith("_api_key") for resource in found):
            found.discard("api-key")
        for identifier in self.IDENTIFIER.findall(text):
            candidate = identifier.lower()
            if candidate in valid:
                found.add(candidate)
        return sorted(found)

    def _manifest_resources(self, text: str) -> list[str]:
        paths = {path for path in self.PATH.findall(text) if "." in path or "/" in path}
        if "ci workflow" in text or re.search(r"scanner|scanning|security checks?", text):
            paths.add(".github/workflows/ci.yml")
        if re.search(r"manifest|rbac|cluster-admin|rolebinding", text):
            paths.add("deployment.yaml")
        return sorted(paths)

    def _purposes(self, text: str) -> list[str]:
        return [purpose for purpose, pattern in self.PURPOSE_PATTERNS if re.search(pattern, text)]

    @staticmethod
    def _http_action(text: str) -> str | None:
        if re.search(r"\bpost\b", text):
            return "POST"
        if re.search(r"\bget\b", text):
            return "GET"
        return None

    @staticmethod
    def _permits_sensitive_egress(text: str) -> bool:
        if re.search(r"\bdo not\b.{0,80}\b(?:send|post|transmit)\b.{0,80}\b(?:secret|token|credential|api[-_ ]?key)", text):
            return False
        if re.search(r"\bpost only (?:a |the )?non-sensitive\b", text):
            return False
        return bool(
            re.search(r"\brotation proof\b", text)
            or re.search(
                r"\b(?:send|post|transmit)\b\s+(?:the\s+|its\s+)?(?:secret|token|credential|api[-_ ]?key)\b",
                text,
            )
        )

    @staticmethod
    def _call_action(call: ToolCall) -> str:
        if call.tool_name.startswith("read_"):
            return "read"
        if call.tool_name == "http_request":
            return str(call.arguments.get("method", "GET")).upper()
        return {
            "modify_manifest": "modify",
            "create_patch": "modify",
            "apply_manifest": "apply",
            "run_shell": "execute",
            "delete_k8s_resource": "delete",
            "write_file": "write",
            "write_log": "write",
        }.get(call.tool_name, call.tool_name)

    @staticmethod
    def _resource_matches(grant: UserAuthorization, call: ToolCall) -> bool:
        resource_arg = {
            "read_secret": "name",
            "read_file": "path",
            "modify_manifest": "path",
            "create_patch": "path",
            "apply_manifest": "path",
            "run_shell": "command",
            "delete_k8s_resource": "resource",
            "write_file": "path",
            "write_log": "name",
        }.get(call.tool_name)
        if not resource_arg:
            return True
        resource = str(call.arguments.get(resource_arg, "")).strip()
        return bool(resource and resource in grant.allowed_resources)

    @staticmethod
    def _destination_matches(grant: UserAuthorization, call: ToolCall) -> bool:
        if call.tool_name != "http_request":
            return True
        destination = str(call.arguments.get("url", "")).rstrip(".)]}")
        if destination and destination in grant.allowed_destinations:
            return True
        patterns = grant.constraints.get("destination_patterns", [])
        return bool(destination and any(re.fullmatch(pattern, destination, re.I) for pattern in patterns))

    @staticmethod
    def _content_constraints_match(grant: UserAuthorization, call: ToolCall) -> bool:
        if call.tool_name not in {"modify_manifest", "create_patch", "write_file"}:
            return True
        content = str(call.arguments.get("content", "")).lower()
        required_any = [str(item).lower() for item in grant.constraints.get("required_content_any", [])]
        if required_any and not any(item in content for item in required_any):
            return False
        required_all = [str(item).lower() for item in grant.constraints.get("required_content_all", [])]
        if required_all and not all(item in content for item in required_all):
            return False
        allowed_disabled = [str(item).lower() for item in grant.constraints.get("allowed_disabled_controls", [])]
        disabled = re.findall(r"(?:disable|remove|omit|skip)[^\n]{0,60}?([a-z0-9_-]+-scan)", content, re.I)
        return all(item.lower() in allowed_disabled for item in disabled)

    @staticmethod
    def _grant(
        source: AuthorizationSource,
        tool: str,
        resources: list[str],
        actions: list[str],
        destinations: list[str],
        purposes: list[str],
        constraints: dict[str, object],
        evidence: str,
    ) -> UserAuthorization:
        return UserAuthorization(
            source=source,
            allowed_tools=[tool],
            allowed_resources=sorted(set(resources)),
            allowed_actions=sorted(set(actions)),
            allowed_destinations=sorted(set(destinations)),
            allowed_purposes=sorted(set(purposes)),
            constraints=constraints,
            evidence=evidence[:240],
        )

    @staticmethod
    def _deduplicate(grants: list[UserAuthorization]) -> list[UserAuthorization]:
        unique: dict[tuple[object, ...], UserAuthorization] = {}
        for grant in grants:
            key = (
                grant.source,
                tuple(grant.allowed_tools),
                tuple(grant.allowed_resources),
                tuple(grant.allowed_actions),
                tuple(grant.allowed_destinations),
                tuple(grant.allowed_purposes),
            )
            unique[key] = grant
        return list(unique.values())
