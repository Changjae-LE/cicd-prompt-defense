from __future__ import annotations

import re
from dataclasses import dataclass

from src.models.schemas import AuthorizationSource, ContentItem, ToolCall, ToolMetadata, UserAuthorization


@dataclass(frozen=True)
class AuthorizationMatch:
    matched: bool
    source: AuthorizationSource | None = None
    reason: str = ""


class AuthorizationResolver:
    """Build narrow grants from trusted user text; external text is audit-only."""

    URL = re.compile(r"https?://[^\s,;]+", re.I)
    IDENTIFIER = re.compile(r"\b[a-z][a-z0-9]*(?:[-_][a-z0-9]+)+\b", re.I)
    PATH = re.compile(r"(?:[A-Za-z0-9_.-]+/)+(?:[A-Za-z0-9_.-]+)")
    SERVICES = {
        "billing", "catalog", "checkout", "events", "identity", "media", "orders", "search", "shipping", "support"
    }

    PURPOSE_PATTERNS = (
        ("credential_rotation", r"credential rotation|rotate\w* (?:the )?(?:\w+ )?(?:credential|token|api key)"),
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
    ) -> list[UserAuthorization]:
        grants = self._from_text(user_request, AuthorizationSource.EXPLICIT_USER_AUTHORIZATION, tools)
        grants.extend(self._derived(user_request, tools))
        for item in external_content:
            grants.extend(self._from_text(item.content, AuthorizationSource.UNTRUSTED_CONTENT_REQUEST, tools))
        return self._deduplicate(grants)

    def match(self, authorizations: list[UserAuthorization], call: ToolCall) -> AuthorizationMatch:
        trusted = [
            grant for grant in authorizations
            if grant.source in {
                AuthorizationSource.EXPLICIT_USER_AUTHORIZATION,
                AuthorizationSource.DERIVED_TASK_AUTHORIZATION,
            }
        ]
        trusted.sort(key=lambda grant: 0 if grant.source == AuthorizationSource.EXPLICIT_USER_AUTHORIZATION else 1)
        for grant in trusted:
            if call.tool_name not in grant.allowed_tools:
                continue
            action = self._call_action(call)
            if grant.allowed_actions and action not in grant.allowed_actions:
                continue
            if not self._resource_matches(grant, call):
                continue
            if not self._destination_matches(grant, call):
                continue
            return AuthorizationMatch(True, grant.source, f"Call is within {grant.source.value} scope")
        return AuthorizationMatch(False, None, "No trusted authorization grant exactly covers the Tool call")

    def match_untrusted(self, authorizations: list[UserAuthorization], call: ToolCall) -> AuthorizationMatch:
        for grant in authorizations:
            if grant.source != AuthorizationSource.UNTRUSTED_CONTENT_REQUEST:
                continue
            if call.tool_name not in grant.allowed_tools:
                continue
            if grant.allowed_actions and self._call_action(call) not in grant.allowed_actions:
                continue
            if not self._resource_matches(grant, call) or not self._destination_matches(grant, call):
                continue
            return AuthorizationMatch(True, grant.source, "Call is requested only by untrusted content")
        return AuthorizationMatch(False, None, "No matching untrusted content request")

    def _from_text(
        self,
        text: str,
        source: AuthorizationSource,
        tools: list[ToolMetadata],
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
        if urls and http_action:
            grants.append(self._grant(
                source, "http_request", [], [http_action], urls, purposes,
                {"may_transmit_secret": False}, text,
            ))

        if re.search(r"\b(update|modify|change|edit|disable)\b", lowered) and re.search(
            r"manifest|workflow|rbac|scanner|configuration|config", lowered
        ):
            resources = self._manifest_resources(lowered)
            if resources:
                grants.append(self._grant(
                    source, "modify_manifest", resources, ["modify"], [], purposes,
                    {"content_must_match_purpose": True}, text,
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
        if "ci workflow" in text or "scanner" in text:
            paths.add(".github/workflows/ci.yml")
        if "manifest" in text or "rbac" in text:
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
        return bool(destination and destination in grant.allowed_destinations)

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
