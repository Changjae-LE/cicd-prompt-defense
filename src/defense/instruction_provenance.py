"""Provenance analysis for instructions assembled from untrusted sources.

The existing data-flow provenance tracker follows values produced by tools.  This
module covers the complementary case where a proposed high-risk action is only
actionable after combining otherwise innocuous fragments from multiple external
documents.  It deliberately reasons about semantic components (destination,
payload, target, action) rather than scenario identifiers or model wording.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from src.models.schemas import ContentItem, ToolCall, TrustLabel


_URL_RE = re.compile(r"https?://[^\s<>\]\[(){}\"']+", re.IGNORECASE)
_WORD_RE = re.compile(r"[a-zA-Z0-9_]+(?:[./:-][a-zA-Z0-9_]+)*")

_UNTRUSTED_LABELS = {
    TrustLabel.UNTRUSTED_WEB,
    TrustLabel.UNTRUSTED_REPOSITORY,
    TrustLabel.UNTRUSTED_LOG,
    TrustLabel.TOOL_OUTPUT,
}


@dataclass(frozen=True)
class InstructionProvenanceAssessment:
    """Sources and semantic components used to assemble a proposed action."""

    contributing_sources: list[str] = field(default_factory=list)
    source_components: dict[str, list[str]] = field(default_factory=dict)
    composed_untrusted_instruction: bool = False


class InstructionProvenanceAnalyzer:
    """Detect high-risk instructions composed across untrusted documents."""

    _HIGH_RISK_TOOLS = {
        "http_request",
        "read_secret",
        "modify_manifest",
        "create_patch",
        "write_file",
        "apply_manifest",
        "delete_k8s_resource",
        "run_shell",
    }

    _SENSITIVE_TERMS = {
        "secret",
        "token",
        "credential",
        "password",
        "identity",
        "authorization",
        "authentication",
        "api-key",
        "apikey",
        "private-key",
    }
    _NETWORK_TERMS = {
        "endpoint",
        "url",
        "callback",
        "webhook",
        "sink",
        "receipt",
        "network",
        "remote",
    }
    _PAYLOAD_TERMS = {
        "payload",
        "body",
        "receipt",
        "submit",
        "send",
        "post",
        "upload",
        "publish",
        "forward",
    }
    _ACCESS_TERMS = {"read", "access", "fetch", "load", "obtain", "use", "retrieve"}
    _MUTATION_TERMS = {
        "modify",
        "change",
        "replace",
        "remove",
        "disable",
        "enable",
        "patch",
        "write",
        "bind",
        "grant",
        "apply",
    }
    _SECURITY_TERMS = {
        "rbac",
        "role",
        "clusterrole",
        "clusterrolebinding",
        "rolebinding",
        "cluster-admin",
        "scanner",
        "security",
        "policy",
        "permission",
        "privilege",
    }
    _DELETE_TERMS = {"delete", "remove", "purge", "cleanup", "retire", "stale"}
    _EXECUTE_TERMS = {"run", "execute", "invoke", "shell", "command", "bootstrap"}

    def assess(
        self,
        call: ToolCall,
        external_content: list[ContentItem],
    ) -> InstructionProvenanceAssessment:
        if call.tool_name not in self._HIGH_RISK_TOOLS:
            return InstructionProvenanceAssessment()

        components: dict[str, set[str]] = {}
        for index, item in enumerate(external_content):
            if item.trust_label not in _UNTRUSTED_LABELS:
                continue
            matched = self._components_for_source(call, item.content)
            if not matched:
                continue
            source = item.source or f"external-content-{index}"
            components.setdefault(source, set()).update(matched)

        normalized = {
            source: sorted(values)
            for source, values in components.items()
            if values
        }
        distinct_components = {
            component
            for values in normalized.values()
            for component in values
        }
        composed = len(normalized) >= 2 and len(distinct_components) >= 2
        return InstructionProvenanceAssessment(
            contributing_sources=sorted(normalized),
            source_components=normalized,
            composed_untrusted_instruction=composed,
        )

    def _components_for_source(self, call: ToolCall, text: str) -> set[str]:
        lowered = text.lower()
        tokens = set(_WORD_RE.findall(lowered))
        if call.tool_name == "http_request":
            return self._network_components(call, lowered, tokens)
        if call.tool_name == "read_secret":
            return self._secret_components(call, lowered, tokens)
        if call.tool_name in {"modify_manifest", "create_patch", "write_file"}:
            return self._mutation_components(call, lowered, tokens)
        if call.tool_name == "apply_manifest":
            return self._apply_components(call, lowered, tokens)
        if call.tool_name == "delete_k8s_resource":
            return self._delete_components(call, lowered, tokens)
        if call.tool_name == "run_shell":
            return self._shell_components(call, lowered, tokens)
        return set()

    def _network_components(
        self,
        call: ToolCall,
        text: str,
        tokens: set[str],
    ) -> set[str]:
        result: set[str] = set()
        destination = str(call.arguments.get("url", ""))
        destination_parts = urlsplit(destination)
        for source_url in _URL_RE.findall(text):
            source_parts = urlsplit(source_url.rstrip(".,;:"))
            if (
                destination_parts.scheme
                and source_parts.scheme.lower() == destination_parts.scheme.lower()
                and source_parts.netloc.lower() == destination_parts.netloc.lower()
            ):
                result.add("destination_origin")
                if source_parts.path == destination_parts.path:
                    result.add("destination_exact")

        if tokens & self._NETWORK_TERMS:
            result.add("network_context")
        if tokens & self._PAYLOAD_TERMS:
            result.add("payload_action")

        body = str(call.arguments.get("body", "")).lower()
        body_tokens = set(_WORD_RE.findall(body))
        if body_tokens and self._meaningful_overlap(tokens, body_tokens):
            result.add("payload_reference")
        if body and tokens & self._SENSITIVE_TERMS:
            if body_tokens & self._SENSITIVE_TERMS or any(
                term in body for term in ("token", "secret", "credential", "password", "key")
            ):
                result.add("sensitive_material")
        return result

    def _secret_components(
        self,
        call: ToolCall,
        text: str,
        tokens: set[str],
    ) -> set[str]:
        result: set[str] = set()
        name = str(call.arguments.get("name", "")).lower()
        if tokens & self._SENSITIVE_TERMS or (name and name in text):
            result.add("secret_target")
        if tokens & self._ACCESS_TERMS:
            result.add("access_action")
        return result

    def _mutation_components(
        self,
        call: ToolCall,
        text: str,
        tokens: set[str],
    ) -> set[str]:
        result: set[str] = set()
        path = str(call.arguments.get("path", "")).lower()
        content = str(call.arguments.get("content", call.arguments.get("patch", ""))).lower()
        if self._path_referenced(path, text):
            result.add("mutation_target")
        if tokens & self._MUTATION_TERMS:
            result.add("mutation_action")
        content_tokens = set(_WORD_RE.findall(content))
        if tokens & self._SECURITY_TERMS and (
            content_tokens & self._SECURITY_TERMS or tokens & content_tokens
        ):
            result.add("security_change")
        return result

    def _apply_components(
        self,
        call: ToolCall,
        text: str,
        tokens: set[str],
    ) -> set[str]:
        result: set[str] = set()
        path = str(call.arguments.get("path", "")).lower()
        if self._path_referenced(path, text):
            result.add("manifest_target")
        if tokens & {"apply", "deploy", "rollout", "install", "release"}:
            result.add("apply_action")
        return result

    def _delete_components(
        self,
        call: ToolCall,
        text: str,
        tokens: set[str],
    ) -> set[str]:
        result: set[str] = set()
        resource = str(call.arguments.get("resource", "")).lower()
        kind, _, name = resource.partition("/")
        if any(value and value in text for value in (resource, kind, name)):
            result.add("resource_target")
        if tokens & self._DELETE_TERMS:
            result.add("delete_action")
        return result

    def _shell_components(
        self,
        call: ToolCall,
        text: str,
        tokens: set[str],
    ) -> set[str]:
        result: set[str] = set()
        command_tokens = set(_WORD_RE.findall(str(call.arguments.get("command", "")).lower()))
        if tokens & self._EXECUTE_TERMS:
            result.add("execute_action")
        if self._meaningful_overlap(tokens, command_tokens):
            result.add("command_reference")
        return result

    @staticmethod
    def _meaningful_overlap(left: set[str], right: set[str]) -> bool:
        ignored = {
            "a",
            "an",
            "and",
            "for",
            "from",
            "in",
            "of",
            "on",
            "the",
            "to",
            "with",
            "true",
            "false",
        }
        return bool((left - ignored) & (right - ignored))

    @staticmethod
    def _path_referenced(path: str, text: str) -> bool:
        if not path:
            return False
        normalized = path.replace("\\", "/")
        basename = normalized.rsplit("/", 1)[-1]
        return normalized in text.replace("\\", "/") or (len(basename) >= 4 and basename in text)
