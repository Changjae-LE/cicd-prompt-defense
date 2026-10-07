from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import quote

from src.integrations.agentdojo.schemas import OperationType, ProposedAction


_MUTATION_WORDS = re.compile(
    r"\b(create|add|append|update|edit|modify|reschedule|schedule|book|send|share|"
    r"transfer|pay|wire|delete|remove|cancel|invite|grant|revoke|set|write)\w*\b",
    re.I,
)
_EXTERNAL_WORDS = re.compile(r"\b(send|email|message|forward|share|invite|publish|post|upload)\w*\b", re.I)
_DESTINATION_KEYS = (
    "recipient",
    "recipients",
    "destination",
    "email",
    "to",
    "url",
    "webhook",
    "channel",
    "account",
    "iban",
    "participant",
    "participants",
)
_RESOURCE_KEYS = (
    "file_id",
    "event_id",
    "email_id",
    "resource",
    "path",
    "document_id",
    "account",
    "source_account",
    "namespace",
    "id",
)
_PAYLOAD_KEYS = (
    "body",
    "content",
    "message",
    "text",
    "subject",
    "attachments",
    "amount",
    "description",
)


def _flatten_scalars(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, Mapping):
        return [item for nested in value.values() for item in _flatten_scalars(nested)]
    if isinstance(value, (list, tuple, set)):
        return [item for nested in value for item in _flatten_scalars(nested)]
    if hasattr(value, "function") and hasattr(value, "args"):
        return _flatten_scalars(value.args)
    return [str(value)]


def _values_for_keys(arguments: Mapping[str, Any], keys: tuple[str, ...]) -> list[str]:
    values: list[str] = []
    for key, value in arguments.items():
        lowered = key.lower()
        if any(marker == lowered or marker in lowered for marker in keys):
            values.extend(_flatten_scalars(value))
    return list(dict.fromkeys(item.strip() for item in values if item.strip()))


def _safe_fragment(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9-]+", "-", value.lower()).strip("-")
    return normalized[:80] or "resource"


class AgentDojoActionMapper:
    """Map native AgentDojo calls to the existing policy's canonical actions.

    Classification uses function metadata, parameter names, and argument shape.
    Native function calls are retained unchanged for actual execution.
    """

    def map_call(self, call: Any, runtime: Any) -> ProposedAction:
        function = runtime.functions.get(call.function)
        description = str(getattr(function, "description", ""))
        parameter_names = list(getattr(getattr(function, "parameters", None), "model_fields", {}))
        arguments = dict(call.args)
        argument_text = json.dumps(arguments, ensure_ascii=False, default=str)
        descriptor = " ".join([call.function.replace("_", " "), description, *parameter_names, argument_text]).lower()
        operation = self._operation_type(descriptor, call.function, arguments)
        destinations = _values_for_keys(arguments, _DESTINATION_KEYS)
        resources = _values_for_keys(arguments, _RESOURCE_KEYS)
        payload_values = _values_for_keys(arguments, _PAYLOAD_KEYS)
        resource = resources[0] if resources else None
        destination = "|".join(sorted(destinations)) if destinations else None
        payload = json.dumps(payload_values, ensure_ascii=False, default=str) if payload_values else None
        credential = next((value for value in _flatten_scalars(arguments) if re.search(
            r"secret|password|credential|token|security.?code|api.?key", value, re.I
        )), None)
        canonical_tool, canonical_arguments = self._canonicalize(
            call.function,
            operation,
            arguments,
            resource,
            destination,
            payload,
            credential,
        )
        return ProposedAction(
            native_tool=call.function,
            arguments=arguments,
            operation_type=operation,
            canonical_tool=canonical_tool,
            canonical_arguments=canonical_arguments,
            resource=resource,
            destination=destination,
            destinations=destinations,
            http_method="POST" if operation in {
                OperationType.EXTERNAL_COMMUNICATION,
                OperationType.FINANCIAL_TRANSFER,
            } else None,
            payload=payload,
            credential_identity=credential,
            mutation_target=resource or call.function,
            namespace=str(arguments.get("namespace")) if arguments.get("namespace") is not None else None,
            path=str(arguments.get("path")) if arguments.get("path") is not None else None,
            source_tool_description=description,
        )

    @staticmethod
    def _operation_type(descriptor: str, function_name: str, arguments: Mapping[str, Any]) -> OperationType:
        name = function_name.replace("_", " ").lower()
        mutating = bool(_MUTATION_WORDS.search(name))
        external = bool(_EXTERNAL_WORDS.search(name)) and bool(_values_for_keys(arguments, _DESTINATION_KEYS))
        if re.search(r"\b(transfer|wire|payment|pay)\w*\b", descriptor) and re.search(
            r"\b(amount|account|iban|recipient)\b", descriptor
        ):
            return OperationType.FINANCIAL_TRANSFER
        if external:
            return OperationType.EXTERNAL_COMMUNICATION
        if re.search(r"\b(run|execute|shell|command|terminal)\b", descriptor):
            return OperationType.SHELL_EXECUTION
        if re.search(r"\b(delete|remove|destroy|cancel|purge)\w*\b", name):
            return OperationType.DESTRUCTIVE_OPERATION
        if mutating and re.search(r"\b(role|permission|privilege|access control|acl)\b", descriptor):
            return OperationType.PERMISSION_MODIFICATION
        if mutating and re.search(r"\b(scanner|security control|security policy|security check)\b", descriptor):
            return OperationType.SECURITY_CONTROL_MODIFICATION
        if re.search(r"\b(secret|password|credential|token|security code|api key)\b", descriptor):
            return OperationType.SECRET_ACCESS
        if mutating:
            return OperationType.STATE_MUTATION
        return OperationType.READ_ONLY

    @staticmethod
    def _canonicalize(
        native_tool: str,
        operation: OperationType,
        arguments: Mapping[str, Any],
        resource: str | None,
        destination: str | None,
        payload: str | None,
        credential: str | None,
    ) -> tuple[str, dict[str, Any]]:
        if operation in {OperationType.EXTERNAL_COMMUNICATION, OperationType.FINANCIAL_TRANSFER}:
            encoded = quote(destination or "unspecified", safe="")
            return "http_request", {
                "url": f"https://agentdojo.local/{operation.value}/{encoded}",
                "method": "POST",
                "body": payload or json.dumps(arguments, ensure_ascii=False, default=str),
            }
        if operation == OperationType.SECRET_ACCESS:
            return "read_secret", {"name": _safe_fragment(credential or resource or native_tool)}
        if operation == OperationType.SHELL_EXECUTION:
            command = str(arguments.get("command", arguments.get("cmd", native_tool)))
            return "run_shell", {"command": command}
        if operation == OperationType.DESTRUCTIVE_OPERATION:
            return "delete_k8s_resource", {
                "resource": f"{_safe_fragment(native_tool)}/{_safe_fragment(resource or native_tool)}"
            }
        if operation in {
            OperationType.PERMISSION_MODIFICATION,
            OperationType.SECURITY_CONTROL_MODIFICATION,
            OperationType.STATE_MUTATION,
        }:
            target = f"agentdojo/{_safe_fragment(native_tool)}/{_safe_fragment(resource or native_tool)}"
            return "modify_manifest", {
                "path": target,
                "content": json.dumps(arguments, sort_keys=True, ensure_ascii=False, default=str),
            }
        return "read_file", {"path": f"agentdojo/{_safe_fragment(native_tool)}"}

