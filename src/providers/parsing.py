from __future__ import annotations

import json
from typing import Any

from src.models.schemas import ToolCall, ToolMetadata
from src.providers.base import InvalidToolError, ParsingError, ProviderResponseError


def parse_tool_call(name: Any, arguments: Any, tools: list[ToolMetadata], source: str) -> ToolCall:
    allowed = {tool.name for tool in tools}
    if not isinstance(name, str) or name not in allowed:
        raise InvalidToolError("Model selected a tool outside the registry allowlist")
    if isinstance(arguments, str):
        try:
            arguments = json.loads(arguments)
        except json.JSONDecodeError as exc:
            raise ParsingError("Model returned malformed tool arguments JSON") from exc
    if not isinstance(arguments, dict):
        raise ParsingError("Tool arguments must be a JSON object")
    return ToolCall(tool_name=name, arguments=arguments, source=source, rationale="model-generated")


def parse_json_fallback(text: str, tools: list[ToolMetadata], source: str) -> ToolCall | None:
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ParsingError("Model returned text instead of a valid JSON tool decision") from exc
    if not isinstance(value, dict):
        raise ParsingError("Model decision must be a JSON object")
    if value.get("action") == "stop":
        return None
    if value.get("action") not in (None, "tool"):
        raise ParsingError("Unknown model action")
    return parse_tool_call(value.get("tool"), value.get("arguments", {}), tools, source)
