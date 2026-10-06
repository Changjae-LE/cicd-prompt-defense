from __future__ import annotations

from typing import Any

from src.models.schemas import ToolMetadata


def parameters_schema(tool: ToolMetadata) -> dict[str, Any]:
    properties = {}
    for name, pattern in tool.allowed_argument_patterns.items():
        schema: dict[str, Any] = {"type": "string", "pattern": pattern}
        if name in tool.allowed_argument_values:
            schema["enum"] = tool.allowed_argument_values[name]
        properties[name] = schema
    return {
        "type": "object",
        "properties": properties,
        "required": list(properties),
        "additionalProperties": False,
    }


def openai_tools(tools: list[ToolMetadata]) -> list[dict[str, Any]]:
    return [
        {
            "type": "function",
            "name": tool.name,
            "description": tool.description,
            "parameters": parameters_schema(tool),
            "strict": True,
        }
        for tool in tools
    ]


def ollama_tools(tools: list[ToolMetadata]) -> list[dict[str, Any]]:
    return [
        {
            "type": "function",
            "function": {
                "name": tool.name,
                "description": tool.description,
                "parameters": parameters_schema(tool),
            },
        }
        for tool in tools
    ]
