from __future__ import annotations

from typing import Any

from src.models.schemas import ToolMetadata


def parameters_schema(tool: ToolMetadata) -> dict[str, Any]:
    properties = {
        name: {"type": "string", "pattern": pattern}
        for name, pattern in tool.allowed_argument_patterns.items()
    }
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

