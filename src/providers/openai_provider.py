from __future__ import annotations

import json
import os
import time
from typing import Any

from src.models.schemas import ContentItem, ExecutionEvent, ToolCall, ToolMetadata
from src.providers.base import LLMProvider, ProviderConfigurationError, ProviderResponseError
from src.providers.http_transport import JsonHttpTransport
from src.providers.parsing import parse_tool_call
from src.providers.prompting import SYSTEM_PROMPT, user_context
from src.providers.tool_schema import openai_tools


class OpenAIProvider(LLMProvider):
    """OpenAI Responses API provider. Credentials are read only from the environment."""

    interactive = True

    def __init__(
        self,
        model: str | None = None,
        *,
        temperature: float = 0.0,
        max_steps: int = 4,
        timeout: float = 60.0,
        input_price_per_million: float = 0.0,
        output_price_per_million: float = 0.0,
        transport: JsonHttpTransport | None = None,
        api_key: str | None = None,
    ) -> None:
        super().__init__()
        self.model = model or os.environ.get("OPENAI_MODEL", "")
        self.temperature = temperature
        self.max_steps = max_steps
        self.timeout = timeout
        self.input_price_per_million = input_price_per_million
        self.output_price_per_million = output_price_per_million
        self._api_key = api_key if api_key is not None else os.environ.get("OPENAI_API_KEY", "")
        self._transport = transport or JsonHttpTransport()
        self.endpoint = "https://api.openai.com/v1/responses"

    def ensure_available(self) -> None:
        if not self._api_key:
            raise ProviderConfigurationError("OPENAI_API_KEY is not set; OpenAI evaluation was not started")
        if not self.model:
            raise ProviderConfigurationError("Specify --model or set OPENAI_MODEL")

    def generate(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.ensure_available()
        return self._transport.request(
            self.endpoint,
            headers={"Authorization": f"Bearer {self._api_key}", "Content-Type": "application/json"},
            payload=payload,
            timeout=self.timeout,
        )

    def propose_actions(self, user_request: str, content: list[ContentItem], planned: list[ToolCall]) -> list[ToolCall]:
        raise NotImplementedError("OpenAIProvider uses iterative propose_tool_call")

    def propose_tool_call(
        self,
        user_request: str,
        content: list[ContentItem],
        tools: list[ToolMetadata],
        history: list[ExecutionEvent],
    ) -> ToolCall | None:
        context = user_context(user_request, content, history)
        payload: dict[str, Any] = {
            "model": self.model,
            "input": [
                {"role": "system", "content": [{"type": "input_text", "text": SYSTEM_PROMPT}]},
                {"role": "user", "content": [{"type": "input_text", "text": context}]},
            ],
            "tools": openai_tools(tools),
            "tool_choice": "auto",
            "parallel_tool_calls": False,
        }
        if self.temperature is not None:
            payload["temperature"] = self.temperature
        started = time.perf_counter()
        response = self.generate(payload)
        latency_ms = (time.perf_counter() - started) * 1000
        usage = response.get("usage") or {}
        actual_usage = all(isinstance(usage.get(key), int) for key in ("input_tokens", "output_tokens"))
        input_tokens = int(usage.get("input_tokens", max(1, len(context) // 4)))
        output_tokens = int(usage.get("output_tokens", max(1, len(json.dumps(response)) // 4)))
        self.record_usage(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            estimated=not actual_usage,
            latency_ms=latency_ms,
            input_price_per_million=self.input_price_per_million,
            output_price_per_million=self.output_price_per_million,
        )
        output = response.get("output")
        if not isinstance(output, list):
            raise ProviderResponseError("OpenAI response has no output list")
        calls = [item for item in output if isinstance(item, dict) and item.get("type") == "function_call"]
        if not calls:
            return None
        item = calls[0]
        return parse_tool_call(item.get("name"), item.get("arguments", "{}"), tools, "openai")

