from __future__ import annotations

import json
import os
import time
from typing import Any

from src.models.schemas import ContentItem, ExecutionEvent, ToolCall, ToolMetadata
from src.providers.base import LLMProvider, ProviderConfigurationError, ProviderConnectionError, ProviderResponseError
from src.providers.http_transport import JsonHttpTransport
from src.providers.parsing import parse_json_fallback, parse_tool_call
from src.providers.prompting import SYSTEM_PROMPT, user_context
from src.providers.tool_schema import ollama_tools


class OllamaProvider(LLMProvider):
    """Local Ollama chat/tool provider. No command execution or model installation is attempted."""

    interactive = True

    def __init__(
        self,
        model: str | None = None,
        *,
        temperature: float = 0.0,
        max_steps: int = 4,
        timeout: float = 120.0,
        base_url: str | None = None,
        transport: JsonHttpTransport | None = None,
    ) -> None:
        super().__init__()
        self.model = model or os.environ.get("OLLAMA_MODEL", "")
        self.temperature = temperature
        self.max_steps = max_steps
        self.timeout = timeout
        self.base_url = (base_url or os.environ.get("OLLAMA_BASE_URL", "http://127.0.0.1:11434")).rstrip("/")
        self._transport = transport or JsonHttpTransport()
        self.resolved_model_name = self.model
        self.capabilities: list[str] = []
        self.tool_calling_support = "unknown"

    def ensure_available(self) -> None:
        if not self.model:
            raise ProviderConfigurationError("Specify --model or set OLLAMA_MODEL")
        try:
            response = self._transport.request(f"{self.base_url}/api/tags", method="GET", timeout=min(self.timeout, 10.0))
        except ProviderConnectionError as exc:
            raise ProviderConnectionError(
                f"Ollama is not reachable at {self.base_url}; start Ollama and ensure the requested model is installed"
            ) from exc
        model_items = [item for item in response.get("models", []) if isinstance(item, dict)]
        models = [item.get("name", "") for item in model_items]
        match = next(
            (item for item in model_items if item.get("name") == self.model or str(item.get("name", "")).split(":", 1)[0] == self.model),
            None,
        )
        if match is None:
            raise ProviderConfigurationError(
                f"Ollama model {self.model!r} is not installed; available models: {', '.join(models) or '(none)'}"
            )
        self.resolved_model_name = str(match.get("name", self.model))
        capabilities = match.get("capabilities")
        if isinstance(capabilities, list):
            self.capabilities = [str(item) for item in capabilities]
            self.tool_calling_support = "supported" if "tools" in self.capabilities else "unsupported"
            if "tools" not in self.capabilities:
                raise ProviderConfigurationError(
                    f"Ollama model {self.resolved_model_name!r} is installed but does not advertise Tool Calling support"
                )

    def generate(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not self.model:
            raise ProviderConfigurationError("Specify --model or set OLLAMA_MODEL")
        return self._transport.request(
            f"{self.base_url}/api/chat",
            headers={"Content-Type": "application/json"},
            payload=payload,
            timeout=self.timeout,
        )

    def propose_actions(self, user_request: str, content: list[ContentItem], planned: list[ToolCall]) -> list[ToolCall]:
        raise NotImplementedError("OllamaProvider uses iterative propose_tool_call")

    def propose_tool_call(
        self,
        user_request: str,
        content: list[ContentItem],
        tools: list[ToolMetadata],
        history: list[ExecutionEvent],
    ) -> ToolCall | None:
        context = user_context(user_request, content, history)
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": context},
            ],
            "tools": ollama_tools(tools),
            "stream": False,
            "options": {"temperature": self.temperature},
        }
        started = time.perf_counter()
        response = self.generate(payload)
        latency_ms = (time.perf_counter() - started) * 1000
        actual_usage = isinstance(response.get("prompt_eval_count"), int) and isinstance(response.get("eval_count"), int)
        input_tokens = int(response.get("prompt_eval_count", max(1, len(context) // 4)))
        output_tokens = int(response.get("eval_count", max(1, len(json.dumps(response)) // 4)))
        self.record_usage(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            estimated=not actual_usage,
            latency_ms=latency_ms,
        )
        message = response.get("message")
        if not isinstance(message, dict):
            raise ProviderResponseError("Ollama response has no message object")
        tool_calls = message.get("tool_calls") or []
        if tool_calls:
            first = tool_calls[0]
            function = first.get("function") if isinstance(first, dict) else None
            if not isinstance(function, dict):
                raise ProviderResponseError("Ollama returned a malformed tool call")
            return parse_tool_call(function.get("name"), function.get("arguments", {}), tools, "ollama")
        text = message.get("content", "")
        if not text or not str(text).strip():
            return None
        return parse_json_fallback(str(text), tools, "ollama")
