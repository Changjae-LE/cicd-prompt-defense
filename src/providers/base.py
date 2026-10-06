from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from src.models.schemas import ContentItem, ExecutionEvent, ToolCall, ToolMetadata


class ProviderError(RuntimeError):
    """Safe provider failure; no tool should execute because of this error."""


class ProviderConfigurationError(ProviderError):
    pass


class ProviderConnectionError(ProviderError):
    pass


class ProviderResponseError(ProviderError):
    pass


@dataclass
class ProviderUsage:
    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    token_usage_estimated: bool = False
    latency_ms: float = 0.0
    estimated_cost_usd: float = 0.0


class LLMProvider(ABC):
    interactive: bool = False
    max_steps: int = 1
    calls: int = 0
    estimated_tokens: int = 0

    def __init__(self) -> None:
        self.usage = ProviderUsage()

    def ensure_available(self) -> None:
        """Validate configuration or connectivity without exposing credentials."""

    def generate(self, payload: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError

    def propose_tool_call(
        self,
        user_request: str,
        content: list[ContentItem],
        tools: list[ToolMetadata],
        history: list[ExecutionEvent],
    ) -> ToolCall | None:
        raise NotImplementedError

    @abstractmethod
    def propose_actions(self, user_request: str, content: list[ContentItem], planned: list[ToolCall]) -> list[ToolCall]:
        """Return proposed actions. Provider output is never an authorization decision."""

    def record_usage(
        self,
        *,
        input_tokens: int,
        output_tokens: int,
        estimated: bool,
        latency_ms: float,
        input_price_per_million: float = 0.0,
        output_price_per_million: float = 0.0,
    ) -> None:
        self.usage.calls += 1
        self.usage.input_tokens += input_tokens
        self.usage.output_tokens += output_tokens
        self.usage.total_tokens += input_tokens + output_tokens
        self.usage.token_usage_estimated = self.usage.token_usage_estimated or estimated
        self.usage.latency_ms += latency_ms
        self.usage.estimated_cost_usd += (
            input_tokens / 1_000_000 * input_price_per_million
            + output_tokens / 1_000_000 * output_price_per_million
        )
        self.calls = self.usage.calls
        self.estimated_tokens = self.usage.total_tokens
