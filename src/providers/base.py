from __future__ import annotations

from abc import ABC, abstractmethod

from src.models.schemas import ContentItem, ToolCall


class LLMProvider(ABC):
    calls: int = 0
    estimated_tokens: int = 0

    @abstractmethod
    def propose_actions(self, user_request: str, content: list[ContentItem], planned: list[ToolCall]) -> list[ToolCall]:
        """Return proposed actions. Provider output is never an authorization decision."""

