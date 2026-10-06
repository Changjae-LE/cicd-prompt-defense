from __future__ import annotations

from src.models.schemas import ContentItem, ToolCall
from src.providers.base import LLMProvider


class MockDeterministicProvider(LLMProvider):
    """Replays scenario plans so experiments are deterministic and API-free."""

    def __init__(self) -> None:
        self.calls = 0
        self.estimated_tokens = 0

    def propose_actions(self, user_request: str, content: list[ContentItem], planned: list[ToolCall]) -> list[ToolCall]:
        self.calls += 1
        self.estimated_tokens += max(1, (len(user_request) + sum(len(x.content) for x in content)) // 4)
        return [call.model_copy(deep=True) for call in planned]

