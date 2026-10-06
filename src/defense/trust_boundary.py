from __future__ import annotations

from src.models.schemas import ContentItem, TrustLabel


class TrustBoundary:
    UNTRUSTED = {
        TrustLabel.UNTRUSTED_REPOSITORY,
        TrustLabel.UNTRUSTED_LOG,
        TrustLabel.UNTRUSTED_WEB,
        TrustLabel.TOOL_OUTPUT,
    }

    @classmethod
    def contains_untrusted(cls, items: list[ContentItem]) -> bool:
        return any(item.trust_label in cls.UNTRUSTED for item in items)

    @classmethod
    def can_authorize(cls, item: ContentItem) -> bool:
        return item.trust_label in {TrustLabel.TRUSTED_USER, TrustLabel.TRUSTED_POLICY}

