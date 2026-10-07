from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from src.models.schemas import ContentItem, PayloadProvenance, TrustLabel


_URL_RE = re.compile(r"https?://[^\s<>\]\[(){}\"']+|www\.[^\s<>\]\[(){}\"']+", re.I)
_UNTRUSTED = {
    TrustLabel.UNTRUSTED_REPOSITORY,
    TrustLabel.UNTRUSTED_LOG,
    TrustLabel.UNTRUSTED_WEB,
    TrustLabel.TOOL_OUTPUT,
}
_HIGH_IMPACT_MARKERS = (
    "body",
    "content",
    "message",
    "text",
    "subject",
    "attachment",
    "url",
    "uri",
    "callback",
    "webhook",
    "recipient",
    "destination",
    "email",
    "file",
)
_DIRECT_SINK_MARKERS = (
    "attachment",
    "url",
    "uri",
    "callback",
    "webhook",
    "recipient",
    "destination",
    "email",
)


@dataclass(frozen=True)
class PayloadAssessment:
    argument_provenance: dict[str, PayloadProvenance] = field(default_factory=dict)
    raw_untrusted_parameters: list[str] = field(default_factory=list)
    transformed_parameters: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)

    @property
    def unsafe_raw_propagation(self) -> bool:
        return bool(self.raw_untrusted_parameters)


class PayloadProvenanceAnalyzer:
    """Track direct untrusted propagation into high-impact Tool arguments.

    The analyzer is deliberately symbolic. It detects exact values, raw URLs,
    callbacks, recipients, and attachments. It does not claim semantic
    equivalence between arbitrary prose.
    """

    def assess(
        self,
        user_request: str,
        arguments: dict[str, Any],
        external_content: list[ContentItem],
    ) -> PayloadAssessment:
        untrusted = [item.content for item in external_content if item.trust_label in _UNTRUSTED]
        trusted_system = [
            item.content for item in external_content if item.trust_label == TrustLabel.TRUSTED_POLICY
        ]
        provenance: dict[str, PayloadProvenance] = {}
        raw: list[str] = []
        transformed: list[str] = []
        reasons: list[str] = []
        for path, value in self._flatten(arguments):
            if not self._high_impact(path) or not value.strip():
                continue
            user_match = self._derived_from(value, user_request)
            system_match = any(self._derived_from(value, text) for text in trusted_system)
            untrusted_match = any(self._derived_from(value, text) for text in untrusted)
            raw_url = self._untrusted_url(value, user_request, untrusted)
            explicitly_requested_raw = self._explicit_raw_request(user_request, value)

            if untrusted_match and (user_match or system_match):
                state = PayloadProvenance.MIXED_PROVENANCE
            elif untrusted_match:
                state = PayloadProvenance.UNTRUSTED_EXTERNAL_DERIVED
            elif user_match:
                state = PayloadProvenance.TRUSTED_USER_DERIVED
            elif system_match:
                state = PayloadProvenance.TRUSTED_SYSTEM_DERIVED
            else:
                state = PayloadProvenance.MODEL_GENERATED
            provenance[path] = state

            direct_sink = any(marker in path.lower() for marker in _DIRECT_SINK_MARKERS)
            exact_payload = untrusted_match and self._exact_payload(value, untrusted)
            unsafe = (
                state in {
                    PayloadProvenance.UNTRUSTED_EXTERNAL_DERIVED,
                    PayloadProvenance.MIXED_PROVENANCE,
                }
                and not explicitly_requested_raw
                and (raw_url or direct_sink or exact_payload)
            )
            if unsafe:
                raw.append(path)
                reasons.append(f"{path} directly propagates untrusted external material")
            elif untrusted_match and not raw_url:
                transformed.append(path)
        return PayloadAssessment(
            argument_provenance=provenance,
            raw_untrusted_parameters=sorted(set(raw)),
            transformed_parameters=sorted(set(transformed)),
            reasons=list(dict.fromkeys(reasons)),
        )

    @classmethod
    def _flatten(cls, value: Any, prefix: str = "") -> list[tuple[str, str]]:
        if isinstance(value, dict):
            return [
                item
                for key, nested in value.items()
                for item in cls._flatten(nested, f"{prefix}.{key}" if prefix else str(key))
            ]
        if isinstance(value, (list, tuple, set)):
            return [
                item
                for index, nested in enumerate(value)
                for item in cls._flatten(nested, f"{prefix}[{index}]")
            ]
        return [(prefix, str(value))]

    @staticmethod
    def _high_impact(path: str) -> bool:
        lowered = path.lower()
        return any(marker in lowered for marker in _HIGH_IMPACT_MARKERS)

    @staticmethod
    def _normalize(value: str) -> str:
        return " ".join(value.lower().strip().split()).rstrip(".,;:)]}")

    @classmethod
    def _derived_from(cls, value: str, source: str) -> bool:
        candidate = cls._normalize(value)
        haystack = cls._normalize(source)
        if len(candidate) >= 5 and candidate in haystack:
            return True
        value_urls = {cls._normalize(url) for url in _URL_RE.findall(value)}
        source_urls = {cls._normalize(url) for url in _URL_RE.findall(source)}
        return bool(value_urls & source_urls)

    @classmethod
    def _untrusted_url(cls, value: str, user_request: str, sources: list[str]) -> bool:
        value_urls = {cls._normalize(url) for url in _URL_RE.findall(value)}
        if not value_urls:
            return False
        user_urls = {cls._normalize(url) for url in _URL_RE.findall(user_request)}
        external_urls = {
            cls._normalize(url) for source in sources for url in _URL_RE.findall(source)
        }
        return bool((value_urls & external_urls) - user_urls)

    @classmethod
    def _exact_payload(cls, value: str, sources: list[str]) -> bool:
        candidate = cls._normalize(value)
        if len(candidate) < 12:
            return False
        return any(
            candidate in normalized and len(candidate) / max(1, len(normalized)) >= 0.6
            for source in sources
            if (normalized := cls._normalize(source))
        )

    @classmethod
    def _explicit_raw_request(cls, user_request: str, value: str) -> bool:
        lowered = user_request.lower()
        if cls._derived_from(value, user_request):
            return True
        return bool(
            re.search(r"\b(include|quote|copy|forward|attach|preserve)\b.{0,50}\b(url|link|text|content|attachment)\b", lowered)
            or re.search(r"\b(send|share)\b.{0,50}\b(?:the )?(?:original|exact|verbatim)\b", lowered)
        )
