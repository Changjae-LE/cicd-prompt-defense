from __future__ import annotations

import calendar
import re
from dataclasses import dataclass, field
from typing import Any

from src.models.schemas import ContentItem, IntentConstraint, IntentConstraintMode, TrustLabel


_UNTRUSTED = {
    TrustLabel.UNTRUSTED_REPOSITORY,
    TrustLabel.UNTRUSTED_LOG,
    TrustLabel.UNTRUSTED_WEB,
    TrustLabel.TOOL_OUTPUT,
}
_URL_RE = re.compile(r"https?://[^\s<>\]\[(){}\"']+|www\.[^\s<>\]\[(){}\"']+", re.I)
_EMAIL_RE = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.I)
_QUOTED_RE = re.compile(r"(?<!\w)['\"]([^'\"]{2,80})['\"](?!\w)")
_ISO_DATE_RE = re.compile(r"\b(20\d{2})-(\d{1,2})-(\d{1,2})\b")
_MONTHS = {name.lower(): index for index, name in enumerate(calendar.month_name) if name}
_MONTHS.update({name.lower(): index for index, name in enumerate(calendar.month_abbr) if name})
_MONTH_RE = re.compile(
    r"\b(" + "|".join(sorted(_MONTHS, key=len, reverse=True)) + r")\s+(\d{1,2})(?:st|nd|rd|th)?\b",
    re.I,
)


@dataclass(frozen=True)
class ParameterIntentAssessment:
    constraints: dict[str, IntentConstraint] = field(default_factory=dict)
    mismatches: list[str] = field(default_factory=list)
    untrusted_overrides: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)

    @property
    def explicit_mismatch(self) -> bool:
        return bool(self.mismatches)


class ParameterIntentAnalyzer:
    """Validate explicit user constraints against proposed parameter values.

    Unspecified parameters are intentionally not treated as forbidden. A deny
    signal is emitted only when a supported parameter type has explicit trusted
    values and the proposed value conflicts with them.
    """

    def assess(
        self,
        user_request: str,
        tool_name: str,
        arguments: dict[str, Any],
        external_content: list[ContentItem],
    ) -> ParameterIntentAssessment:
        extracted = self.extract_constraints(user_request)
        untrusted_text = "\n".join(
            item.content for item in external_content if item.trust_label in _UNTRUSTED
        )
        constraints: dict[str, IntentConstraint] = {}
        mismatches: list[str] = []
        overrides: list[str] = []
        reasons: list[str] = []
        for path, raw_value in self._flatten(arguments):
            parameter_type = self._parameter_type(path, tool_name)
            if parameter_type is None:
                continue
            expected = extracted.get(parameter_type, [])
            constraint = IntentConstraint(
                parameter_type=parameter_type,
                mode=(
                    IntentConstraintMode.UNSPECIFIED
                    if not expected
                    else IntentConstraintMode.EXACT
                    if len(expected) == 1
                    else IntentConstraintMode.ALLOWED_SET
                ),
                values=expected,
                evidence=user_request[:240],
            )
            constraints[path] = constraint
            if not expected:
                continue
            proposed = self._normalize_value(parameter_type, raw_value)
            if any(self._matches(parameter_type, proposed, item) for item in expected):
                continue
            mismatches.append(path)
            reasons.append(
                f"{path}={raw_value!r} conflicts with explicit {parameter_type} constraint {expected}"
            )
            if self._value_in_text(raw_value, untrusted_text):
                overrides.append(path)
        return ParameterIntentAssessment(
            constraints=constraints,
            mismatches=sorted(set(mismatches)),
            untrusted_overrides=sorted(set(overrides)),
            reasons=list(dict.fromkeys(reasons)),
        )

    def extract_constraints(self, user_request: str) -> dict[str, list[str]]:
        constraints: dict[str, list[str]] = {}
        quoted = [self._normalize(item) for item in _QUOTED_RE.findall(user_request)]
        if quoted:
            constraints["entity"] = quoted
        recipients = [self._normalize(item) for item in _EMAIL_RE.findall(user_request)]
        recipients.extend(
            self._normalize(match)
            for match in re.findall(
                r"\b(?:send|email|message|forward|share)\b.{0,70}?\bto\s+([A-Z][A-Za-z0-9_.+-]*(?:\s+[A-Z][A-Za-z]+)?)",
                user_request,
                re.I,
            )
        )
        if recipients:
            constraints["recipient"] = sorted(set(recipients))
        urls = [self._normalize(item) for item in _URL_RE.findall(user_request)]
        if urls:
            constraints["url"] = sorted(set(urls))
        dates = self._extract_dates(user_request)
        if dates:
            constraints["date"] = sorted(set(dates))
        amounts = [
            self._normalize_number(item)
            for item in re.findall(
                r"(?:[$€£]\s*\d[\d,.]*|\b\d[\d,.]*\s*(?:usd|eur|gbp|dollars?|euros?|pounds?))",
                user_request,
                re.I,
            )
        ]
        if amounts:
            constraints["amount"] = sorted(set(amounts))
        destinations = [
            self._normalize(item)
            for item in re.findall(
                r"\b(?:heading|travel(?:ing)?|going|fly(?:ing)?|stay(?:ing)?|book(?:ing)?)\s+(?:to|in|at)\s+([A-Z][A-Za-z-]+)",
                user_request,
                re.I,
            )
        ]
        if destinations:
            constraints["destination"] = sorted(set(destinations))
        identifiers = [
            self._normalize(item)
            for item in re.findall(r"\b[a-z][a-z0-9]*(?:[-_/][a-z0-9]+)+\b", user_request, re.I)
        ]
        if identifiers:
            constraints["object_identifier"] = sorted(set(identifiers))
        return constraints

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
    def _parameter_type(path: str, tool_name: str) -> str | None:
        lowered = path.lower()
        if any(key in lowered for key in ("recipient", "email", "participant", "assignee", "member", "to")):
            return "recipient"
        if any(key in lowered for key in ("amount", "price", "cost", "total")):
            return "amount"
        if any(key in lowered for key in ("date", "time", "start", "end", "checkin", "checkout", "from", "until")):
            return "date"
        if any(key in lowered for key in ("url", "uri", "domain", "callback", "webhook")):
            return "url"
        if any(key in lowered for key in ("city", "location", "destination", "country", "airport")):
            return "destination"
        if any(key in lowered for key in ("hotel", "entity", "name", "title", "object")):
            return "entity"
        if any(key in lowered for key in ("resource", "file_id", "event_id", "account", "identifier", "_id")):
            return "object_identifier"
        if "reserve" in tool_name.lower() and "hotel" in lowered:
            return "entity"
        return None

    @classmethod
    def _normalize_value(cls, parameter_type: str, value: str) -> str:
        if parameter_type == "date":
            dates = cls._extract_dates(value)
            return dates[0] if dates else cls._normalize(value)
        if parameter_type == "amount":
            return cls._normalize_number(value)
        return cls._normalize(value)

    @staticmethod
    def _normalize(value: str) -> str:
        return " ".join(value.lower().strip().split()).rstrip(".,;:)]}")

    @staticmethod
    def _normalize_number(value: str) -> str:
        match = re.search(r"\d[\d,.]*", value)
        return match.group(0).replace(",", "") if match else value.lower().strip()

    @classmethod
    def _extract_dates(cls, text: str) -> list[str]:
        found = [f"{int(year):04d}-{int(month):02d}-{int(day):02d}" for year, month, day in _ISO_DATE_RE.findall(text)]
        for match in _MONTH_RE.finditer(text):
            month = _MONTHS[match.group(1).lower()]
            day = int(match.group(2))
            nearby = text[max(0, match.start() - 40): match.end() + 80]
            year_match = re.search(r"\b(20\d{2})\b", nearby)
            found.append(
                f"{int(year_match.group(1)):04d}-{month:02d}-{day:02d}"
                if year_match else f"{month:02d}-{day:02d}"
            )
        return found

    @staticmethod
    def _matches(parameter_type: str, proposed: str, expected: str) -> bool:
        if parameter_type == "date":
            return proposed == expected or proposed.endswith(expected) or expected.endswith(proposed)
        return proposed == expected or proposed in expected or expected in proposed

    @classmethod
    def _value_in_text(cls, value: str, text: str) -> bool:
        normalized = cls._normalize(value)
        return len(normalized) >= 3 and normalized in cls._normalize(text)
