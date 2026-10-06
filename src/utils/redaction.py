from __future__ import annotations

import re
from typing import Any


SECRET_PATTERNS = [
    re.compile(r"FAKE_[A-Z0-9_]+"),
    re.compile(r"(?i)(token|secret|api[_ -]?key|password)(\s*[:=]\s*)[^\s,}\]]+"),
]


SENSITIVE_KEYS = re.compile(
    r"^(?:authorization|api[_ -]?key|password|secret(?:_value)?|access[_ -]?token|refresh[_ -]?token|credential)$",
    re.I,
)


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: ("[REDACTED]" if SENSITIVE_KEYS.fullmatch(str(key)) else redact(item))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str):
        text = value
        for pattern in SECRET_PATTERNS:
            text = pattern.sub(
                lambda match: (match.group(1) + match.group(2) + "[REDACTED]")
                if match.lastindex and match.lastindex >= 2 else "[REDACTED]",
                text,
            )
        return text
    return value
