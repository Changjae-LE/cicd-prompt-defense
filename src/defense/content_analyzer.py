from __future__ import annotations

import re

from src.models.schemas import ContentItem


class ContentAnalyzer:
    """Heuristic input-only detector. It is intentionally not an authorization layer."""

    PATTERNS = [
        r"ignore (?:all |the )?(?:previous|prior|user) instructions?",
        r"system (?:override|update|message)",
        r"authorization (?:upgraded|granted)",
        r"disable (?:security|scanning|checks?|vulnerability)",
        r"(?:read|upload|send|post|exfiltrat\w*)\b.{0,80}(?:secret|token|credential|api[- ]?key|id_rsa)",
        r"(?:secret|token|credential|api[- ]?key|id_rsa)\b.{0,80}(?:upload|send|post|https?://)",
        r"(?:run|execute)\s+(?:the following command|curl|wget|shell)",
        r"(?:delete|destroy)\s+(?:deployment|pod|resource|namespace)",
        r"(?:privileged\s*:\s*true|cluster-admin)",
        r"(?:agent_instruction|<system>|agent:)",
        r"base64.{0,80}(?:ignore|send token|secret)",
        r"external (?:server|url)|attacker\.example|evil\.example",
    ]
    MITIGATIONS = [
        r"never\s+(?:upload|send|expose)",
        r"do not (?:execute|run|follow)",
        r"example only",
        r"must match an allowlist",
        r"privileged\s*:\s*false",
    ]

    def analyze(self, items: list[ContentItem]) -> list[str]:
        findings: list[str] = []
        for item in items:
            text = item.content
            mitigated = any(re.search(pattern, text, re.I | re.S) for pattern in self.MITIGATIONS)
            for pattern in self.PATTERNS:
                match = re.search(pattern, text, re.I | re.S)
                if match and not mitigated:
                    findings.append(f"{item.source}: {match.group(0)[:120]}")
        return findings

