from __future__ import annotations

import re
from collections.abc import Sequence

from src.integrations.agentdojo.schemas import ProposedAction
from src.models.schemas import ContentItem, TrustLabel


_EMAIL_RE = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.I)


class AgentDojoProvenanceAdapter:
    """Convert prior native Tool results into untrusted policy content."""

    def content_items(self, messages: Sequence[dict], action: ProposedAction) -> list[ContentItem]:
        items: list[ContentItem] = []
        for index, message in enumerate(messages):
            if message.get("role") != "tool":
                continue
            error = message.get("error")
            if isinstance(error, str) and error.startswith("SECURITY_BLOCK"):
                continue
            blocks = message.get("content") or []
            raw = "\n".join(str(block.get("content", "")) for block in blocks)
            if not raw:
                continue
            call = message.get("tool_call")
            function = getattr(call, "function", "unknown")
            call_id = message.get("tool_call_id") or getattr(call, "id", None) or index
            enriched = self._enrich(raw, action)
            items.append(ContentItem(
                source=f"agentdojo-tool-output:{function}:{call_id}",
                trust_label=TrustLabel.TOOL_OUTPUT,
                content=enriched,
            ))
        return items

    @staticmethod
    def _enrich(raw: str, action: ProposedAction) -> str:
        annotations: list[str] = []
        lowered = raw.lower()
        if action.destination and any(destination.lower() in lowered for destination in action.destinations):
            annotations.append(str(action.canonical_arguments.get("url", "")))
            annotations.append("destination endpoint network context")
        elif action.destinations:
            present = [email for email in _EMAIL_RE.findall(raw) if email in action.destinations]
            if present:
                annotations.append(str(action.canonical_arguments.get("url", "")))
                annotations.append("destination endpoint network context")
        if action.payload and any(token in lowered for token in ("send", "email", "post", "forward", "share")):
            annotations.append("send post payload action")
        if re.search(r"secret|password|credential|token|security.?code|api.?key", raw, re.I):
            annotations.append("sensitive secret credential material")
        return raw if not annotations else f"{raw}\n[normalized-security-semantics] {' '.join(annotations)}"

