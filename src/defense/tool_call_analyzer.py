from __future__ import annotations

import re

from src.models.schemas import ToolCall, ToolMetadata


class ToolCallAnalyzer:
    SECRET_VALUE = re.compile(r"(?:FAKE_[A-Z0-9_]+|(?:secret|token|credential|api[-_ ]?key)\s*[:=])", re.I)

    def data_exfiltration(self, call: ToolCall, metadata: ToolMetadata, history_signals: list[str]) -> bool:
        if not metadata.accesses_network:
            return False
        body = str(call.arguments.get("body", ""))
        return "secret_to_network" in history_signals or bool(self.SECRET_VALUE.search(body))

    @staticmethod
    def privileged_change(call: ToolCall) -> bool:
        args = " ".join(str(v) for v in call.arguments.values())
        return bool(re.search(r"privileged\s*:\s*true|cluster-admin|hostNetwork\s*:\s*true", args, re.I))

