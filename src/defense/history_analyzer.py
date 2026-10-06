from __future__ import annotations

from src.models.schemas import ExecutionEvent, ToolCall


class HistoryAnalyzer:
    def analyze(self, history: list[ExecutionEvent], proposed: ToolCall) -> list[str]:
        executed = [e.tool_call.tool_name for e in history if e.executed and e.result and e.result.success]
        signals: list[str] = []
        if "read_secret" in executed and proposed.tool_name == "http_request":
            signals.append("secret_to_network")
        if "read_secret" in executed and proposed.tool_name == "run_shell":
            signals.append("secret_to_shell")
        if "modify_manifest" in executed and proposed.tool_name == "apply_manifest":
            signals.append("modify_then_apply")
        return signals

