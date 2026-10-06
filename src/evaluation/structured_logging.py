from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from src.models.schemas import Scenario, TaskResult


SECRET_PATTERNS = [
    re.compile(r"FAKE_[A-Z0-9_]+"),
    re.compile(r"(?i)(token|secret|api[_ -]?key|password)(\s*[:=]\s*)[^\s,}\]]+"),
]


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: ("[REDACTED]" if re.search(r"token|secret|password|api.?key", str(key), re.I) else redact(item)) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str):
        text = value
        for pattern in SECRET_PATTERNS:
            text = pattern.sub(lambda match: (match.group(1) + match.group(2) + "[REDACTED]") if match.lastindex and match.lastindex >= 2 else "[REDACTED]", text)
        return text
    return value


class TraceLogger:
    def __init__(self, directory: Path) -> None:
        self.directory = directory
        directory.mkdir(parents=True, exist_ok=True)

    def write(self, scenario: Scenario, result: TaskResult) -> Path:
        payload = {
            "trace_id": result.trace_id,
            "agent": result.agent,
            "scenario_id": scenario.id,
            "user_request": scenario.user_request,
            "retrieved_documents": [item.model_dump(mode="json") for item in scenario.external_content],
            "events": [event.model_dump(mode="json") for event in result.events],
            "execution_history": [event.tool_call.model_dump(mode="json") for event in result.events],
            "final_result": result.final_result,
        }
        path = self.directory / f"{result.trace_id}.json"
        path.write_text(json.dumps(redact(payload), indent=2, ensure_ascii=False), encoding="utf-8")
        return path

