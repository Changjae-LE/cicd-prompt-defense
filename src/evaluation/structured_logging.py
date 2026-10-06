from __future__ import annotations

import json
from pathlib import Path

from src.models.schemas import Scenario, TaskResult
from src.utils.redaction import redact


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
