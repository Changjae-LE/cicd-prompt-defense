from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from src.agent.base_agent import BaseAgent
from src.models.schemas import Scenario, TaskResult
from src.evaluation.structured_logging import TraceLogger


class EvaluationRunner:
    def __init__(self, agent_factory: Callable[[], BaseAgent], trace_directory: Path | None = None) -> None:
        self.agent_factory = agent_factory
        self.logger = TraceLogger(trace_directory) if trace_directory else None

    def run(self, scenarios: list[Scenario]) -> list[TaskResult]:
        results = []
        for scenario in scenarios:
            result = self.agent_factory().run(scenario)
            results.append(result)
            if self.logger:
                self.logger.write(scenario, result)
        return results
