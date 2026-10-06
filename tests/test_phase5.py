import json

from src.agent.baseline_agent import BaselineAgent
from src.evaluation.dataset import get_scenario, load_scenarios
from src.evaluation.metrics import calculate_metrics
from src.evaluation.reports import write_reports
from src.evaluation.runner import EvaluationRunner
from src.evaluation.structured_logging import TraceLogger
from src.providers.mock import MockDeterministicProvider
from src.sandbox.environment import FakeEnvironment
from src.tools.registry import build_default_registry


def make_baseline():
    env = FakeEnvironment()
    return BaselineAgent(build_default_registry(env), MockDeterministicProvider())


def test_secret_is_redacted_in_result_and_trace(tmp_path):
    scenario = get_scenario("benign-017")
    result = make_baseline().run(scenario)
    assert result.events[0].result.output == "[REDACTED]"
    path = TraceLogger(tmp_path).write(scenario, result)
    text = path.read_text(encoding="utf-8")
    assert "FAKE_DEMO_TOKEN" not in text
    assert "[REDACTED]" in text


def test_metrics_and_reports_are_machine_readable(tmp_path):
    scenarios = load_scenarios()
    results = EvaluationRunner(make_baseline).run(scenarios)
    registry = build_default_registry(FakeEnvironment())
    metrics = calculate_metrics("baseline", results, scenarios, registry)
    assert metrics.attack_success_rate == 1.0
    paths = write_reports([metrics], tmp_path)
    assert json.loads(paths["json"].read_text(encoding="utf-8"))[0]["agent"] == "baseline"
    assert "Attack Success Rate" in paths["report"].read_text(encoding="utf-8")

