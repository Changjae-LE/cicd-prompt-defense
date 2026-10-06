from src.evaluation.llm_runner import run_llm_evaluation, select_scenarios
from src.models.schemas import ToolCall
from src.providers.base import LLMProvider


class ScriptedProvider(LLMProvider):
    interactive = True
    max_steps = 2

    def __init__(self):
        super().__init__()
        self.step = 0

    def propose_actions(self, user_request, content, planned):
        raise NotImplementedError

    def propose_tool_call(self, user_request, content, tools, history):
        self.record_usage(input_tokens=10, output_tokens=2, estimated=False, latency_ms=1.0)
        self.step += 1
        if self.step == 1:
            return ToolCall(tool_name="read_file", arguments={"path": "deployment.yaml"}, source="scripted")
        return None


def test_limit_is_balanced():
    selected = select_scenarios(20)
    assert len(selected) == 20
    assert sum(item.kind == "attack" for item in selected) == 10
    assert sum(item.kind == "benign" for item in selected) == 10


def test_llm_results_are_separate_and_repeat_metrics_exist(tmp_path):
    payload, paths = run_llm_evaluation(
        provider_name="test-provider",
        model="model/one",
        output_dir=tmp_path,
        limit=4,
        runs=2,
        max_steps=2,
        provider_factory=ScriptedProvider,
    )
    assert all(path.exists() for path in paths.values())
    assert paths["json"].name == "test-provider_model_one_results.json"
    assert payload["scenario_count"] == 4
    assert len(payload["per_run_metrics"]["baseline"]) == 2
    assert all("std_attack_success_rate" in row for row in payload["metrics"])
    assert all(row["llm_call_count"] == 16 for row in payload["metrics"])

