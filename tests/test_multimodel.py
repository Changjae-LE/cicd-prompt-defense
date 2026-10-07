from __future__ import annotations

from src.evaluation.multimodel_runner import (
    ALL_VARIANTS,
    ModelSpec,
    ReplayProvider,
    make_variant_agent,
    parse_variants,
    run_multimodel_evaluation,
    select_multimodel_scenarios,
)
from src.models.schemas import ToolCall
from src.providers.base import LLMProvider, ProviderConfigurationError
from src.providers.mock import MockDeterministicProvider
from src.sandbox.environment import FakeEnvironment
from src.tools.registry import build_default_registry


class ScriptedProvider(LLMProvider):
    interactive = True
    max_steps = 2

    def __init__(self):
        super().__init__()
        self.step = 0

    def propose_actions(self, user_request, content, planned):
        raise NotImplementedError

    def propose_tool_call(self, user_request, content, tools, history):
        self.record_usage(input_tokens=8, output_tokens=2, estimated=False, latency_ms=1.0)
        self.step += 1
        if self.step == 1:
            return ToolCall(tool_name="read_file", arguments={"path": "deployment.yaml"})
        return None


class MissingProvider(ScriptedProvider):
    def ensure_available(self):
        raise ProviderConfigurationError("test model is not installed")


def test_multimodel_selection_is_balanced_and_deterministic():
    first = select_multimodel_scenarios(12)
    second = select_multimodel_scenarios(12)
    assert [item.id for item in first] == [item.id for item in second]
    assert sum(item.kind == "attack" for item in first) == 6
    assert sum(item.kind == "benign" for item in first) == 6


def test_all_six_variants_are_constructible():
    for variant in ALL_VARIANTS:
        registry = build_default_registry(FakeEnvironment())
        agent = make_variant_agent(
            variant, registry, MockDeterministicProvider(), post_task_audit_steps=2
        )
        assert agent.name == variant


def test_variant_parser_rejects_unknown_and_deduplicates():
    assert parse_variants("baseline,full,baseline") == ["baseline", "full"]
    try:
        parse_variants("baseline,unknown")
    except ValueError as exc:
        assert "unknown" in str(exc)
    else:
        raise AssertionError("unknown variant should fail")


def test_replay_provider_returns_identical_deep_copied_sequence():
    calls = [ToolCall(tool_name="read_file", arguments={"path": "README.md"})]
    provider = ReplayProvider(calls)
    replayed = provider.propose_actions("", [], [])
    replayed[0].arguments["path"] = "changed"
    assert calls[0].arguments["path"] == "README.md"
    assert provider.usage.calls == 0


def test_multimodel_writes_end_to_end_and_controlled_outputs(tmp_path):
    payload, paths = run_multimodel_evaluation(
        specs=[ModelSpec("test", "model-one")],
        output_dir=tmp_path,
        variants=["baseline", "full"],
        limit=4,
        runs=2,
        max_steps=2,
        provider_builder=lambda spec: ScriptedProvider(),
    )
    assert all(path.exists() for path in paths.values())
    assert payload["dataset"]["attack_count"] == 2
    assert payload["dataset"]["benign_count"] == 2
    assert {row["evaluation_mode"] for row in payload["metrics"]} == {"end_to_end", "controlled"}
    controlled = [row for row in payload["metrics"] if row["evaluation_mode"] == "controlled"]
    assert all(row["llm_call_count_mean"] == 0 for row in controlled)
    assert payload["configuration"]["controlled_proposal_source"].startswith("baseline")
    assert (tmp_path / "test_model-one_results.json").exists()
    report = paths["report"].read_text(encoding="utf-8")
    assert "The 2 deterministic repetitions provide descriptive replication only" in report
    assert "Smoke samples and one run" not in report


def test_unavailable_models_are_recorded_without_installing(tmp_path):
    payload, _ = run_multimodel_evaluation(
        specs=[ModelSpec("ollama", "missing-model")],
        output_dir=tmp_path,
        variants=["baseline"],
        limit=2,
        provider_builder=lambda spec: MissingProvider(),
    )
    status = payload["model_status"][0]
    assert status["status"] == "unavailable"
    assert status["installation_command"] == "ollama pull missing-model"
    assert payload["metrics"] == []
