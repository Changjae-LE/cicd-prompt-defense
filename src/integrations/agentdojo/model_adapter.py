from __future__ import annotations

import os
from collections.abc import Iterable, Sequence
from typing import Any

from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, load_system_message
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM
from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop, ToolsExecutor
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
from agentdojo.types import ChatMessage
from openai import OpenAI

from src.integrations.agentdojo.defense_gate import DefenseAwareToolsExecutor, RecordingToolsExecutor


class CapturingAgentPipeline(AgentPipeline):
    """Native AgentPipeline with read-only access to its latest output trace."""

    def __init__(self, elements: Iterable[BasePipelineElement]) -> None:
        super().__init__(elements)
        self.last_messages: Sequence[ChatMessage] = []
        self.last_environment: Env = EmptyEnv()

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = [],
        extra_args: dict = {},
    ):
        output = super().query(query, runtime, env, messages, extra_args)
        self.last_environment = output[2]
        self.last_messages = output[3]
        return output


def ollama_openai_client(base_url: str = "http://127.0.0.1:11434") -> OpenAI:
    return OpenAI(base_url=f"{base_url.rstrip('/')}/v1", api_key="ollama")


def openai_api_client(
    *,
    api_key: str | None = None,
    base_url: str | None = None,
) -> OpenAI:
    resolved_key = api_key if api_key is not None else os.environ.get("OPENAI_API_KEY", "")
    if not resolved_key:
        raise ValueError("OPENAI_API_KEY is not set; external validation was not started")
    resolved_url = base_url if base_url is not None else os.environ.get("OPENAI_BASE_URL")
    kwargs: dict[str, Any] = {"api_key": resolved_key}
    if resolved_url:
        kwargs["base_url"] = resolved_url
    return OpenAI(**kwargs)


def available_ollama_models(base_url: str = "http://127.0.0.1:11434") -> list[str]:
    return [item.id for item in ollama_openai_client(base_url).models.list().data]


def model_is_available(model: str, installed: Sequence[str]) -> bool:
    requested = model.removesuffix(":latest")
    return any(item.removesuffix(":latest") == requested for item in installed)


def build_ollama_pipeline(
    model: str,
    variant: str,
    *,
    temperature: float = 0.0,
    base_url: str = "http://127.0.0.1:11434",
) -> tuple[CapturingAgentPipeline, Any]:
    if variant not in {"baseline", "context-aware", "full", "refined-full"}:
        raise ValueError("AgentDojo variants are baseline, context-aware, full, and refined-full")
    llm = OpenAILLM(ollama_openai_client(base_url), model, temperature=temperature)
    llm.name = f"local-{model}"
    if variant == "baseline":
        executor = RecordingToolsExecutor(ToolsExecutor())
    else:
        executor = DefenseAwareToolsExecutor(variant)
    pipeline = CapturingAgentPipeline([
        SystemMessage(load_system_message(None)),
        InitQuery(),
        llm,
        ToolsExecutionLoop([executor, llm]),
    ])
    pipeline.name = f"local-{model}-{variant}"
    return pipeline, executor


def build_openai_pipeline(
    model: str,
    variant: str,
    *,
    temperature: float = 0.0,
    client: OpenAI | None = None,
) -> tuple[CapturingAgentPipeline, Any]:
    """Build the same native AgentDojo pipeline against the OpenAI API.

    The exact caller-supplied model ID is preserved. This function never resolves
    aliases or substitutes a fallback model.
    """

    if variant not in {"baseline", "context-aware", "full", "refined-full"}:
        raise ValueError("AgentDojo variants are baseline, context-aware, full, and refined-full")
    llm = OpenAILLM(client or openai_api_client(), model, temperature=temperature)
    if variant == "baseline":
        executor = RecordingToolsExecutor(ToolsExecutor())
    else:
        executor = DefenseAwareToolsExecutor(variant)
    pipeline = CapturingAgentPipeline([
        SystemMessage(load_system_message(None)),
        InitQuery(),
        llm,
        ToolsExecutionLoop([executor, llm]),
    ])
    # ImportantInstructionsAttack derives the human-facing model name from this
    # native pipeline name. Keep the exact snapshot ID present.
    pipeline.name = f"{model}-{variant}"
    return pipeline, executor
