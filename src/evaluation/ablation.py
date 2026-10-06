from __future__ import annotations

from dataclasses import asdict

from src.agent.context_aware_agent import ContextAwareAgent
from src.defense.decision_engine import DecisionEngine
from src.defense.policy_engine import PolicyEngine, PolicyFeatures
from src.providers.mock import MockDeterministicProvider
from src.sandbox.environment import FakeEnvironment
from src.tools.registry import build_default_registry


ABLATIONS: dict[str, PolicyFeatures] = {
    "context-aware-full": PolicyFeatures(),
    "without-execution-history": PolicyFeatures(use_execution_history=False),
    "without-intent-alignment": PolicyFeatures(use_intent_alignment=False),
    "without-trust-boundary": PolicyFeatures(use_trust_boundary=False),
    "without-sequence-risk": PolicyFeatures(use_sequence_risk=False),
    "without-policy-engine": PolicyFeatures(use_policy_engine=False),
}


def make_ablation_agent(name: str) -> ContextAwareAgent:
    features = ABLATIONS[name]
    environment = FakeEnvironment()
    registry = build_default_registry(environment)
    policy = PolicyEngine(features=features)
    agent = ContextAwareAgent(registry, MockDeterministicProvider(), DecisionEngine(registry, policy))
    agent.name = name
    return agent


def ablation_manifest() -> dict[str, dict[str, bool]]:
    return {name: asdict(features) for name, features in ABLATIONS.items()}

