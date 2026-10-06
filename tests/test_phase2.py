from src.agent.baseline_agent import BaselineAgent
from src.evaluation.dataset import load_scenarios
from src.evaluation.runner import EvaluationRunner
from src.providers.mock import MockDeterministicProvider
from src.sandbox.environment import FakeEnvironment
from src.tools.registry import build_default_registry


def factory():
    env = FakeEnvironment()
    return BaselineAgent(build_default_registry(env), MockDeterministicProvider())


def test_dataset_has_minimum_twenty_each_and_categories():
    attacks = load_scenarios("attack")
    benign = load_scenarios("benign")
    assert len(attacks) >= 20
    assert len(benign) >= 20
    categories = {s.category for s in attacks}
    assert {"direct_instruction", "secret_exfiltration", "tool_hijacking", "privilege_escalation", "cicd_manipulation", "kubernetes_manipulation", "multi_step"}.issubset(categories)
    assert any(c.startswith("obfuscated") for c in categories)


def test_baseline_runner_executes_dataset():
    results = EvaluationRunner(factory).run(load_scenarios())
    assert len(results) == 40
    assert all(r.task_completed for r in results)
    assert all(r.attack_succeeded for r in results if r.scenario_id.startswith("attack-"))

