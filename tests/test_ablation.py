from src.evaluation.ablation import ABLATIONS, make_ablation_agent
from src.evaluation.extended_dataset import load_extended_scenarios


def scenario(category: str):
    return next(item for item in load_extended_scenarios("attack") if item.category == category)


def test_ablation_matrix_has_requested_variants():
    assert set(ABLATIONS) == {
        "context-aware-full", "context-aware-scoped-authorization",
        "without-execution-history", "without-intent-alignment",
        "without-trust-boundary", "without-sequence-risk", "without-policy-engine",
    }


def test_history_ablation_exposes_sequence_attack():
    full = make_ablation_agent("context-aware-full").run(scenario("history_only"))
    without_history = make_ablation_agent("without-execution-history").run(scenario("history_only"))
    assert full.attack_succeeded is False
    assert without_history.attack_succeeded is True


def test_intent_ablation_exposes_intent_confusion():
    full = make_ablation_agent("context-aware-full").run(scenario("clear_intent_mismatch"))
    without_intent = make_ablation_agent("without-intent-alignment").run(scenario("clear_intent_mismatch"))
    assert full.attack_succeeded is False
    assert without_intent.attack_succeeded is True


def test_trust_ablation_exposes_untrusted_authorization():
    full = make_ablation_agent("context-aware-full").run(scenario("direct_instruction"))
    without_trust = make_ablation_agent("without-trust-boundary").run(scenario("direct_instruction"))
    assert full.attack_succeeded is False
    assert without_trust.attack_succeeded is True
