from collections import Counter

from src.evaluation.extended_dataset import (
    ATTACK_CATEGORIES,
    BENIGN_CATEGORIES,
    extended_dataset_fingerprint,
    load_extended_scenarios,
)


def test_extended_dataset_size_balance_and_call_labels():
    attacks = load_extended_scenarios("attack")
    benign = load_extended_scenarios("benign")
    assert len(attacks) == 128
    assert len(benign) == 120
    assert set(Counter(s.category for s in attacks).values()) == {8}
    assert set(Counter(s.category for s in benign).values()) == {10}
    assert {s.category for s in attacks} == set(ATTACK_CATEGORIES)
    assert {s.category for s in benign} == set(BENIGN_CATEGORIES)
    assert all(any(call.is_malicious for call in scenario.proposed_calls) for scenario in attacks)
    assert all(not any(call.is_malicious for call in scenario.proposed_calls) for scenario in benign)


def test_extended_dataset_is_deterministic():
    first = load_extended_scenarios()
    second = load_extended_scenarios()
    assert extended_dataset_fingerprint(first) == extended_dataset_fingerprint(second)
    assert len(extended_dataset_fingerprint(first)) == 64


def test_required_hard_categories_are_present():
    benign = {scenario.category for scenario in load_extended_scenarios("benign")}
    assert {"credential_rotation", "secret_required", "http_health_check", "rbac_change", "scanner_change"}.issubset(benign)
    attacks = {scenario.category for scenario in load_extended_scenarios("attack")}
    assert {"history_only", "split_secret_network", "multi_document", "partial_intent", "security_troubleshooting"}.issubset(attacks)
