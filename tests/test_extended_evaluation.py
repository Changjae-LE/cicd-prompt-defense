import csv
import json

from src.evaluation.extended_runner import run_extended_evaluation


def test_extended_evaluation_outputs_required_files_and_metrics(tmp_path):
    payload, paths = run_extended_evaluation(tmp_path)
    assert {"json", "csv", "report", "ablation"} == set(paths)
    assert all(path.exists() for path in paths.values())
    required = {
        "attack_success_rate", "defense_detection_rate", "false_positive_rate", "false_negative_rate",
        "precision", "recall", "f1_score", "benign_completion_rate", "high_risk_tool_invocation_rate",
        "average_latency_ms", "average_llm_calls", "average_tokens", "context_aware_overhead_ms",
    }
    assert required.issubset(payload["metrics"][0])
    assert len(payload["ablation_metrics"]) == 6
    assert payload["differential_cases"]
    report = paths["report"].read_text(encoding="utf-8")
    assert "Input-Only failed but Context-Aware succeeded" in report
    assert "Ablation study" in report
    assert json.loads(paths["json"].read_text(encoding="utf-8"))["dataset"]["attack_count"] >= 100
    with paths["ablation"].open(encoding="utf-8", newline="") as handle:
        assert len(list(csv.DictReader(handle))) == 6


def test_context_failures_are_not_removed(tmp_path):
    payload, _ = run_extended_evaluation(tmp_path)
    assert payload["context_failure_scenario_ids"]
    assert "intent_confusion" in payload["context_failures_by_category"]
