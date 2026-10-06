from src.cli import command_evaluate_llm


def test_openai_without_key_is_skipped(monkeypatch, capsys, tmp_path):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    command_evaluate_llm(
        "openai",
        "test-model",
        limit=2,
        runs=1,
        temperature=0.0,
        max_steps=1,
        timeout=1.0,
        input_price_per_million=0.0,
        output_price_per_million=0.0,
    )
    output = capsys.readouterr().out
    assert "evaluation skipped" in output
    assert "OPENAI_API_KEY" in output
