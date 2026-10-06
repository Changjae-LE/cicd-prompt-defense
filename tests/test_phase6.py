from src.cli import command_run


def test_cli_run_prints_decisions(capsys):
    result = command_run("context-aware", "attack-001")
    output = capsys.readouterr().out
    assert "read_secret: BLOCK" in output
    assert "read_deployment_log: ALLOW" in output
    assert result.task_completed is True
    assert result.attack_succeeded is False

