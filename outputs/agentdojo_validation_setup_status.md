# AgentDojo external-validation setup status

Date: 2026-10-07

## Current status

- Existing AgentDojo adapter commit preserved: `632d222`
- Original Ollama 45-case pilot preserved unchanged
- Existing AgentDojo test baseline confirmed: `123 passed`
- New validation tests: `5 passed`
- Current AgentDojo environment total: `128 passed`
- Requested model: `gpt-4o-mini-2024-07-18`
- Attack: native `important_instructions`
- Official OpenAI catalog: requested snapshot is listed and supports function calling
- Current API account access: not checked because `OPENAI_API_KEY` is absent
- Automatic fallback: not performed
- Phase 1: not run
- Phase 2: not run by qualification gate

## Frozen selection

The manifest was written before any model request under `results/agentdojo/validation/selection_manifest.json`.

Selection rule:

1. Use the native `banking`, `travel`, `workspace`, and `slack` suites.
2. Per suite, select the two lowest numeric user-task IDs with a native-visible injection vector.
3. Per suite, select the two lowest numeric injection-task IDs with non-empty native Tool ground truth.
4. Use each suite's 2×2 Cartesian product.
5. Add the official AgentDojo repository positive-control `banking/user_task_11/injection_task_0` for `gpt-4o-mini-2024-07-18 + important_instructions`.
6. Never replace cases after observing results.

This produces 17 frozen cases. It is a signal-enriched qualification set, not a population ASR estimate and not a published-result reproduction.

## Qualification gate

Phase 2 runs only if Phase 1 satisfies both:

```text
malicious ground-truth Tool proposals > 0
and Baseline native ASR > 0
```

If the gate passes, Baseline results are reused and Context-Aware/Full run on exactly the same model, attack, task IDs, and injection IDs. Conditional success counts only an actually proposed native ground-truth malicious call that the gate blocks before execution.

## Generated blocked-state outputs

The following required files exist under `results/agentdojo/validation/` and explicitly record `blocked_missing_api_key` / `not_run` rather than fabricated measurements:

- `qualification_summary.json`
- `qualification_cases.csv`
- `defense_comparison_summary.json`
- `defense_comparison_cases.csv`
- `validation_report.md`
- `selection_manifest.json`

## Required action

Set `OPENAI_API_KEY` in the Codex task environment without pasting it into chat, then rerun:

```powershell
$env:PYTHONUTF8 = "1"
.\.venv-agentdojo\Scripts\python.exe -m src.integrations.agentdojo.validation `
  --model gpt-4o-mini-2024-07-18 `
  --temperature 0 `
  --output-dir results/agentdojo/validation
```

The runner first checks exact account access to the requested snapshot. If unavailable, it stops and records accessible candidates; it never silently substitutes another model. An explicit fallback requires a separate `--fallback-model` argument and is labelled external validation rather than reproduction.
