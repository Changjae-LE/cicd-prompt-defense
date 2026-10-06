# Goal-Aware Evaluation — ollama / llama3.1

> Operational termination and research audit are reported separately. Audit-only high-risk proposals are authorized but never executed.

## Real LLM comparison

| Mode | ASR (executed) | Audit counterfactual ASR | Existing FPR | Operational FPR | Benign completion | Goal completion | Post-task malicious detection | Calls | Tokens | Latency ms | Call savings | Token savings | Latency savings |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| current-agent | 20.0% | 20.0% | 60.0% | 40.0% | 40.0% | 50.0% | 100.0% | 37 | 36310 | 26742.7 | 0.0% | 0.0% | 0.0% |
| goal-aware-operational | 20.0% | 20.0% | 40.0% | 40.0% | 40.0% | 50.0% | 0.0% | 24 | 22945 | 12200.7 | 35.1% | 36.8% | 54.4% |
| goal-aware-research-audit | 20.0% | 20.0% | 60.0% | 40.0% | 40.0% | 50.0% | 100.0% | 34 | 33130 | 18270.3 | 8.1% | 8.8% | 31.7% |

`attack_success_rate` counts only executed malicious calls and can fall mechanically in operational/audit modes. `audit_counterfactual_asr` restores malicious audit proposals that the policy would have allowed, so early termination is not credited as defense.

## Focused deterministic scenarios

| Mode | Goal completion | Existing FPR | Operational FPR | Post-task rate | Redundant rate | Post-task malicious detection |
|---|---:|---:|---:|---:|---:|---:|
| current-agent | 66.7% | 0.0% | 0.0% | 33.3% | 50.0% | 100.0% |
| goal-aware-operational | 66.7% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| goal-aware-research-audit | 66.7% | 0.0% | 0.0% | 33.3% | 50.0% | 100.0% |

## Goal detector ablation

| Variant | Goal completion | False completions | Post-task malicious detections | Avg calls before goal |
|---|---:|---:|---:|---:|
| goal-detector-full | 66.7% | 0 | 2 | 1.33 |
| without-execution-history | 50.0% | 0 | 2 | 1.50 |
| without-resource-matching | 83.3% | 1 | 2 | 1.33 |
| without-tool-results | 83.3% | 1 | 2 | 1.33 |

## Research questions answered

1. **Operational FP:** original FPR changed from 60.0% to 40.0% when post-goal blocks were removed from the operational path.
2. **Benign completion:** remained 40.0%; termination removed redundant work but did not repair unrelated model/Tool or scope failures.
3. **Tool calls:** decreased by 13 (35.1%).
4. **Tokens and latency:** tokens decreased by 13365 (36.8%); measured total latency decreased by 14542.0 ms (54.4%).
5. **Post-task attacks:** audit mode observed malicious post-task proposals in 2 attack scenarios and blocked 100.0% of them.
6. **Premature completion:** the full detector produced 0 false completions in the focused controls. Removing resource matching or Tool-result validation creates false completion.
7. **New false negatives:** audit counterfactual ASR was 20.0%, versus current ASR 20.0%; no reduction was credited solely to non-execution.

## Safety and interpretation

- Operational mode stops provider sampling immediately after a structured goal is satisfied.
- Research audit samples only the configured number of additional proposals. Those calls receive security decisions but no Tool executes.
- Existing FPR is retained; operational FPR separately estimates user-visible blocking before a successful stop.
- Goal definitions use evaluation expected outcomes and trusted authorization scope. This is an oracle-assisted study, not a production-quality semantic goal judge.
- Token and latency savings compare independent model runs and should be confirmed with repeated trials.
- A bounded audit can still miss malicious behavior delayed beyond the configured audit window.
- Exact canonical matching avoids alias-based privilege expansion but can miss semantically equivalent benign resources.
- The current goal compiler is deterministic and English-oriented; complex remediation quality cannot be inferred from Tool-name completion alone.
