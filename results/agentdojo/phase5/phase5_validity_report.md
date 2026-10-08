# AgentDojo Phase 5 validity report

Phase 5 changes error attribution only. Security policy, defenses, matcher, prompts, Tool schemas, and the 20-case selection remain frozen.

## Existing Phase 4 20% reclassification

- Actual case-runs: `80`
- Provider/integration affected rate: `0.0%`
- Benchmark-native runtime affected rate: `20.0%`
- Empty-result rate: `10.0%`
- Entity-not-found rate: `10.0%`
- Model-generated invalid entity/argument rate: `11.2%`

## Fresh identical 20-case smoke validity

- Provider errors: `0.0%`
- Parsing errors: `0.0%`
- Adapter integration errors: `0.0%`
- Benchmark runtime errors: `18.8%`
- Empty results: `10.0%`
- Entity not found: `8.8%`
- Model argument errors: `8.8%`
- Proposal-source mismatch: `0`
- Missing ground truth: `0`
- Gate status: **PASS**
- Resume 50-case broader validation: **PASS**
- Interpretation warnings: `['benchmark_runtime_error_rate_interpretation_warning']`

## Completion attribution

- Native utility failures: `35`
- Defense-induced failure rate over all end-to-end case-runs: `38.3%`
- Failures with a security block present: `23` (65.7%)
- Non-exclusive completion labels: `{'task_impossible_or_benchmark_state_mismatch': 2, 'model_wrong_entity_or_argument': 4, 'empty_result_preceded_utility_failure': 1, 'defense_block_present': 23, 'integration_failure_present': 0}`
- Caution: Attribution is association, not proof that the block was the sole cause of utility failure.

## Controlled replay metrics (diagnostic, unchanged defense)

| Defense | Malicious calls | Blocked | Detection | FPR proxy |
|---|---:|---:|---:|---:|
| context-aware | 18 | 6 | 33.3% | 6.0% |
| full | 18 | 10 | 55.6% | 20.5% |
| refined-full | 18 | 14 | 77.8% | 32.5% |

## Matcher mismatch methodology issue

- Phase 4 mismatch rows: `13`
- `native_evaluator_credits_attack_without_exact_ground_truth_call`: 2
- `intermediate_or_partial_action_without_final_native_goal`: 10
- `strict_tool_call_without_complete_native_goal`: 1

Matcher definitions were not changed. These cases remain a Phase 6/future methodology issue.
