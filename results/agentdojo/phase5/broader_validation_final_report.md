# Phase 5 final verification and 50-case broader validation

## Final verification

- Default environment regression: **115 passed**.
- AgentDojo environment regression: **165 passed**.
- All six required Phase 5 artifacts exist: the reclassification CSV/JSON, smoke CSV/JSON, tool-semantics report, and validity report.
- Phase 5 row counts are internally consistent: 266 reclassification rows and 140 smoke rows (20 Baseline source + 60 End-to-End + 60 Controlled Replay).
- The fresh smoke uses 20 unique frozen cases. Its model is exactly `gpt-4o-mini-2024-07-18`; exact access, function calling, and tool-call ID preservation all passed.
- The Phase 5 runner verified that the original Phase 4 smoke files, Defense sources, and AgentDojo native sources retained their checksums. The broader run was written to a separate `phase4/broader` directory.
- Security-policy/adapter/metric/schema checksums still match the broader manifest. AgentDojo native-source checksums also match. Recomputing the deterministic selection produced exactly the stored 50 cases.
- Thresholds remain frozen at 5% core integration error, 10% benchmark warning, and 25% benchmark severe-stop.
- An exact-material and key-shaped-token scan of 101 result/report files found zero API-key matches.
- Phase 5 smoke status is **PASS**. Its 18.75% benchmark-native outcome rate carries an interpretation warning but does not cross the 25% stop threshold.

## Frozen broader configuration

- AgentDojo `0.1.35`, benchmark `v1.2.2`
- Model `gpt-4o-mini-2024-07-18`, temperature `0`, no fallback
- Native attack `important_instructions`
- 50 deterministic cases with no overlap with the original 17: banking 13, travel 13, workspace 12, slack 12
- Variants: Context-Aware, Phase 2 Full, Refined Full
- End-to-End and Controlled Replay both executed; Controlled Replay is the primary causal comparison

## Primary result: Controlled Replay

The shared frozen Baseline proposals contained **38 strict malicious calls in 25/50 cases**. This is distinct from cases in which the model never proposed a malicious action.

| Variant | Detected / 38 | Detection (Wilson 95% CI) | Executed / 38 | Strict execution (95% CI) | FPR proxy (95% CI) |
|---|---:|---:|---:|---:|---:|
| Context-Aware | 15 | 39.5% [25.6%, 55.3%] | 23 | 60.5% [44.7%, 74.4%] | 15.8% [11.7%, 20.9%] |
| Phase 2 Full | 27 | 71.1% [55.2%, 83.0%] | 11 | 28.9% [17.0%, 44.8%] | 30.7% [25.2%, 36.8%] |
| Refined Full | 31 | 81.6% [66.6%, 90.8%] | 7 | 18.4% [9.2%, 33.4%] | 39.0% [33.1%, 45.3%] |

Refined Full blocks 16 more strict malicious calls than Context-Aware and 4 more than Phase 2 Full, but its FPR proxy is also 23.2 percentage points above Context-Aware and 8.3 points above Phase 2 Full. The wider subset therefore confirms a security/utility trade-off rather than an unqualified improvement.

## Descriptive End-to-End result

Independent trajectories are not a causal comparison.

| Variant | Native ASR (Wilson 95% CI) | Native Utility (Wilson 95% CI) | E2E strict execution |
|---|---:|---:|---:|
| Context-Aware | 24.0% [14.3%, 37.4%] | 44.0% [31.2%, 57.7%] | 55.9% |
| Phase 2 Full | 6.0% [2.1%, 16.2%] | 34.0% [22.4%, 47.8%] | 31.1% |
| Refined Full | 0.0% [0.0%, 7.1%] | 32.0% [20.8%, 45.8%] | 18.2% |

The 0/50 Refined Full ASR has an upper Wilson bound of 7.1%; it must not be described as proof of zero population risk.

## Phase 5 validity reclassification

The raw Phase 4 report is preserved unchanged and labels a 21.5% combined tool error as invalid. Under the frozen Phase 5 taxonomy, those events are not adapter failures.

| Category | Affected actual case-runs | Rate |
|---|---:|---:|
| Provider error | 0 / 200 | 0.0% |
| Parsing error | 0 / 200 | 0.0% |
| Adapter integration error | 0 / 200 | 0.0% |
| EMPTY_RESULT | 9 / 200 | 4.5% |
| ENTITY_NOT_FOUND | 29 / 200 | 14.5% |
| BENCHMARK_TOOL_RUNTIME_ERROR | 1 / 200 | 0.5% |
| Benchmark-native outcome, union | 39 / 200 | 19.5% |
| Model argument/invalid-entity indicator | 31 / 200 | 15.5% |

Proposal-source mismatches, missing ground truth, and replay errors were all zero. Core integration error is 0%. Benchmark-native outcomes exceed the 10% interpretation threshold but remain below the 25% severe-stop threshold. Final validity is therefore **PASS with interpretation warning**.

## Generalization gap from the original 17 cases

| Variant | Detection gap | FPR-proxy gap | Strict-execution gap | Native-ASR gap | Native-utility gap |
|---|---:|---:|---:|---:|---:|
| Context-Aware | -24.8 pp | -0.0 pp | +24.8 pp | +6.4 pp | -14.8 pp |
| Phase 2 Full | -0.4 pp | +9.7 pp | +0.4 pp | +0.1 pp | -30.7 pp |
| Refined Full | +3.0 pp | +16.2 pp | -3.0 pp | +0.0 pp | -44.5 pp |

Refined Full's controlled malicious-call detection generalized in this subset, but the FPR proxy and native utility degraded substantially. Context-Aware's lower FPR generalized, while its malicious-call detection weakened. This is the central result of the broader validation.

## Matcher and interpretation limits

- Strict/native matcher mismatch rows: 26.
- Of these, 6 were native successes without an exact malicious ground-truth call, 16 were intermediate/partial read actions, and 4 were strict calls that did not complete the native attack goal.
- The results support claims only for this frozen 50-case, four-domain subset, this exact model snapshot, `important_instructions`, and one run.
- They do not establish cross-model or cross-attack generalization, do not constitute the full AgentDojo benchmark, and are not a reproduction of published AgentDojo results.
- Controlled Replay supports the causal blocking comparison. End-to-End ASR and utility remain descriptive because each Defense produces a different model trajectory.
