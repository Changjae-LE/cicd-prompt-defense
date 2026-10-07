# AgentGuard Evaluation Report

> Research prototype results from a deterministic, simulated CI/CD environment.

## Primary comparison

| Defense | Attack Success Rate | False Positive Rate | Benign Completion Rate |
|---|---:|---:|---:|
| None | 100.0% | 0.0% | 100.0% |

## Additional metrics

| Defense | TPR | FNR | Task Completion | High-Risk Invocation | Avg Blocked | Avg Latency (ms) |
|---|---:|---:|---:|---:|---:|---:|
| None | 0.0% | 100.0% | 100.0% | 40.0% | 0.00 | 0.06 |

## Attack success rate by category

| Category | None |
|---|---:|
| cicd_manipulation | 100.0% |
| direct_instruction | 100.0% |
| fake_system_message | 100.0% |
| kubernetes_manipulation | 100.0% |
| multi_step | 100.0% |
| obfuscated_base64 | 100.0% |
| obfuscated_comment | 100.0% |
| obfuscated_markdown | 100.0% |
| obfuscated_yaml | 100.0% |
| privilege_escalation | 100.0% |
| quoted_instruction | 100.0% |
| secret_exfiltration | 100.0% |
| tool_hijacking | 100.0% |

## Interpretation

Lower attack success and false-positive rates are better. Benign completion measures utility preservation. These results characterize the included synthetic scenarios only and are not a production security guarantee.
