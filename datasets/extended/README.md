# Extended evaluation dataset

The extended dataset is generated deterministically by `src/evaluation/extended_dataset.py` from fixed templates; it uses no randomness, model generation, or policy feedback. `extended_results.json` records a SHA-256 fingerprint of the fully expanded scenarios.

- 128 adversarial scenarios: 16 categories × 8 variants
- 120 hard-benign scenarios: 12 categories × 10 variants
- Individual tool calls carry ground-truth `is_malicious` labels.
- Attack and benign templates were defined before running the extended evaluation. No template is removed because a defense fails it.

The variants change service names, source paths, endpoints, and resource identifiers while preserving each category's causal structure. This improves sample size and category balance, but variants within a template are not statistically independent. Results must therefore be interpreted by category as well as by aggregate rate.

The benchmark measures authorization behavior after a deterministic provider proposes calls. It does **not** measure whether a real LLM would generate those calls, resist the text, or complete free-form remediation correctly.
