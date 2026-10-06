# Provenance/Data-Flow Evaluation — mock / deterministic

> Artifacts are symbolic identifiers only. Raw Secret values are never serialized and all sinks are simulated.

Scenarios: 12 (9 attack, 3 benign).

## Real LLM smoke

| Variant | ASR | FPR | Benign completion | Exfil detection | Direct detection | Indirect detection | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| context-sequence-only | 0.0% | 0.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| context-provenance | 0.0% | 33.3% | 66.7% | 100.0% | 100.0% | 100.0% | 90.0% | 100.0% | 94.7% |
| context-provenance-scoped | 0.0% | 0.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |

## Deterministic identical-proposal comparison

| Variant | ASR | FPR | Benign completion | Exfil detection | Indirect detection | Provenance-rule detection |
|---|---:|---:|---:|---:|---:|---:|
| context-sequence-only | 0.0% | 0.0% | 100.0% | 100.0% | 100.0% | 0.0% |
| context-provenance | 0.0% | 33.3% | 66.7% | 100.0% | 100.0% | 88.9% |
| context-provenance-scoped | 0.0% | 0.0% | 100.0% | 100.0% | 100.0% | 88.9% |

## Sequence allowed, provenance blocked

- None in this run.

## Provenance ablation

| Variant | ASR | FPR | Benign completion | Provenance detection | Indirect provenance detection |
|---|---:|---:|---:|---:|---:|
| provenance-full | 0.0% | 0.0% | 100.0% | 88.9% | 87.5% |
| without-source-labeling | 0.0% | 0.0% | 100.0% | 0.0% | 0.0% |
| without-transformation-propagation | 0.0% | 0.0% | 100.0% | 33.3% | 25.0% |
| without-sink-classification | 0.0% | 0.0% | 100.0% | 0.0% | 0.0% |
| without-derived-from-tracking | 0.0% | 0.0% | 100.0% | 55.6% | 50.0% |
| without-scoped-authorization-integration | 0.0% | 33.3% | 66.7% | 88.9% | 87.5% |

## Interpretation

The sequence baseline retains the existing execution-history rules. Provenance contributes only when a symbolic sensitive lineage reaches a classified sink; intermediate encoding, splitting, file, and log operations do not clear sensitivity. One-way fingerprints are explicitly declassified to INTERNAL.

The incremental benefit should be read from the identical-proposal differential cases, not from model-run aggregate differences alone. Local model variants are sampled independently and can choose different chains.

## Limitations

- Symbolic references require cooperating Tool adapters; arbitrary semantic copying outside registered artifacts is not tracked.
- The prototype does not inspect real bytes, nested archives, encryption, steganography, or covert channels.
- Declassification is hard-coded for the simulated fingerprint Tool and would require trusted implementation attestation in production.
- A task-local graph cannot follow flows across processes, agents, or evaluation runs.
- Correct source labels and sink classification remain trusted assumptions.
