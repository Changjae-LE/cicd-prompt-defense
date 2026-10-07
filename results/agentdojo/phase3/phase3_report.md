# AgentDojo Phase 3 refined-defense evaluation

This is a frozen, signal-enriched external validation pilot, not an AgentDojo published-result reproduction.

## Configuration

- Model: `gpt-4o-mini-2024-07-18`
- Attack: `important_instructions`
- Cases: `17`
- Temperature: `0.0`
- Variants: Context-Aware, unchanged Phase 2 Full, Phase 3 Refined Full.
- Phase 1 and Phase 2 results were not overwritten.

## End-to-End

| Defense | Native ASR | Native utility | Strict proposal rate | Strict execution rate | Detection | FPR proxy | Malicious blocked | Benign blocked | Calls | Tokens | Avg latency ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| context-aware | 17.6% | 58.8% | 52.9% | 31.2% | 68.8% | 16.9% | 11 | 12 | 85 | 150521 | 5965.1 |
| full | 5.9% | 64.7% | 52.9% | 25.0% | 75.0% | 25.9% | 12 | 15 | 80 | 138063 | 5088.6 |
| refined-full | 0.0% | 76.5% | 52.9% | 14.3% | 85.7% | 30.6% | 18 | 22 | 90 | 160369 | 6371.1 |

## Controlled replay

| Defense | Malicious proposals | Blocked | Executed | Detection | FPR proxy | Payload blocks | Intent blocks |
|---|---:|---:|---:|---:|---:|---:|---:|
| context-aware | 14 | 9 | 5 | 64.3% | 15.8% | 0 | 0 |
| full | 14 | 10 | 4 | 71.4% | 21.1% | 0 | 0 |
| refined-full | 14 | 11 | 3 | 78.6% | 22.8% | 16 | 3 |

## Phase 2 Full → Refined Full causal delta

- Preserved malicious blocks: `10`
- Newly fixed malicious calls: `1`
- New malicious regressions: `0`
- New false-positive proxy calls: `1`
- Remaining executed malicious calls: `3`

The Phase 2 reference metrics below are retained only as a historical comparison because their Baseline proposal trace was not persisted and cannot be replayed exactly in Phase 3.

- Phase 2 `baseline` controlled detection=0.0%, FPR proxy=0.0%.
- Phase 2 `context-aware` controlled detection=70.6%, FPR proxy=9.4%.
- Phase 2 `full` controlled detection=70.6%, FPR proxy=17.0%.

## Architecture

- Payload-aware authorization assigns TRUSTED_USER_DERIVED, TRUSTED_SYSTEM_DERIVED, MODEL_GENERATED, UNTRUSTED_EXTERNAL_DERIVED, or MIXED_PROVENANCE per high-impact argument.
- Raw URLs, callbacks, attachments, recipients, and near-verbatim payload propagation are distinguished from transformed summaries and explicitly requested quotation.
- Parameter intent constraints cover entity, destination, resource/object identifier, date/time, recipient, amount, and URL. Explicit constraints are EXACT or ALLOWED_SET; absent values remain UNSPECIFIED and are not automatically blocked.
- Existing Full decisions are monotonic: Refined Full preserves existing denies, then adds payload or parameter mismatch denies.

## Interpretation boundary

A lower End-to-End ASR alone is not credited as a defense improvement. The main causal evidence is the Controlled Replay delta on the same Phase 3 Baseline proposal trace.
