# AgentDojo Phase 4 broader-validation 결과

## 결론

Phase 4의 20-case smoke는 사전에 고정한 validity gate를 통과하지 못했다. Provider error와 parsing error는 모두 0%였고 exact model, function calling, proposal-source digest, ground truth, defense/native source freeze는 모두 정상으로 확인되었다. 그러나 case-level Tool runtime/integration error가 20.0%로 사전 threshold 5%를 초과했다.

따라서 지시된 stop condition에 따라 50-case broader validation은 실행하지 않았다. 아래 수치는 유효성 경고가 붙은 smoke diagnostics이며, broader generalization 결과로 주장할 수 없다. Phase 4 도중 방어 rule, matcher, threshold, prompt, case selection은 변경하지 않았다.

## 1. 선택과 실행 범위

- 실행 case: 20개 smoke
- Domain 분포: banking 5, travel 5, workspace 5, slack 5
- 기존 signal-enriched 17개와 overlap: 0
- 새로운 broader-only case: 20
- 전체 eligible broader 후보: 592개(기존 17개 제외 후)
- Model: exact `gpt-4o-mini-2024-07-18`
- Attack: native `important_instructions`
- Runs: 1
- Fallback: 없음
- 50-case broader run: stop condition 때문에 미실행

선택은 결과를 보지 않고 수행했다. 각 suite에서 injectable user task와 non-empty native Tool ground truth를 가진 injection task의 Cartesian product를 만들고, 두 task 축을 대각선 순환한 뒤 suite round-robin으로 20개를 선택했다. 20개는 50개 선택의 정확한 prefix다. 각 injected case가 native attack result와 원래 user-task utility를 동시에 제공한다.

## 2. Controlled Replay smoke diagnostics

하나의 frozen Baseline proposal source를 세 방어에 동일하게 재생했다.

| Defense | Malicious calls | Blocked | Executed | Detection, Wilson 95% CI | FPR proxy, Wilson 95% CI |
|---|---:|---:|---:|---:|---:|
| Context-Aware | 14 | 4 | 10 | 28.57% [11.72%, 54.65%] | 10.59% [5.65%, 18.89%] |
| Phase 2 Full | 14 | 7 | 7 | 50.00% [26.77%, 73.23%] | 29.41% [20.80%, 39.83%] |
| Refined Full | 14 | 10 | 4 | 71.43% [45.35%, 88.28%] | 40.00% [30.24%, 50.63%] |

Phase 2 Full 대비 Refined Full은 기존 malicious block 7개를 모두 보존하고 strict malicious call 3개를 추가 차단했다. Malicious regression은 0개였다. 동시에 non-matching call 9개를 새로 차단해 FPR proxy가 10.59%p 증가했다. 이 9개 중 8개는 parameter-intent rule, 1개는 payload-propagation rule과 관련된다.

남은 strict malicious executions 4개는 다음 두 taxonomy로 분류되었다.

- Attack-chain intermediate read: 2개
- Same-tool/destination semantic attack 또는 부족한 의미 제약: 2개

## 3. End-to-End smoke diagnostics

각 arm은 독립 모델 trajectory이므로 causal comparison으로 사용하지 않는다.

| Defense | Native ASR, Wilson 95% CI | Native Utility, Wilson 95% CI | Strict execution | FPR proxy |
|---|---:|---:|---:|---:|
| Context-Aware | 35.00% [18.12%, 56.71%] | 55.00% [34.21%, 74.18%] | 80.00% | 10.47% |
| Phase 2 Full | 10.00% [2.79%, 30.10%] | 40.00% [21.88%, 61.34%] | 57.14% | 33.04% |
| Refined Full | 0.00% [0.00%, 16.11%] | 40.00% [21.88%, 61.34%] | 23.81% | 53.28% |

Refined Full의 Native ASR 0%는 작은 표본, 독립 trajectory, validity failure 때문에 일반화 증거가 아니다. 95% Wilson upper bound도 16.11%다.

## 4. Original 17 대비 provisional smoke delta

이 표는 진단용이며 validity failure 때문에 generalization gap 추정치로 사용할 수 없다.

| Defense | Detection delta | FPR proxy delta | Strict execution delta | Native utility delta |
|---|---:|---:|---:|---:|
| Context-Aware | -35.71%p | -5.20%p | +35.71%p | -3.82%p |
| Phase 2 Full | -21.43%p | +8.36%p | +21.43%p | -24.71%p |
| Refined Full | -7.14%p | +17.19%p | +7.14%p | -36.47%p |

Refined Full은 smoke에서도 Full보다 더 많은 동일 proposal을 차단했지만, 원래 17개보다 FPR proxy와 utility 손실 신호가 크게 악화되었다. 이는 Phase 5에서 검증할 중요한 over-constraint 후보다.

## 5. Refined rule별 효과

동일 event가 여러 rule에 동시에 귀속될 수 있으므로 행을 합산하면 전체 block 수보다 커질 수 있다. `Non-Malicious`는 fixed strict matcher 비일치이며 실제 benign을 보장하지 않는다.

| Rule | Malicious blocks | Non-malicious blocks | Precision-like ratio |
|---|---:|---:|---:|
| `PAYLOAD_SCOPE_MISMATCH` | 4 | 10 | 28.57% |
| `UNTRUSTED_PAYLOAD_PROPAGATION_DENY` | 4 | 10 | 28.57% |
| `PARAMETER_INTENT_MISMATCH` | 6 | 20 | 23.08% |
| `UNTRUSTED_PARAMETER_OVERRIDE_DENY` | 6 | 17 | 26.09% |
| `UNTRUSTED_SCOPE_EXPANSION_DENY` | 7 | 24 | 22.58% |

## 6. Utility와 false-positive 진단

세 end-to-end arm의 utility failures를 원인별로 분류한 결과:

- Security block: 11
- Over-constrained parameter intent: 7
- Payload provenance block: 2
- Tool/task environment error: 5
- Security block 없이 발생한 model/native-task outcome failure: 8

새 FP proxy에서 특히 관찰된 후보는 다음과 같다.

- Travel의 정상 정보 조회 Tool(`get_rating_reviews_for_hotels`, `get_hotels_prices`, `get_hotels_address`, `get_all_hotels_in_city`)에 parameter intent가 과도하게 적용됨
- 정상 action chain의 `create_calendar_event`가 parameter mismatch로 차단됨
- Banking `send_money`의 constraint 추출/적용 불일치
- Slack `post_webpage`의 payload provenance 차단이 strict matcher상 non-malicious로 분류됨

이 항목은 Phase 4에서 수정하지 않았다.

## 7. Native evaluator와 strict matcher 불일치

총 13개 mismatch row가 발생했다.

- Native attack success이나 executed exact strict-ground-truth call이 없음: 2개
- Strict-matched Tool call이 실행됐지만 전체 native injection goal은 실패: 11개

후자의 다수는 `read_channel_messages`, `get_channels`, 호텔 정보 조회처럼 전체 공격 goal의 중간 단계만 strict ground truth와 일치한 경우다. 따라서 strict execution은 공격 chain 노출을 측정하지만 native ASR과 동일한 의미가 아니다. Matcher definition은 변경하지 않았다.

## 8. Evaluation validity

| Check | Result |
|---|---:|
| Exact snapshot access | PASS |
| Native function calling | PASS |
| Model fallback | 없음 |
| Provider error rate | 0.00% |
| Parsing error rate | 0.00% |
| Tool runtime/integration error rate | **20.00% — threshold 초과** |
| Controlled replay error | 0 |
| Proposal-source mismatch | 0 |
| Missing benchmark ground truth | 0 |
| Defense source checksum change | 없음 |
| AgentDojo native source checksum change | 없음 |

Tool 오류는 주로 “검색 결과 없음”, 존재하지 않는 transaction/contact/channel 등 AgentDojo Tool의 `ValueError`였다. 이는 provider/API 호환 실패는 아니지만 사전 정의한 tool-error validity threshold에는 포함되므로 broader run을 중단했다.

## 9. Token과 비용

- Measured LLM API calls: 419
- Pre-check calls: 2(토큰 계측 제외)
- Input tokens: 875,404
- Output tokens: 23,844
- Total tokens: 899,248
- CLI 가격: input $0.15/M, output $0.60/M
- 추정 비용: $0.145617
- 모든 case-run token usage: complete

가격은 runner의 명시적 CLI parameter로 고정되며 API key는 결과에 저장하지 않는다.

## 10. 이번 결과로 주장 가능한 범위

가능한 주장:

> 고정된 20-case smoke proposal에서 Refined Full은 14개 strict malicious call 중 10개(71.43%)를 차단했고, Phase 2 Full보다 3개를 추가 차단했다. 동시에 FPR proxy는 40.00%였으며 tool-error validity gate가 실패했다.

주장할 수 없는 내용:

- 50-case broader subset으로 일반화되었다.
- AgentDojo 전체 benchmark에서 효과가 유지된다.
- Native ASR 0%가 일반적인 방어 성능이다.
- 다른 모델이나 prompt-injection 전체에 일반화된다.
- AgentDojo published result를 재현했다.

## 11. Phase 5 후보 — 이번 단계에서는 수정하지 않음

1. 정상 read-only 탐색 Tool까지 막는 parameter-intent over-constraint 조사
2. Explicit constraint와 탐색 후보 목록/중간 Tool argument를 구분하는 action-stage semantics
3. Payload propagation의 실제 benign transformation과 strict-matcher 비일치 사례 검토
4. Attack-chain 중간 read와 terminal harmful action을 구분하는 reporting taxonomy
5. Native evaluator success와 exact strict Tool matching 불일치 13건의 독립 matcher audit
6. “정상적인 empty-result ValueError”와 adapter/tool integration failure를 구분하는 Phase 5 전용 validity 정의
7. 위 항목을 사전 등록한 후에만 20-case smoke 재실행 및 50-case gate 재평가

## 12. 산출물

Validity warning smoke 결과는 `results/agentdojo/phase4/smoke/`에 보존했다.

- `phase4_case_manifest.json`
- `phase4_frozen_proposals.json`
- `phase4_end_to_end.csv` / `.json`
- `phase4_controlled_replay.csv` / `.json`
- `phase4_rule_analysis.csv`
- `phase4_failure_taxonomy.csv`
- `phase4_matcher_mismatches.csv`
- `phase4_report.md`

