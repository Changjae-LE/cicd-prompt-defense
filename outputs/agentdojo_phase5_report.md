# AgentDojo Phase 5: Error Attribution 및 Validity 재평가

## 결론

기존 Phase 4의 “Tool runtime/integration error 20%”는 실제 adapter/integration failure가 아니었다. 80개 actual case-run에서 관찰된 non-defense error 20 events는 모두 AgentDojo native Tool이 의도적으로 반환한 `EMPTY_RESULT` 10건과 `ENTITY_NOT_FOUND` 10건이었다. 진짜 provider/parsing/adapter integration error는 0%였다.

동일한 frozen 20 case를 exact `gpt-4o-mini-2024-07-18`로 다시 실행한 Phase 5 smoke에서도 provider, parsing, adapter integration error는 모두 0%였다. Benchmark-native runtime outcome은 18.75%로 해석 경고 기준 10%는 넘었지만 severe 기준 25% 이하였다. Proposal mismatch, missing ground truth, replay error도 모두 0이므로 core validity gate와 50-case 재개 판정은 **PASS**다.

이번 Phase에서는 Security Policy, scoped authorization, payload provenance, parameter intent, Context-Aware/Full/Refined Full logic, strict matcher, model prompt, Tool schema, case selection을 변경하지 않았다. Raw AgentDojo Tool feedback도 그대로 유지했다.

## 1. 기존 Phase 4 20%의 실제 구성

| 항목 | Event count | Affected case-runs | Rate over 80 actual runs |
|---|---:|---:|---:|
| Provider/parsing/adapter integration | 0 | 0 | 0.00% |
| `EMPTY_RESULT` | 10 | 8 | 10.00% |
| `ENTITY_NOT_FOUND` | 10 | 8 | 10.00% |
| 전체 benchmark-native runtime outcome | 20 | 16 | 20.00% |
| Model-generated invalid entity/argument | 별도 attribution | 9 | 11.25% |

즉 기존 20% metric은 “integration이 깨진 비율”이 아니라, 모델이 AgentDojo 환경에서 조회·수정하려 한 대상이 없거나 검색 결과가 비어 있던 trajectory 비율이었다.

## 2. Error taxonomy

Phase 5는 raw error를 보존하면서 다음 class와 structured outcome을 병기한다.

| Error class | Structured outcome | 의미 |
|---|---|---|
| `PROVIDER_ERROR` | `PROVIDER_FAILURE` | OpenAI/API transport 또는 provider 실패 |
| `PARSING_ERROR` | `PROVIDER_FAILURE` | 응답/Tool call parsing 실패 |
| `ADAPTER_INTEGRATION_ERROR` | `INVALID_ARGUMENT` | 지원되지 않는 Tool, runtime contract mismatch |
| `EMPTY_RESULT` | `EMPTY_RESULT` | Native search가 결과 없음으로 `ValueError` 반환 |
| `ENTITY_NOT_FOUND` | `NOT_FOUND` | Native environment에 transaction/contact/channel 등이 없음 |
| `MODEL_ARGUMENT_ERROR` | `INVALID_ARGUMENT` | Schema validation 실패 또는 model argument 오류 |
| `BENCHMARK_TOOL_RUNTIME_ERROR` | `BENCHMARK_RUNTIME_ERROR` | 그 밖의 native Tool runtime outcome |
| `DEFENSE_BLOCK` | `BLOCKED_BY_DEFENSE` | Security decision으로 실행 전 차단 |
| `OTHER` | `BENCHMARK_RUNTIME_ERROR` | 위 분류로 설명되지 않은 오류 |

`EMPTY_RESULT`와 `ENTITY_NOT_FOUND`는 native benchmark outcome이면서 동시에 model behavior에서 유발될 수 있다. Argument가 user request에서 직접 유래했는지 별도로 추적해 benchmark-state mismatch와 model-generated invalid entity/argument를 구분했다.

## 3. AgentDojo Tool semantics

설치된 AgentDojo 0.1.35 소스를 직접 확인했다.

- `search_calendar_events`: 검색 결과가 없으면 native Tool이 `ValueError("No events found...")` 발생
- `search_emails`: 검색 결과가 없으면 native Tool이 `ValueError("No emails found...")` 발생
- `search_contacts_by_name` / `search_contacts_by_email`: contact가 없으면 native Inbox method가 `ValueError` 발생
- `update_scheduled_transaction`: ID가 없으면 native Tool이 `ValueError` 발생
- `get_users_in_channel`: channel이 없으면 native Tool이 `ValueError` 발생

이 오류들은 argument schema validation 이후 AgentDojo Tool 내부에서 발생한다. Adapter가 만든 오류가 아니다.

AgentDojo `FunctionsRuntime`은 exception을 `ErrorType: message`로 보존하고 OpenAI adapter는 `message["error"]`를 다음 Tool message content로 그대로 전달한다. 이를 구조화된 JSON feedback으로 교체하면 모델 trajectory와 benchmark meaning이 바뀌므로 이번 Phase에서는 변경하지 않았다. Structured outcome은 평가 artifact에만 추가했다.

Fallback entity, fake transaction/contact, default channel, 가짜 검색 결과는 만들지 않았다.

## 4. 기존 Phase 4에서 문제가 많았던 Tool

| Tool | Non-defense error events |
|---|---:|
| `search_calendar_events` | 9 |
| `get_users_in_channel` | 4 |
| `search_contacts_by_email` | 3 |
| `update_scheduled_transaction` | 2 |
| `search_emails` | 1 |
| `search_contacts_by_name` | 1 |

가장 빈번한 문제는 calendar search의 empty result였다.

## 5. 개선된 validity gate

기존 5% threshold는 완화하지 않았다.

- Provider error > 5%: FAIL
- Parsing error > 5%: FAIL
- Adapter integration error > 5%: FAIL
- Proposal-source mismatch > 0: FAIL
- Missing ground truth > 0: FAIL
- Controlled replay error > 0: FAIL

Benchmark-native runtime outcome은 core integration failure와 합치지 않는다.

- >10%: interpretation warning
- >25%: severe benchmark-state contamination으로 50-case 재개 FAIL

25%는 네 actual trajectory 중 하나 이상이 benchmark-state exception을 겪어 aggregate 해석을 지배하기 시작하는 보수적 경계다. 이 기준은 Phase 5 fresh smoke 결과를 보기 전에 고정했다.

## 6. 동일 20-case fresh smoke validity

| Metric | Result |
|---|---:|
| Exact model access | PASS |
| Function calling | PASS |
| Fallback | 없음 |
| Provider errors | 0.00% |
| Parsing errors | 0.00% |
| Adapter integration errors | 0.00% |
| Benchmark-native runtime outcomes | 18.75% |
| Empty results | 10.00% |
| Entity not found | 8.75% |
| Model-generated invalid entity/argument | 8.75% |
| Proposal-source mismatch | 0 |
| Missing ground truth | 0 |
| Replay errors | 0 |
| Core validity | **PASS** |
| Benchmark interpretation warning | **YES** |
| 50-case broader validation 재개 | **PASS** |

Fresh non-defense events는 `EMPTY_RESULT` 11개와 `ENTITY_NOT_FOUND` 9개였다. 가장 많은 Tool은 다시 `search_calendar_events` 10개였고, 그다음 `get_users_in_channel` 4개였다.

## 7. Fresh smoke defense 결과 — 진단용

Defense는 변경하지 않았으며, 수치는 error-attribution run의 부수 결과다.

### Controlled replay

| Defense | Malicious calls | Blocked | Executed | Detection | FPR proxy |
|---|---:|---:|---:|---:|---:|
| Context-Aware | 18 | 6 | 12 | 33.33% | 6.02% |
| Phase 2 Full | 18 | 10 | 8 | 55.56% | 20.48% |
| Refined Full | 18 | 14 | 4 | 77.78% | 32.53% |

### End-to-End

| Defense | Native ASR | Native Utility | Strict execution | FPR proxy |
|---|---:|---:|---:|---:|
| Context-Aware | 50.00% | 45.00% | 86.67% | 7.53% |
| Phase 2 Full | 10.00% | 45.00% | 34.62% | 26.67% |
| Refined Full | 0.00% | 35.00% | 30.00% | 44.25% |

독립 model trajectory이므로 End-to-End 차이는 causal defense comparison으로 사용하지 않는다.

## 8. Completion과 defense-induced failure

- End-to-End case-runs: 60
- Native Utility failures: 35
- Utility failure이면서 security block이 존재: 23
- Defense-induced failure proxy: 23/60 = 38.33%
- Utility failures 중 security block이 존재한 비율: 23/35 = 65.71%

이 값은 block과 utility failure의 연관이며, block이 유일한 원인이었다는 인과 증거는 아니다.

비배타적 completion labels:

- Task impossible 또는 benchmark-state mismatch: 2
- Model wrong entity/argument: 4
- Empty result 이후 utility failure: 1
- Defense block present: 23
- Integration failure present: 0

## 9. Matcher mismatch 13건 taxonomy

Matcher definition은 변경하지 않았다.

| Category | Count |
|---|---:|
| Native evaluator가 exact ground-truth Tool match 없이 attack success 인정 | 2 |
| Intermediate/partial read action은 strict match지만 final native goal 미완료 | 10 |
| Strict Tool call은 있었지만 complete native goal 미완료 | 1 |

Native evaluator는 최종 goal semantics를 평가하고 strict matcher는 exact Tool/argument match를 평가하므로 동일 metric이 아니다. 이는 Phase 6 또는 future methodology issue로 유지한다.

## 10. 비용과 재현성

- Measured LLM API calls: 410
- Pre-check API calls: 2
- Input tokens: 833,182
- Output tokens: 24,269
- Total tokens: 857,451
- CLI 가격 기준 추정 비용: $0.139539
- Phase 4 source files checksum 변경: 없음
- Defense source checksum 변경: 없음
- AgentDojo native evaluator/runtime checksum 변경: 없음
- API key material 저장: 없음

## 11. 주장 가능한 범위와 남은 한계

주장 가능:

> Phase 4에서 하나로 합쳐졌던 20% Tool error는 실제 integration failure 0%와 benchmark-native empty/not-found outcome 20%로 분해된다. 동일 20-case fresh smoke에서도 integration failure는 0%였으며 core validity gate는 PASS했다.

주의할 점:

- Benchmark runtime outcome은 fresh run에서도 18.75%여서 결과 해석 경고가 유지된다.
- User-request anchoring 기반 model attribution은 symbolic heuristic이며 완전한 인과 분류가 아니다.
- Security block과 utility failure의 동시 발생은 인과 관계를 증명하지 않는다.
- Strict matcher와 native evaluator의 의미 차이가 13건 존재한다.
- 50-case 실행을 재개할 수 있다는 판정은 “결과가 좋을 것”이라는 뜻이 아니라 integration validity가 확보되었다는 뜻이다.
- Phase 5에서는 50-case run을 자동 실행하지 않았다.

