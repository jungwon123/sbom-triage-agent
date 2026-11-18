# HARNESS.md — 작업 진행 방식

> CLAUDE.md가 "무엇·규칙"이라면, 이 파일은 "어떤 순서로, 무엇을 확인하고 다음으로 넘어가는가"다.
> AI 에이전트(Claude Code 등)와 사람 모두 이 순서를 따른다.

## 1. 작업 루프 (모든 태스크 공통)

```
1. READ    : CLAUDE.md 절대 규칙 + 해당 Phase의 입력·게이트 확인
2. PLAN    : 바꿀 파일과 완료 기준을 3줄 이내로 적는다
3. BUILD   : 한 번에 파이프라인 한 단계만 수정
4. VERIFY  : 해당 Phase의 게이트 명령을 실제로 실행
5. RECORD  : 아래 7장 진행 로그에 한 줄 기록 (무엇 / 게이트 결과 / 다음)
```

게이트가 실패하면 다음 Phase로 가지 않는다. 같은 게이트에서 2번 연속 실패하면 범위를 줄이는 쪽으로 사람에게 확인한다.

## 2. Phase 구성

| Phase | 내용 | 입력 | 산출물 | 게이트 (통과 조건) |
|---|---|---|---|---|
| P0 Setup | 레포 뼈대, `.env`, 데모 레포 확정 | REQUIREMENTS | 디렉터리 구조, `models.py` | `uv run pytest -q` 통과(빈 테스트), 데모 레포에서 Syft 실행 성공 |
| P1 Pipeline | ① SBOM ② 스캔 ③ 보강 | 데모 레포 | `findings.json` | `scan.py`가 SBOM만 입력으로 동작 · 모든 Finding이 스키마 검증 통과 · EPSS/KEV/bump 채워진 비율 출력 · 캐시만으로 재실행 성공 |
| P2 Rules | ④ 규칙 점수 + golden 라벨링 | findings | `triage.json`(rule만), `golden.yaml` | `score.py` 단위 테스트 통과 · `triage eval`로 CVSS 정렬과 규칙 단독의 일치율, NOW 누락 측정됨 |
| P3 Agent | ⑤ 도달성·근거·조치안 | triage(rule) | `triage.json`(final), `agent_log.jsonl` | 스키마 100% 통과 · ±1 제약 위반 0 · 근거 수치 검증 통과 · 일치율 ≥ 규칙 단독 · NOW 누락 0건 또는 원인 기록 · 안전장치 위반 0 |
| P3.5 Verify | ⑥ 샌드박스 검증 | triage(final) | `verify/<finding_id>/`, `Verification` | 데모 레포 NOW 항목 전부 `verdict` 산출 · 컨테이너가 원본 레포를 변경하지 않음(테스트로 확인) · 시간 상한 초과 시 `inconclusive`로 종료 |
| P4 Dashboard | ⑦ P0 화면 | triage.json | `web/` | `tsc --noEmit` 통과 · 데모 시나리오 1~4 화면 수동 확인 |
| P5 Demo | 리플레이 모드, 리허설 | 전체 | 발표 자료 | 네트워크와 Docker를 끈 상태에서 시나리오 전체 3분 내 완주 2회 |

## 3. 검증 장치 (Guardrails as tests)

| 검증 | 위치 | 잡아내는 것 |
|---|---|---|
| 스키마 검증 | `tests/test_models.py` | 필드 누락·타입 오류 |
| 점수 결정성 | `tests/test_score.py` | 같은 입력 → 같은 점수, 경계값(60/30) |
| 버킷 조정 제약 | `tests/test_agent_contract.py` | NOW↔MONITOR 직행, `override_reason` 누락, KEV 하향, `needs_review` 대상의 자동 하향 |
| 근거 사실성 | `tests/test_agent_contract.py` | rationale 속 숫자가 Finding 값과 불일치 |
| 도구 샌드박스 | `tests/test_tools.py` | 레포 밖 경로 접근, `..` 경로, 심볼릭 링크 탈출 |
| 조치 제안 검증 | `tests/test_apply.py` | 패키지명 불일치, `fixed_in` 미만 버전, 셸 메타문자가 든 `to_version` |
| 검증 판정 | `tests/test_verdict.py` | 기준선 대비 회귀, 비교 불가, `mitigation_only`의 verdict 규칙 |
| 도달성 변이 | `poc/mutation_test.py` 이식 | 주석, 문자열 오탐과 사용 추가, 제거, 테스트 이동 판정 |
| 컨테이너 격리 | `tests/test_sandbox.py` | 원본 레포 불변, 타임아웃 동작, 네트워크 차단 단계에서 외부 호출 실패 |
| 골든 일치율 | `triage eval` | CVSS 정렬/규칙/에이전트의 버킷 일치율 회귀, NOW 누락 |

에이전트 출력은 사람이 "괜찮아 보인다"로 통과시키지 않는다. 위 테스트가 통과해야 통과다.

## 4. 에이전트 실행 설계 (P3 상세)

```
for finding in candidates(rule_bucket in {NOW, NEXT}):
    context = get_finding(finding)                 # 결정론적 데이터
    loop (최대 6 tool calls):
        search_usages / read_file / get_advisory   # 필요할 때만
    output = AgentVerdict JSON  ──► Pydantic 검증
        ├─ 실패 → 오류 메시지 붙여 1회 재시도
        └─ 재실패 → rule 결과 그대로 + reachability="unknown"
    contract check (±1, override_reason, 수치 일치, 조치 제안 검증, 하향 안전장치)
        └─ 위반 → rule 결과로 fallback + agent_log에 기록
    triage = merge(rule_result, verdict)           # Triage는 코드가 조립
```

- MONITOR 후보는 에이전트를 호출하지 않는다 (비용·시간). 단, `reachability=unknown`으로 표시.
- 시스템 프롬프트에는 점수 규칙 요약과 ±1 제약을 넣고, "모르면 unknown"을 명시한다.
- 모든 tool call과 응답은 `agent_log.jsonl`에 남겨 발표 때 "에이전트가 어떻게 판단했는지" 보여줄 수 있게 한다.

**검증 루프 (P3.5, `runner.py`가 실행)**

```
baseline = sandbox.baseline(repo)                  # run당 1회, 조치 전 상태
for t in final_triage where final_bucket == NOW:
    attempt = 1
    loop:
        v = sandbox.verify(t.remediation, baseline)
        if v.verdict != "failed" or attempt == 3: break
        proposal = agent.revise(t, failure=v.steps)   # 실패 로그 전달 (F8-5)
        t.remediation = apply.build(proposal)         # 같은 조치 제안 검증을 다시 통과
        attempt += 1
    t.verification = v
```

## 5. 시간 박스 & 컷 규칙

| 체크포인트 | 이때까지 안 됐으면 |
|---|---|
| D1 13:00 — P1 게이트 | Syft 포기, lockfile 파싱만 사용 |
| D1 19:00 — P2 게이트 | golden set을 데모 레포 10건으로 축소, 평가 레포는 라벨링 없이 분포만 보고 |
| D2 12:00 — P3 게이트 | 도달성 판정을 import 검색 결과로 대체, 에이전트는 근거·조치안만 |
| D2 14:00 — P3.5 게이트 | F8-5 재시도를 1회로 축소, 검증은 install + rescan만 |
| D2 16:00 — P4 게이트 | 상세 패널 단순화, 토글(F7-4)만은 유지 |
| D2 18:00 | 기능 동결. 이후는 리플레이·리허설만 |

컷 순서: F7-5 → F6-6 → F4-6 → F7-9 → F1-6 → F4-5 → F1-3. **P0 요구사항은 자르지 않는다.** 단, 위 P3.5 체크포인트의 축소는 시간 초과 시의 예외로 허용한다.

## 6. 세션 시작 / 종료 체크리스트

**시작할 때**
- [ ] 7장 진행 로그의 마지막 줄 확인 → 현재 Phase와 다음 할 일
- [ ] `uv run pytest -q` 현재 상태 확인

**끝낼 때**
- [ ] 게이트 명령 실행 결과를 로그에 기록
- [ ] 스키마를 바꿨다면 `web/src/lib/types.ts` 동기화 확인 (`scripts/gen_types.py --check`)
- [ ] 미해결 이슈는 REQUIREMENTS 13장 "열린 질문"에 추가

## 7. 진행 로그

| 시각 | Phase | 한 일 | 게이트 | 다음 |
|---|---|---|---|---|
| 2026-10-31 | P0 | 요구사항·하네스 초안 작성 | — | 데모 레포 확정, 열린 질문 정리 |
| 2026-10-31 | P0 | 샌드박스 결정 반영, 설계 변경 4건·과제 대조 보완 3건 반영, REQUIREMENTS v0.2 | 문서 일관성 확인 | 데모 레포 확정(T3) |
| 2026-10-31 | P0 | 데모 레포 realworld 확정, 커밋 고정, 보완 3건 반영 | 정적 스캔으로 A·B·C 후보 확인, 컨테이너 검증 미실행 | T4 Setup, T5 실측 |
| 2026-10-31 | P0 | 차별화 보강 3건 반영: 실측 비교, 하향 안전장치, 서비스 영향 조회 | 문서 일관성 확인 | T4 Setup, T5 실측 |
| 2026-10-31 | P0 | 규칙·샌드박스 PoC 실측 (`docs/poc-results.md`) | 대비 사례 확인, LLM·golden 미측정 | T4 Setup |
| 2026-10-31 | P0 | 시나리오 1·2 실측: NOW 30패키지 검증, 변이 36건 (`docs/poc-results.md`) | verified 20/30, 실제 테스트 확인 2건 | 키 확보, 라벨링 |
| 2026-11-01 | P0 | 대시보드 React(Vite) 전환, 저장소 결정(D31, D32), 아키텍처 재생성 | finalize 통과 | 키 확보, 라벨링 |
| 2026-11-01 | P0 | 운영 PoC 2종 측정, 키워드와 학습 자료 문서 추가, D33 (`docs/poc-results.md`) | 동시 4개에서 처리량 최고, 큐 유실 0, LLM 병목 미측정 | 키 확보, 라벨링 |
| 2026-11-18 | P1~P3.5 | `backend/triage/` 구현: SBOM(Syft, lockfile, SBOM 파일, Maven pom), 스캔·보강, 규칙 점수, 에이전트(Anthropic·OpenAI·replay 어댑터), 샌드박스 검증, eval, doctor, API. 기본 모델 Fable 5.2 (D34) | pytest 80 통과(Docker 격리 포함). 3개 레포 리플레이 결과가 PoC와 일치(2,665 / 581 / 332 / NOW 41). 데모 레포 NOW 2건 verified, tests_run 27. **LLM 실호출 미검증(키 없음)**, golden 라벨 0건 | `.env`에 키 입력 후 `triage doctor --llm`, `triage agent`; 라벨링; `web/` 대시보드(P4) |
| 2026-11-18 | P4 | `web/` 대시보드(요약, 분포 띠, 정렬 토글, 목록, 상세, 검증 결과), `scripts/gen_types.py`, 본선용 하네스 키트 `kit/` | `tsc --noEmit` 통과, `pnpm build` 성공, 브라우저에서 데모 실행 화면 확인(데스크톱, 모바일). LLM 실호출은 여전히 미검증 | 키 입력 후 에이전트 실행, 라벨링, 시나리오와 리허설(P5) |
| 2026-11-18 | P3 | 로컬 LLM 어댑터(`llm_local.py`), 2단계 분리(코드 판독은 사내 모델, 작성은 외부 모델), `triage compare`, D35 | pytest 83 통과(Docker 테스트 제외, Docker 데몬 무응답). 작성 모델에 코드와 파일 이름이 가지 않음을 테스트로 확인. **로컬과 API 모두 실호출 미검증**, 라벨 0건 | 디스크 확보 후 Ollama 설치, 키 입력, 라벨링, `triage compare` |
| 2026-11-18 | P3 | Ollama `qwen2.5:7b`로 로컬 어댑터 실호출, 도구가 있을 때 JSON 강제를 끄는 수정, 판독 모델이 파일을 안 열면 답을 버리는 검사, Slack 알림(D36), `docs/onprem-llm.md` | pytest 86 통과(Docker 테스트 제외). 로컬 판독 6/6 유효, 도구 호출 21회. **API 모델은 `.env`가 없어 미실행**, 분리 구성 미실행, 라벨 0건, Slack 실제 전송 미검증 | `.env` 생성과 키 입력, Docker 재시작, 라벨링, `triage compare` 전체 구성 |
| 2026-11-18 | P3 | API 모델(Claude Fable 5.2) 첫 실호출, API 단독과 분리 구성 실행, 데모 실행에 API 결과 반영, 구성별 비교 기록(`docs/onprem-llm.md`) | API 단독 6/6 유효, 계약 위반 0, 등급 조정 3건(form-data NOW→NEXT 포함). 분리 6/6 유효. 판독 결과는 6건 중 4건이 API와 다름. 정확도는 라벨이 없어 미측정, 87건 중 6건만 실행 | 라벨링, 전체 실행 여부 결정(비용), Docker 재시작 후 새 NOW 검증 |
| 2026-11-18 | P4 | 정답 라벨 20건 첫 측정, 라벨을 레포별로만 적용하도록 `eval.load_golden` 수정(다른 레포의 같은 패키지에 라벨이 섞이던 문제) | pytest 87 통과(Docker 테스트 제외). 일치율 CVSS 정렬 9/20(45%), 규칙 8/20(40%), 규칙+AI 8/20(40%), NOW 누락 3건. 라벨 20건 중 AI가 판단한 항목은 2건뿐이고 확신도와 메모가 비어 있어 라벨 재확인 전에는 결론을 내지 않음 | 라벨 재확인, 라벨 대상 20건에 AI 판단 실행 |
| 2026-11-18 | P4 | 데이터와 방향이 어긋난 라벨 8건을 사용자 요청으로 AI가 다시 매김(메모에 "AI 재검토" 표기, 나머지 12건은 사람 라벨) | 일치율 세 방식 모두 14/20(70%), NOW 누락 0건. 8건은 도구 결과를 본 AI가 매겼으므로 독립된 정답이 아님. 발표 수치로 쓸 때는 사람 라벨 12건과 구분해 표기 | 라벨 대상 20건에 AI 판단 실행 |
| 2026-11-18 | P4 | Docker 재시작 후 샌드박스 테스트와 데모 실행의 NOW 3건 검증 | `tests/test_sandbox.py` 3개 통과. body-parser 3건(직접 2건은 1.20.9로 upgrade, 간접 1건은 overrides)과 form-data 모두 verified, 실행된 테스트 27개, 회귀 0건, 원본 레포 변경 0건. 테스트 단계는 조치 전에도 실패하던 테스트 때문에 failed로 표시되지만 기준선과 비교해 새로 깨진 테스트가 없어 verified | 라벨 대상 20건에 AI 판단 실행 |
| 2026-11-18 | P4 | `triage agent --labeled` 추가(라벨이 있는 후보만 판단, 나머지는 이전 판단 유지), 세 레포의 라벨 대상 중 규칙 후보 14건에 API 모델 실행 | pytest 87 통과(Docker 테스트 제외). 14건 모두 유효한 답, 계약 위반 3건(재시도로 해결). 일치율 CVSS 정렬 14/20, 규칙 14/20, 규칙+AI 12/20, NOW 누락 0건. 사람 라벨 12건만 보면 8, 7, 4. AI가 틀린 8건 중 6건은 라벨보다 낮게 본 경우이고 그중 2건은 EPSS 상위 10% 안의 NOW를 NEXT로 내림(minimist, systeminformation). `override_reason`에 자리표시자 `{package}`가 채워지지 않은 사례 1건 | 하향 안전장치 기준 논의(F6-9), override_reason 자리표시자 처리 |
| 2026-11-18 | P4 | 하향 안전장치 확대(D37, F6-9 개정): EPSS 상위 10%이고 규칙이 NOW이면 하향 보류. 조정 사유의 자리표시자도 채움 | pytest 90 통과(Docker 테스트 제외). 저장된 AI 답변을 리플레이로 다시 적용(API 호출 없음). 일치율 규칙+AI 12/20 → 14/20, 사람 라벨 12건 기준 4 → 6. 보류 2건(minimist, systeminformation)은 "담당자 확인 필요"로 표시. 기준을 같은 20건에서 정했으므로 이 수치는 검증이 아니라 조정 결과 | 새 라벨 자료로 재측정 |
