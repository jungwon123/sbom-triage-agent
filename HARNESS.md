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
| 2026-11-18 | P4 | 로컬 판독 모델을 `qwen2.5:14b`로 올려 같은 6건 재측정(`compare --configs local_reader --limit 6`, API 호출 없음) | 6건 모두 유효한 답. API 모델 판독과 일치 7B 3/6 → 14B 4/6. 487초(건당 약 81초), 도구 호출 34회 중 오류 10회. 실행 중 스왑 19GB, 디스크 여유 2GB까지 감소. **표본 6건이라 한 건 차이는 오차 범위** | 노트북에서는 7B 유지, 사내 GPU 서버급 모델 필요를 발표 근거로 사용 |
| 2026-11-18 | P4 | 블라인드 테스트: 별도 세션이 점수 규칙과 기존 라벨을 보지 않고 `fixtures/blind/`에 SBOM 2개(npm CycloneDX 40개, PyPI SPDX 40개)와 정답 47건 작성. 결과를 `out/`에 고정한 뒤 채점. purl 해석을 PyPI, Go, crates.io, NuGet, RubyGems, Packagist로 확대하고 해석 못 한 컴포넌트는 `coverage.unsupported`와 경고로 표시 | pytest 96 통과, `tsc --noEmit` 통과. 수정 전 PyPI 파일은 **0건(조용히 누락)**, 수정 후 193건. 규칙 단독 일치율 npm 9/23, PyPI 5/24, 합계 14/47. NOW 누락 0건. **틀린 33건 전부 과대평가**(MONITOR 정답 20건 중 1건만 맞음). AI 단계는 소스가 없어 미실행. 두 파일의 정답을 모두 열어 봤으므로 이후 조정의 검증에는 새 블라인드 세트가 필요 | SBOM만 있을 때(`unknown`)의 노출 점수와 EPSS 백분위 배점 재검토, 새 블라인드 세트로 확인 |
| 2026-11-18 | P4 | 점수 조정 D38: EPSS는 백분위 0.8 초과분만 반영, 소스가 없어 미판정인 항목의 노출 가중치 0.6 → 0.4. 라벨 67건(블라인드 47, 기존 20)으로 여러 안을 재생해 고름. 라벨이 있는 후보 9건에 API 모델 재실행 | pytest 99 통과. 규칙 단독 일치율 블라인드 14/47 → 30/47(npm 17/23, PyPI 13/24), 기존 라벨 14/20 → 15/20, 규칙+AI 15/20. NOW 누락 0건. 과소평가가 새로 4건 생김(모두 한 단계). 블라인드 NOW 건수 npm 40 → 4, PyPI 65 → 5. **데모 실행(realworld)의 규칙 NOW가 2 → 0, 최종 NOW 1건으로 줄어 시연 재구성 필요.** 조정에 쓴 라벨로 잰 수치라 검증이 아님 | `fixtures/blind2/`로 확인, 데모 실행 전체 후보에 AI 재실행 |
| 2026-11-18 | P4 | D38 검증: 두 번째 블라인드 세트 `fixtures/blind2/`(npm CycloneDX 38개, Maven SPDX 40개, 정답 45건). 점수 조정 뒤에 만들어졌고 결과를 `out/`에 고정한 뒤 채점 | 규칙 단독 일치율 26/45(npm 10/21, Maven 16/24). 같은 자료에서 조정 전 규칙 13/45, CVSS 정렬 18/45. NOW 누락 0건, 과소평가 1건(EPSS가 없는 sharp, NOW → NEXT), 과대평가 18건(두 단계 차이 1건). 정답 작성자가 첫 세트와 같은 AI 세션이라 사람 기준과의 일치는 미확인. AI 단계 미실행 | MONITOR와 NEXT 구분은 취약점 내용을 읽는 AI 단계로 보완 검토, 데모 실행 전체 후보에 AI 재실행 |
| 2026-11-19 | P4 | 기본 모델을 Claude Opus 5.5로 변경(D34). 데모 실행 `realworld`의 후보 30건을 Opus 5.5로 다시 판단. 일부만 다시 돌리는 `agent --retry-failed` 추가, 부분 실행이 저장된 답을 덮어쓰지 않게 수정 | pytest 100 통과. 30건 모두 유효(첫 답 계약 위반 12회, 재시도 후 통과). 최종 NOW 4, NEXT 13, MONITOR 102. NOW 4건(body-parser) 샌드박스 verified. 라벨 10건 일치 8건(규칙 단독 7, CVSS 정렬 7), NOW 누락 0. 오프라인 재생 동일 | 라벨 10건은 표본이 작다. Fable과의 직접 비교는 Fable 판단이 14건에서 끊겨 하지 못함 |
| 2026-11-19 | P4 | D39: SBOM만 있을 때의 AI 판단 단계 추가(`prompts.SBOM_SYSTEM`, 도구 없음, 어드바이저리 본문 근거). 블라인드 4개 파일의 라벨 92건 중 규칙 후보 74건을 Opus 5.5로 판단. 조치 제안 검사가 npm과 Maven 이름만 받던 문제를 고침(PyPI 20건이 전부 규칙 결과로 대체되던 원인) | pytest 106 통과. 일치 56 → 66/92 (세트 1: 30 → 37/47, 세트 2: 26 → 29/45). AI가 고친 것 16건, 맞던 것을 틀리게 한 것 6건. NOW 누락 0건. 호출 132회, 입력 29.6만, 출력 9.7만 토큰 | 세트 2도 완전한 블라인드가 아니다(오답 유형을 알고 지시문을 씀). 과소평가 1 → 4건. 남은 오답 26건 중 18건은 AI가 규칙 결과를 유지한 경우이고 서비스 맥락이 전달되지 않는다. 정답표는 AI 세션이 작성 |
| 2026-11-19 | P4 | D40: 서비스 맥락을 AI 지시문에 전달(`prompts.SERVICE_CONTEXT`, `ServiceContext.note`, `Run.set_context`). 블라인드 4개 실행에 README의 서비스 설명을 맥락으로 넣고 라벨 후보 74건 재판단. 근거 문장 숫자 검사를 완화: log4j, SHA256처럼 이름 안의 숫자는 통과, 단독 숫자와 버전은 계속 거부 | pytest 110 통과. 일치 63/92 (세트 1: 33/47, 세트 2: 30/45). 맥락 없는 D39 실행은 66/92. AI가 고친 것 16건, 틀리게 한 것 9건, 과소평가 6건, NOW 누락 0건. 규칙 대체 3건(log4j-core 등, 숫자 검사에 걸림) | 맥락 전달의 효과는 확인되지 않았다. 구성당 1회 실행이라 차이 3건이 실행 간 편차인지 알 수 없다. 숫자 검사 완화 뒤의 재실행은 하지 않았다. `out/`의 블라인드 실행은 맥락을 넣은 결과로 남아 있다 |
| 2026-11-19 | P4 | D41: 수정안과 승인 흐름. 샌드박스 사본에서 package.json과 lockfile의 diff를 떠서 `verify/*.patch`로 저장, `decide.py`(수정안 목록, 결정 기록, 내보내기), API 4개(`proposals`, `patch`, `decisions`, `export`), CLI `decide`와 `export`, `verify --buckets`, 화면의 수정안 diff와 담당자 결정 영역 | pytest 118 통과, `tsc --noEmit` 통과. 데모 실행 재검증: body-parser 1.20.1과 1.20.2 모두 verified, 패치 2개(lockfile 405줄 변경), 두 패치 모두 데모 레포에 `git apply --check` 통과. 실행 사본에서 화면으로 승인 1건과 내보내기까지 확인 | 로그인이 없어 결정자 이름은 입력값 그대로다. 패치는 건별로 원본 기준이라 여러 건을 합친 상태는 검증하지 않는다. 같은 패키지의 두 버전(직접 1.20.2, express 경유 1.20.1)이 별개 수정안으로 나온다. diff는 npm만 지원 |
| 2026-11-19 | P4 | D42: 승인분 결합 검증과 단일 패치(`verify_run.verify_together`, `decide.export(together=True)`, `CombinedCheck`, CLI `export --together`, API `export?together=true`, 화면 버튼). 판정 보강: 테스트 실행 수가 기준선보다 줄면 `inconclusive` | pytest 122 통과(샌드박스 테스트 3건은 Docker 무응답으로 건너뜀), `tsc --noEmit`과 빌드 통과. 결합 명령의 순서와 대체 경로는 가짜 샌드박스로 확인 | 가짜 샌드박스 확인만으로는 아래 행의 결함을 잡지 못했다 |
| 2026-11-19 | P4 | D42 실제 확인: qwen2.5:14b 삭제(디스크 여유 1GB → 10GB), Docker Desktop 재시작. 데모 실행 사본에서 body-parser 1.20.2(직접)와 1.20.1(express 경유)을 승인하고 함께 검증. 첫 실행은 `failed (target_remains)`: 건별 명령을 이어 붙이면 express 쪽 1.20.1이 남았다. 같은 패키지를 `"body-parser": "$body-parser"` override 하나로 처리하도록 수정 | 수정 후 `verified`: 대상 취약점 6건 중 남은 것 0, 새 취약점 0, 테스트 27개 실행(조치 전과 같은 실패만), lockfile 442줄 변경. `combined.patch`가 데모 레포에 `git apply --check` 통과. 화면의 함께 검증 버튼에서도 같은 결과. pytest 123 통과 | 서로 다른 패키지 여러 건을 합치는 경우는 실제 샌드박스에서 돌려 보지 않았다(승인 대상이 body-parser뿐). API의 함께 검증은 요청이 1분가량 붙잡혀 있다 |
| 2026-11-19 | P4 | D43: 작업 큐(`jobs.py`, `Job` 모델). 함께 검증을 `POST /export/together`(202) + `GET /jobs/{id}`, `GET /jobs/latest`로 전환하고 화면은 상태를 2초마다 확인. 건별 내보내기는 즉시 응답 그대로 | pytest 130 통과, `tsc --noEmit`과 빌드 통과. 실제 샌드박스로 브라우저 확인: 버튼을 누르면 진행 문구가 뜨고, 도중에 새로 고쳐도 이어지며, 약 1분 뒤 "함께 적용한 결과: 검증 통과" 표시. 큐 테스트: 순차 실행, 중복 요청 병합, 실패 후 작업자 생존, 서버 재시작 시 `interrupted` | 큐가 프로세스 안에 있어 서버 재시작 시 대기 작업이 사라진다. `uvicorn --workers`를 2 이상으로 띄우면 프로세스마다 큐가 따로 생겨 동시 실행 제한이 깨진다. 작업 취소 기능은 없다 |
| 2026-11-19 | P4 | D44: 설계 비판 보고서의 수정 반영(버킷 하한, EPSS 하향 차단, 조치 버전 상한, 로그와 자격 증명 파일 유출 경로 차단, KEV와 EPSS 캐시 만료, SPDX와 버전 비교 수정, `rescore` 명령, 화면의 KEV 목록 판과 미조회 경고). 저장된 실행 5개를 `rescore`로 현재 규칙에 맞춤 | pytest 146 통과, `tsc --noEmit`과 빌드 통과. 규칙 버킷 변화는 전체 저장 실행에서 2건(NodeGoat의 악성 패키지 fsevents와 블라인드 D의 KEV 항목 tomcat-embed-core가 NEXT → NOW). 데모 실행은 변화 없음(NOW 4, NEXT 13, MONITOR 102, verified 유지). KEV 캐시가 2026.10.30판에서 2026.11.18판(1,786건)으로 갱신됐고 저장된 발견 중 새로 KEV가 된 것은 없음. 블라인드 92건: 규칙 단독 56 그대로, 규칙+AI 63 → 61, 과소평가 6 → 3건, NOW 누락 0. 조치 버전 상한에 걸린 기존 답은 0건 | 일치 건수는 2건 줄었다. EPSS 차단이 정답 MONITOR인 항목의 하향도 막기 때문이며, 과소평가를 줄이는 쪽을 택한 결과다. 블라인드 A의 화면 NOW가 38건에서 8건으로 바뀐 것은 옛 규칙 버킷이 섞여 있던 것을 바로잡은 것이다 |
| 2026-11-19 | P5 | D45: 저장 계층 분리와 PostgreSQL. `store/`(인터페이스, 파일, PostgreSQL, 스키마, 가져오기), `deploy/docker-compose.yml`, CLI `db init`, `db import`, `db status`, API `GET /api/search`와 `GET /api/health`, `doctor`의 저장소 점검. `runner.Run`, `decide`, `cache`, `api`가 저장 계층을 거치도록 변경 | pytest 158 통과(같은 계약 테스트를 파일과 실제 PostgreSQL 16 양쪽에서 실행). 저장된 실행 24개(Finding 2,953건, 이벤트 682건)와 캐시 1,258건을 DB로 가져옴. PostgreSQL 모드 API에서 실행 목록, 상세, 수정안, 패키지와 취약점 검색 확인. 결정 1건을 API로 기록해 DB 행 생성과 파일 미생성을 확인한 뒤 삭제 | 처음 구현은 쓰기가 커밋되지 않았다(psycopg의 암묵적 트랜잭션 안에서 `transaction()`이 savepoint가 됨). 같은 연결로 읽는 테스트는 통과해서 `db status`로 발견했고, autocommit 연결로 고친 뒤 다른 연결에서 확인하는 테스트를 추가했다. 작업 큐, 인증, 산출물 저장소 분리는 아직이다. 스키마 변경 이력 관리 도구는 없다 |
| 2026-11-20 | P5 | D46: DB 기반 작업 큐와 별도 작업자. 저장 계층에 작업 메서드 8개(추가, 조회, 최신, 가져가기, 갱신, 목록, 작업자 생존 기록과 조회), 스키마 2판(`jobs`, `workers`), `jobs.py` 재작성, CLI `worker`(`--once`, `--poll`), `GET /api/health`의 큐 상태, `Job` 모델과 `types.ts` 갱신, 화면의 "작업자 없음" 안내. 샌드박스 단계가 시간 초과하면 컨테이너를 종료하도록 수정 | pytest 170 통과(큐 테스트를 파일과 실제 PostgreSQL 양쪽에서 실행: 순서, 중복 요청 병합, 작업자 4개가 12건을 겹치지 않고 처리, 죽은 작업자의 작업 재시도와 `interrupted`, 뒤늦은 결과 거부, 긴 작업의 생존 신호). 실제 확인: PostgreSQL 모드 API(8001)와 작업자를 다른 프로세스로 실행. 작업자 없이 요청하면 `queued`와 작업자 없음 표시. 작업자 1이 샌드박스 실행 중일 때 `kill -9` → 30초 뒤 대기열 복귀 → 작업자 2가 이어받아 `attempts=2`, 검증 통과(대상 취약점 0건 남음, 테스트 27개), 패치 하나 생성. `SIGTERM`으로 작업자 정상 종료. 확인에 쓴 임시 실행은 삭제 | 시간 초과 테스트(`test_sandbox.py`)가 돌 때마다 10분짜리 컨테이너가 남던 것을 이번에 발견했다(클라이언트만 종료되고 컨테이너는 계속 실행). 스레드별 DB 연결이 테스트 스키마를 따르지 않아 저장소에 `schema` 옵션을 추가했다. 남은 한계: 작업자가 강제 종료되면 그 샌드박스 컨테이너는 단계가 끝날 때까지 남는다. 작업 취소 기능은 없다. 작업 종류는 함께 검증 하나뿐이고 스캔과 AI 판단은 아직 명령줄에서만 시작한다. 작업자 컨테이너 이미지와 배포 구성은 없다 |
| 2026-11-22 | P5 | D47: 로그인(OIDC)과 역할. `auth.py`(설정, 서명 쿠키, 인증 서버 조회, ID 토큰 검증, 역할 매핑, FastAPI 의존성, `/auth/login`, `/auth/callback`, `/auth/logout`, `/api/me`), API 경로 13곳에 역할 검사, `Decision.by_id`와 `Me` 모델, `doctor`의 `TRIAGE_AUTH` 점검, 화면의 로그인 화면과 계정 표시와 권한별 안내, `check.sh`의 규칙 6과 11 점검 | pytest 203 통과(인증 33건: 세션 없이 읽기 거부, 열람 역할의 결정과 내보내기 거부, 세션의 이름으로 결정 기록, 잘못된 ID 토큰 10종 거부(다른 키, 다른 대상, 다른 발급자, 만료, nonce 불일치, HS256 혼동, 서명 없음 등), state 불일치, 쿠키 위조와 만료, 다른 사이트의 쓰기, 외부로 나가는 `next`, 키 교체, 설정 누락 시 기동 거부). `tsc --noEmit`과 빌드 통과. 실제 확인: 로컬 가짜 인증 서버와 파일 모드 API를 따로 띄워 브라우저로 로그인. 열람 계정은 화면이 보이고 결정 요청은 403, 그룹 없는 계정은 세션 없이 안내 문구, 승인 계정은 화면에서 승인해 `by`와 `by_id`가 세션 값으로 기록됨. 확인에 쓴 임시 실행은 삭제 | 실제 사내 인증 서버나 Keycloak, Okta 같은 제품으로는 확인하지 않았다(가짜 인증 서버만). 세션을 만료 전에 서버에서 끊을 수 없고 역할 변경은 다음 로그인부터 반영된다. 인증 서버 쪽 로그아웃(RP-initiated logout)은 하지 않는다. 관리 역할로 막는 기능은 아직 없다. 명령줄(`triage decide --by`)은 로그인과 무관하게 이름을 직접 받는다. 서비스별 접근 제한(누가 어느 서비스를 보는지)은 없다 |
| 2026-11-23 | P5 | D48: 서비스 등록과 자동 재분류. `services.py`(등록, 경로 검사, 변경 비교, 다시 확인, 주기, 알림 판단), 저장 계층의 서비스 메서드 5개와 스키마 3판(`services`), `runner.scan`을 수집(`collect`)과 기록(`record`)으로 분리, 작업 종류 `service_check`와 작업자의 주기 확인, `notify.build_change_message`, CLI `services add/list/check/remove`와 `agent --changed`, API `GET/POST /api/services`, `DELETE /api/services/{id}`, `POST /api/services/{id}/check`, 화면의 서비스 탭과 실행 화면의 변경 목록 | pytest 223 통과(서비스 20건, 파일과 실제 PostgreSQL 양쪽: 첫 확인은 실행 생성, 변화 없으면 실행 미생성, 변화가 있으면 새 실행과 AI 판단 재사용, 스캔 실패 시 현재 실행 유지, 주기가 지난 서비스는 한 번만 대기열에, 허용 위치 밖 경로와 심볼릭 링크 거부, 등록은 관리 역할, 다시 확인은 승인 역할). `tsc --noEmit`과 빌드 통과. 실제 확인: 데모 실행에서 NOW 1건을 뺀 임시 사본을 현재 실행으로 등록하고 리플레이 모드 API(8002)의 화면에서 다시 확인 → 새로 발견 1건, AI 판단 29건 재사용, 새 실행 생성. 명령줄로 한 번 더 확인하면 변화 없음 | 실제 데이터 변화(KEV 신규 등재, 새 권고)로는 확인하지 않았다(기준 실행을 고쳐서 만든 변화만). Slack 전송은 실제로 보내 보지 않았다. 규칙만으로 NOW가 되는 경우가 드물어 알림 기준에 NEXT 신규를 넣었다. 새 실행에는 검증과 승인 기록이 없어 다시 해야 한다. 2단계 모드에서 가져온 판단의 도달성은 작성 모델의 답을 따른다(`rescore`와 같음). 원격 저장소 받아 오기, 서비스 수정 명령, 작업자가 다른 호스트일 때의 경로 일치 확인, 확인 이력(마지막 결과만 보관)은 없다. 확인에 쓴 임시 실행 3개와 `out/svc-scratch-demo`는 삭제 권한이 거부되어 남아 있다 |
| 2026-11-23 | P5 | D49: 본선 자료 형식 대비와 Codex 준비. `ingest.py`(판별, lock 파일 파서, 스캐너 결과, CycloneDX XML, SPDX tag-value, 표와 JSON 목록, 폴더 조사), `Component.reported`와 CycloneDX `vulnerabilities` 절 왕복, `scan.py`가 입력이 보고한 취약점을 유지하고 OSV 없이도 진행, CLI `inspect`, `seed`, `scan --columns --ecosystem`, EPSS 파일 대체 조회, `AGENTS.md` 재작성, 키트(`START`, `PLAYBOOK`, `prompts`, `adapt-input`, `data-check`, `profile_input.py`, `check.sh`) 갱신 | pytest 239 통과(입력 16건: 형식별 축약 샘플, 한글 열 이름과 CP949 CSV, 열 지정, 읽지 못하는 입력의 안내 문장, 모노레포 합치기, 보고된 취약점의 왕복, OSV 불통 시 진행, OSV와 중복 제거, EPSS 파일, 표 한 장이 실행 기록까지). `tsc --noEmit`과 빌드 통과. `triage inspect fixtures`로 기존 SBOM 4개와 저장소 4개 판별 확인 | 샘플은 각 도구의 문서 형식을 줄여 직접 만든 것이고 실제 도구가 낸 파일로는 확인하지 않았다(도구 버전에 따라 키가 다를 수 있다). 새로 읽는 입력으로 실제 스캔(OSV 조회 포함)을 돌려 보지 않았다. 화면은 `coverage.input_notes`를 아직 보여 주지 않는다. Codex에서 실제로 세션을 열어 `AGENTS.md`대로 움직이는지 확인하지 않았다 |
