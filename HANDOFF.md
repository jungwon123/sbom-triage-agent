# HANDOFF.md — Claude Code 인수인계 문서

> 작성일: 2026-10-31 (claude.ai 대화 → Claude Code 인계)
> 대상: 이 레포에서 작업을 이어받는 Claude Code 세션
> 사용자: 정원 (프론트엔드 개발자, React·Next.js·TypeScript 주력, 백엔드·에이전트 설계에도 관심)

---

## 0. 이 문서를 읽는 법

1. **이 문서 전체를 먼저 읽는다.** 이전 대화에서 내린 결정, 아직 문서에 반영되지 않은 결정, 막힌 작업이 모두 여기 있다.
2. 그다음 `CLAUDE.md`(규칙) → `HARNESS.md`(진행 방식) → `docs/REQUIREMENTS.md`(요구사항) 순으로 읽는다.
3. 5장의 변경사항은 T1에서 `REQUIREMENTS.md`(v0.2)·`HARNESS.md`·`CLAUDE.md`에 반영되었다.
4. 문서 간 충돌 시 우선순위: REQUIREMENTS > CLAUDE > HARNESS. 이 HANDOFF는 배경과 결정 이력이다.

---

## 1. 배경

### 1.1 대회와 과제

- **대회:** 롯데 AX 해커톤 (사용자는 별도로 SK하이닉스 AI 활용 역량 평가도 준비 중이며, 이 레포와는 무관)
- **선택 과제 (원문):**
  > 롯데이노베이트 [인프라] SW 공급망 스캐닝 AI 에이전트 기획
  > - SBOM 생성과 취약점 스캔 결과의 영향도·우선순위 연결 구조 설계
  > - AI 에이전트 기반 조치안 도출 및 개선
- **다른 후보였던 과제 (참고용):** 롯데칠성음료(AI 페르소나 시장검증, 2순위였음), 롯데웰푸드(K-푸드 수출국), 롯데홈쇼핑(프로모션 시뮬레이터), 롯데케미칼(수요예측), 롯데호텔(고객 데이터 통합), 한국후지필름(설문 에이전트)

### 1.2 이 과제를 고른 이유 (발표·지원서 논리에 그대로 쓰임)

- 개발자가 "현업 당사자"인 유일한 과제 — npm 의존성 문제를 직접 겪는 사람이 만드는 도구
- 공개 도구·공개 DB(Syft, OSV, EPSS, CISA KEV)만으로 **실데이터 기반 작동 프로토타입**이 가능
- 차별화가 명확: CVSS 목록이 아니라 **악용 가능성 + 실제 사용 여부 + 조치 비용**을 결합한 판단

### 1.3 제약 조건 (확정)

| 항목 | 값 |
|---|---|
| 산출물 | **작동 프로토타입 + 발표** |
| 기간·인원 | **1~2일, 1인** |
| 스택 | **Python(파이프라인·에이전트·API) + Next.js(대시보드)** |
| 하네스 | 사용자가 설계한 **CLAUDE.md + HARNESS.md 구조** 적용 |
| 대상 생태계 | npm 하나로 한정 |

### 1.4 사용자 작업 스타일

- 한국어로 소통한다. 코드 주석·커밋 메시지는 영어/한국어 무관하나, **사용자에게 하는 설명은 한국어**.
- 사용자는 **개념을 공부하면서** 진행하길 원한다. 보안 개념(EPSS, reachability, egress 등)을 처음 코드에 도입할 때는 작업 요약에 1~2줄로 "이게 뭐고 왜 필요한지"를 붙인다. 장황한 강의는 하지 않는다.
- 결정이 필요한 지점은 임의로 정하지 말고 묻는다(10장 열린 질문 참고). 단, 되돌리기 쉬운 구현 세부는 합리적으로 정하고 알린다.

---

## 2. 결정 로그

| # | 결정 | 상태 | 근거 / 비고 |
|---|---|---|---|
| D1 | 롯데이노베이트 SBOM 과제 선택 | 확정 | 1.2 |
| D2 | 산출물 = 작동 프로토타입 + 발표, 1~2일, 1인 | 확정 | 사용자 답변 |
| D3 | 스택 = Python + Next.js | 확정 | 사용자 답변 |
| D4 | 하네스 = CLAUDE.md + HARNESS.md | 확정 | 사용자 답변 |
| D5 | **하이브리드 판단 구조**: 수치 판단(심각도·악용 신호·조치 비용)은 규칙, 맥락 해석(도달성·근거·조치안)은 에이전트 | 확정 | 신뢰성 논리의 핵심 |
| D6 | **에이전트는 규칙 버킷을 ±1단계까지만 조정**, 조정 시 `override_reason` 필수, 위반 시 규칙 결과로 fallback | 확정 | "AI가 임의로 정했다" 반론 차단 |
| D7 | 3단계 버킷: **NOW / NEXT / MONITOR** | 확정 | |
| D8 | **CISA KEV는 점수 규칙에만 두고 데모 대비 장면은 EPSS + 도달성 중심** | 확정 | KEV에 npm 라이브러리가 거의 없음 (6.4 참고) |
| D9 | **검증 샌드박스 도입 (A안)**: 에이전트 조치안을 일회용 컨테이너에서 적용 → 설치·빌드·테스트 → 재스캔하여 검증 | 채택 (T1 반영) | 사용자가 인프라 단 확장을 제안 → 범위를 "검증용 샌드박스"로 좁혀 채택. 아키텍처 다이어그램에 반영됨 |
| D10 | **온프레미스 배포 (B안)**: 구현하지 않고 지원서 "구축방안"과 발표에서 **설계로만** 제시 | 채택 (T1 반영) | 사내망 구동, 취약점 DB 미러링, 사내 LLM 대체 가능 |
| D11 | **에이전트의 인프라 직접 관리 (C안)**: 하지 않음. 자율성 로드맵 L3~L4로만 언급 | 확정 | 신뢰 설계("판단은 AI, 실행은 사람 승인")와 충돌, 범위 폭발 |
| D12 | 아키텍처 다이어그램은 **Archify**(github.com/tt-a1i/archify)로 렌더링 | 진행 중 | 소스 JSON 작성 완료, 렌더링 미완 (8장) |
| D13 | 점수 가중치 severity 25 / exploit 25 / exposure 50 | 채택 (golden set으로 튜닝) | severity + exploit 합이 60 미만이라 exposure가 낮으면 규칙만으로 NOW가 되지 않음. 기존 30/35/35에서는 dev 미사용 패키지가 NOW가 될 수 있었음 |
| D14 | 샌드박스 호출 주체는 에이전트가 아니라 오케스트레이터(`runner.py`) | 채택 (T1 반영) | 에이전트 읽기 전용 규칙 유지 |
| D15 | LLM 출력은 `AgentVerdict`로 제한, 샌드박스 명령은 `apply.py`가 조립 | 채택 (T1 반영) | 프롬프트 인젝션이 명령 실행으로 이어지는 경로 차단, 점수 필드를 타입에서 제거 |
| D16 | 조치 전 기준선을 run당 1회 측정하고 회귀만 실패로 판정 | 채택 (T1 반영) | 원래 깨져 있던 테스트를 조치 실패로 오판하지 않기 위함 |
| D17 | 리플레이 2층: 응답 캐시 + `events.jsonl` | 채택 (T1 반영) | 응답 캐시는 LLM·Docker 단계를 재현하지 못함 |
| D18 | `rationale` 수치는 자리표시자로 쓰고 코드가 채움 | 채택 (T1 반영) | 근거 수치를 구조적으로 데이터와 일치시킴 |
| D19 | F8-5(조치안 재생성)를 P0로 승격, 컷 대상에서 제외 | 채택 (T1 반영) | 과제 문구 "조치안 개선"에 직접 대응 |
| D20 | SBOM을 스캔의 단일 입력으로 사용, 재스캔도 SBOM 재생성 후 수행 | 채택 (T1 반영) | 과제 문구 "SBOM과 스캔 결과의 연결" |
| D22 | 데모 레포 = `gothinkster/node-express-realworld-example-app`, 커밋 고정 | 확정 | Prisma mock 단위 테스트, A·B·C 후보 존재. 라이선스 없음 → 코드 미커밋 |
| D23 | import 위치를 runtime/test로 구분, 테스트 전용 import는 미사용 처리 | 채택 | axios가 e2e에서만 import되어 NOW로 오탐되던 문제 |
| D24 | NOW 검증은 패키지@버전 단위로 묶어 수행 | 채택 | 한 패키지의 취약점별 수정 버전이 달라 Finding 단위 검증은 낭비 |
| D25 | 차별점은 실측으로 제시: CVSS 정렬, 규칙, 규칙 + 에이전트 비교, 평가 레포 2개 추가, 오판 공개 | 채택 | 설계 주장은 다른 팀도 쉽게 작성 가능 |
| D26 | 하향 안전장치(F6-9)와 NOW 누락 지표 | 채택 | ±1만으로는 KEV 항목도 하향 가능했음 |
| D27 | 여러 레포 영향 조회를 P1로 승격 | 채택 | 롯데이노베이트 관점과 SBOM 축적 이유를 보여줌 |
| D28 | 회귀 판정은 테스트 이름 단위로 수행 | 채택 | 데모 레포 기준선에서 테스트 7건이 이미 실패 (`docs/poc-results.md`) |
| D21 | 서비스 맥락(`service_criticality`, `internet_facing`)을 입력받되 근거·표시 전용 | 채택 (T1 반영) | 서비스 관점 영향도 보강, 점수 결정성과 D13 유지 |

---

## 3. 파일 인벤토리

```
sbom-triage/
├─ HANDOFF.md                              ← 이 문서
├─ CLAUDE.md                               ← 규칙·스택·디렉터리·컨벤션 (샌드박스 미반영)
├─ HARNESS.md                              ← Phase·게이트·검증·컷 규칙 (샌드박스 미반영)
└─ docs/
   ├─ REQUIREMENTS.md                      ← 요구사항 v0.1 (샌드박스 미반영)
   ├─ architecture/
   │  └─ archify.candidate.json            ← Archify 아키텍처 소스 (렌더링 전)
   └─ application/
      └─ 01-정의및기획안.txt               ← 지원서 1번 칸 초안 (1,856 / 3,000자)
```

아직 코드는 한 줄도 없다. `backend/`, `web/`, `fixtures/`, `tests/`는 P0 Setup에서 만든다.

---

## 4. 시스템 요약

### 4.1 한 줄 정의

npm 레포의 취약점을 CVSS 목록이 아니라 **NOW / NEXT / MONITOR**로 나누고, 항목별 **근거**와 **샌드박스에서 검증된 조치안**을 제시하는 에이전트.

### 4.2 전체 흐름 (샌드박스 반영 최신본)

```
[담당자] ─검토·조치 승인─▶ [Next.js 대시보드] ─분석 요청·SSE─▶ [FastAPI 오케스트레이터] ──▶ [실행 결과 저장소 out/<run_id>]
                                                              │
                                                              ▼ 레포 경로
                          ┌──── [응답 캐시] ◀── 보강 데이터 조회 ── [① SBOM ② 스캔 ③ 보강] ── lockfile·import 검색 ──▶ [대상 레포]
                          │   (DEMO_MODE=replay)                        │                                              ▲
                          ▼ 미스 시 HTTPS                               ▼ Finding[]                                     │ 읽기 전용 tool
                 [공개 취약점 DB: OSV·EPSS·KEV]                [④ 규칙 점수 엔진] ─NOW·NEXT 후보─▶ [⑤ 트리아지 에이전트] ─┘
                                                                                                  │        │
                                                                              근거 데이터만 전송 ▼        ▼ 조치안 검증
                                                                                           [LLM API]   [⑥ 검증 샌드박스]
                                                                                                        (격리 컨테이너 · egress 제한)
경계: [온프레미스 사내망] = 대시보드, API, 파이프라인, 점수 엔진, 에이전트, 샌드박스, 캐시, 저장소, 대상 레포
     외부 = 담당자(사용자), 공개 취약점 DB, LLM API
```

### 4.3 단계별 책임

| 단계 | 모듈 | 결정론? | 하는 일 |
|---|---|---|---|
| ① SBOM | `triage/sbom.py` | 예 | Syft → CycloneDX JSON. 실패 시 lockfile 직접 파싱 |
| ② 스캔 | `triage/scan.py` | 예 | OSV 조회 → `Finding` 정규화, 동일 취약점 경로 병합 |
| ③ 보강 | `triage/enrich/*` | 예 | EPSS, KEV, scope(dev/prod), direct/transitive, fixed_in·bump, import 위치 |
| ④ 점수 | `triage/score.py` | 예 (순수 함수) | risk·effort → rule_bucket, 점수 분해 기록 |
| ⑤ 에이전트 | `triage/agent/*` | 아니오 | 도달성 판정, ±1 조정, 근거 3줄, 조치안 |
| ⑥ 검증 | `triage/verify/*` (신규) | 예 (컨테이너 실행) | 조치안 적용 → install/build/test → 재스캔 → 결과 첨부, 실패 시 에이전트 재시도 |
| ⑦ 대시보드 | `web/` | — | 버킷 뷰, 상세 근거, 검증 결과, 승인 |

---

## 5. 샌드박스 도입 변경사항 (T1 반영 완료)

> ✅ 2026-10-31 반영 완료. 아래는 당시 기록이며, 최종 스키마·판정 규칙은 `docs/REQUIREMENTS.md` F8·8장이 기준이다. 특히 5.2의 `Remediation.commands`는 LLM이 아니라 코드가 채우고, `Verification`에는 `regressions`가 추가되었다(D15, D16).

### 5.1 REQUIREMENTS.md에 추가할 기능 그룹 F8 — 검증 샌드박스

| ID | 요구사항 | 우선순위 |
|---|---|---|
| F8-1 | **NOW 버킷 항목**의 조치안을 일회용 Docker 컨테이너에서 검증 (NEXT·MONITOR는 검증하지 않음) | P0 |
| F8-2 | 원본 레포는 읽기 전용 마운트, 컨테이너 안 작업 디렉터리로 **복사** 후 변경 | P0 |
| F8-3 | 검증 단계: 조치 적용 → 의존성 설치 → `build` 스크립트(있으면) → `test` 스크립트(있으면) → 새 lockfile로 OSV 재스캔 | P0 |
| F8-4 | 판정: 대상 취약점 해소 여부 + **새로 생긴 취약점 중 NOW급 존재 여부** + 빌드/테스트 통과 여부 | P0 |
| F8-5 | 실패 시 실패 로그를 에이전트에 전달하여 **대안 조치안 재생성 (최대 2회)** → 과제 문구 "조치안 개선"에 대응 | P1 |
| F8-6 | 리소스 제한: CPU·메모리·PID 수·실행 시간(예: 5분) 상한 | P0 |
| F8-7 | 네트워크 제한 (6.6 참고): MVP는 설치 단계만 네트워크 허용 + `--ignore-scripts`, 빌드·테스트 단계는 `--network none` | P0 |
| F8-8 | 레지스트리만 허용하는 egress 프록시 | P2 (설계로만 언급) |
| F8-9 | 검증 결과·로그를 `out/<run_id>/verify/<finding_id>/`에 저장, 리플레이 모드에서 재생 가능 | P0 |

### 5.2 스키마 추가 (`models.py`)

```python
class VerifyStep(BaseModel):
    name: Literal["apply", "install", "build", "test", "rescan"]
    status: Literal["passed", "failed", "skipped"]
    duration_ms: int
    log_tail: str                       # 마지막 N줄만

class Verification(BaseModel):
    finding_id: str
    attempt: int                        # 1부터, 최대 3 (최초 + 재시도 2)
    remediation_applied: Remediation
    steps: list[VerifyStep]
    target_resolved: bool               # 대상 취약점 해소
    new_findings: list[str]             # 새로 생긴 취약점 id
    new_now_findings: list[str]         # 그중 NOW급
    verdict: Literal["verified", "failed", "inconclusive"]
    # verified = target_resolved and not new_now_findings and build/test가 failed 아님

class Triage(BaseModel):
    ...                                 # 기존 필드 유지
    verification: Verification | None   # NOW 항목만 채워짐
```

`Remediation` 모델은 REQUIREMENTS에 이름만 있고 정의가 없다. 아래로 정의한다.

```python
class Remediation(BaseModel):
    kind: Literal["upgrade_direct", "override_transitive", "mitigation_only"]
    package: str
    from_version: str
    to_version: str | None              # mitigation_only면 None
    commands: list[str]                 # 예: ["npm install lodash@4.17.21"]
    package_json_patch: dict | None     # overrides 스니펫
    mitigation: str | None              # 수정 버전이 없을 때의 임시 완화책
    breaking_risk: Literal["low", "medium", "high"]
    notes: str | None
```

### 5.3 데모 시나리오 변경

기존 4단계 "B의 조치 명령어 실행 → 재스캔 → 사라짐"을 다음으로 교체한다.

> **4. 검증 (30초):** B 항목 상세 패널에서 샌드박스 검증 결과 표시
> — `install ✓ · build ✓ · test 42/42 ✓ · 재스캔: 대상 취약점 해소 ✓ · 신규 NOW 0건` → **승인 대기**
> (가능하면 실패 → 재시도 → 성공 사례 1건도 보여준다: "조치안 개선")

### 5.4 우선순위·일정 변경

- **F6-6 (PR 초안 생성)**: P1 → **P2**로 하향. 검증 결과가 PR보다 데모 가치가 높다.
- **컷 순서 갱신**: F7-5 → F6-6 → F8-5 → F4-6 → F4-5 → F1-3
- **HARNESS Phase 추가**: P3(Agent)와 P4(Dashboard) 사이에 **P3.5 Verify** 삽입

| Phase | 내용 | 게이트 |
|---|---|---|
| P3.5 Verify | ⑥ 샌드박스 검증 | 데모 레포 NOW 항목 전부 `verdict` 산출 · 컨테이너가 원본 레포를 변경하지 않음(테스트로 확인) · 시간 상한 초과 시 `inconclusive`로 종료 |

- **시간 박스 갱신**: D2 12:00 P3 게이트 → **D2 14:00 P3.5 게이트** 추가 (안 되면 F8-5 제거, 검증은 install+rescan만) → D2 16:00 P4 게이트 → D2 18:00 기능 동결

### 5.5 CLAUDE.md 갱신 사항

- 디렉터리에 `backend/triage/verify/` (`sandbox.py`, `apply.py`, `run.py`) 추가
- 스택 표에 **Docker** 추가 (검증 샌드박스)
- 절대 규칙 4번 보강: "에이전트는 읽기 전용. **변경은 샌드박스 컨테이너 안의 복사본에만** 적용되며, 원본 레포 반영은 사람 승인 후 별도 경로."
- 자주 쓰는 명령에 `uv run python -m triage verify out/<run_id>` 추가

### 5.6 HARNESS.md 갱신 사항

- 3장 검증 장치에 추가:
  - `tests/test_sandbox.py` — 원본 레포 불변, 타임아웃 동작, 네트워크 차단 단계에서 외부 호출 실패 확인
- 4장 에이전트 실행 설계 끝에 검증 루프 추가:

```
for t in final_triage where final_bucket == NOW:
    attempt = 1
    loop:
        v = sandbox.verify(t.remediation)
        if v.verdict == "verified" or attempt == 3: break
        t.remediation = agent.revise(t, failure=v.steps)   # 실패 로그 전달
        attempt += 1
    t.verification = v
```

- 7장 진행 로그에 "샌드박스 결정 반영" 한 줄 추가

### 5.7 자율성 단계 (발표·지원서용, REQUIREMENTS 11장 "범위 밖" 근처에 추가)

| 단계 | 에이전트가 하는 일 | 이번 해커톤 |
|---|---|---|
| L0 | 우선순위·조치안 추천 | ✓ |
| L1 | 샌드박스에서 조치안 검증 | ✓ |
| L2 | 검증된 조치안으로 PR 생성 | 일부 (P2) |
| L3 | 정책 범위 내 자동 병합 (예: patch 버전 + 테스트 통과) | 로드맵 |
| L4 | 컨테이너 이미지·인프라 단 조치 | 로드맵 |

### 5.8 온프레미스 설계 (구현 X, 지원서·발표용)

- 전 구성요소를 사내망에서 구동, 계열사 소스코드는 외부로 나가지 않음
- 외부 데이터는 주기적 동기화: OSV 데이터 덤프, EPSS 일일 CSV, KEV JSON → 사내 미러
- LLM: 프로토타입은 외부 API(근거 데이터만 전송) / 운영은 사내 LLM으로 교체 가능하도록 LLM 호출을 어댑터로 분리
- 샌드박스: 사내 npm 레지스트리 미러(예: Verdaccio, Nexus)만 허용

---

## 6. 기술 상세와 함정 (구현 전 반드시 확인)

> 아래 API·도구 동작은 작성 시점 지식 기준이다. **구현 시 공식 문서로 재확인**할 것.

### 6.1 SBOM (Syft)

- 명령 예: `syft dir:<repo> -o cyclonedx-json=<out>/sbom.cdx.json`
- **dev/prod 구분은 Syft 출력에 의존하지 말 것.** `package-lock.json`(lockfileVersion 2·3)의 `packages` 맵에서 각 항목의 `"dev": true` 플래그로 판정한다.
- direct 여부: 루트 `package.json`의 `dependencies`/`devDependencies` 키로 판정
- 의존성 경로(`paths`): lockfile의 `node_modules/a/node_modules/b` 중첩 경로와 각 패키지의 `dependencies` 필드로 그래프를 만들어 BFS
- Syft 설치 불가·실패 시 F2-2 fallback(lockfile 파싱)으로 바로 전환 — 게이트에서 막히지 말 것

### 6.2 취약점 스캔 (OSV)

- `POST https://api.osv.dev/v1/querybatch` — **응답에는 취약점 ID(및 modified)만 온다.** 상세(affected ranges, severity, aliases)는 `GET https://api.osv.dev/v1/vulns/{id}`로 별도 조회해야 한다. 상세 조회 결과는 반드시 캐시.
- **OSV의 `severity`는 CVSS 점수가 아니라 벡터 문자열**(예: `CVSS:3.1/AV:N/...`)인 경우가 많다. 점수로 변환하려면 Python `cvss` 패키지 등을 사용. 없으면 `database_specific.severity`(GHSA의 LOW/MODERATE/HIGH/CRITICAL)를 대표값으로 매핑하고 그 사실을 `risk_breakdown`에 기록.
- npm 어드바이저리는 GHSA ID가 기본이고 CVE는 `aliases`에 있을 수도, 없을 수도 있다.
- `fixed_in`: `affected[].ranges[].events`의 `fixed` 값 중 현재 버전보다 큰 최소값

### 6.3 EPSS (FIRST)

- `GET https://api.first.org/data/v1/epss?cve=CVE-A,CVE-B,...` (여러 개 콤마 구분, 배치 크기 제한 확인)
- **CVE ID에만 점수가 있다.** GHSA만 있는 항목은 `epss=None` → 점수 규칙에서 "미상" 처리 (exploit 항목에 중립값, 예: 백분위 0.5가 아니라 **별도 상수**로 두고 근거에 "EPSS 없음" 명시)

### 6.4 CISA KEV

- JSON 피드: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` — 실행 시 1회 받아 캐시
- **npm 라이브러리 등재는 거의 없다** (주로 상용 제품·OS·장비). 따라서 KEV는 점수 규칙에만 존재하고, 데모 장면에 의존하지 않는다 (D8).

### 6.5 도달성 (reachability)

- 1차: Python 파일 순회로 `import ... from 'pkg'`, `require('pkg')`, `import('pkg')`, 서브패스(`pkg/sub`) 검색 → `import_sites`
- 2차 (에이전트): 어드바이저리 본문에서 취약 함수명 추출(F4-5, P1) → `search_usages(package, symbol)`로 호출 여부 확인
- 간접 의존성은 우리 코드가 직접 import하지 않으므로, **그 패키지를 끌어온 direct 의존성의 사용 여부**를 기준으로 판단하고 `unknown`을 적극 사용 (모르면 unknown — 과대 확신 금지)
- `node_modules` 내부는 검색 대상에서 제외

### 6.6 검증 샌드박스 (Docker)

- 베이스 이미지: 대상 레포의 Node 버전과 맞는 `node:<ver>-slim` (`package.json`의 `engines` 또는 `.nvmrc` 참고, 없으면 LTS)
- 실행 옵션 예: `--rm --memory 2g --cpus 2 --pids-limit 512 --read-only`(작업 디렉터리만 tmpfs/볼륨) + 원본 레포는 `:ro` 마운트 후 컨테이너 내부로 복사
- **네트워크 2단계 (MVP):**
  1. install 단계: 네트워크 허용, `npm ci --ignore-scripts` (설치 스크립트 실행 차단 — 악성 패키지의 postinstall 공격 경로 차단)
  2. build/test/rescan 준비 단계: `--network none` 컨테이너로 재실행 (같은 볼륨 사용)
  - 재스캔(OSV 조회)은 컨테이너 밖 호스트에서 새 lockfile을 읽어 수행
- `--ignore-scripts` 때문에 네이티브 모듈 빌드가 필요한 레포는 build가 실패할 수 있다 → 데모 레포 선정 시 확인 (10장 Q1)
- 조치 적용 방식:
  - `upgrade_direct`: `npm install <pkg>@<ver> --package-lock-only --ignore-scripts` 후 `npm ci`
  - `override_transitive`: `package.json`에 `overrides` 추가 후 `npm install --package-lock-only` → `npm ci`
- 데모 환경에 Docker가 없을 가능성 대비: 검증 결과는 사전 실행분을 `out/`에 저장하고 리플레이 모드에서 재생 (N1)

### 6.7 LLM / 에이전트

- Anthropic API tool use, 모델명은 `.env`의 `LLM_MODEL`로 주입 (하드코딩 금지)
- 항목당 tool call 최대 6회, 출력은 Pydantic 검증 → 실패 시 오류 메시지 붙여 1회 재시도 → 재실패 시 규칙 결과 fallback
- **근거 사실성 검증**: `rationale`에서 숫자(CVSS, EPSS, 버전 문자열)를 추출해 `Finding` 값과 대조하는 테스트 필수
- LLM 호출은 어댑터(`agent/llm.py`)로 분리 — 온프레미스 시 사내 LLM 교체 대비 (5.8)
- 외부 전송 데이터: CVE/GHSA ID, 패키지명·버전, 보강 수치, **필요한 코드 조각만**. 레포 전체 전송 금지.

### 6.8 점수 규칙 (초안, REQUIREMENTS F5 그대로)

```
risk (0~100) = severity×25 + exploit×25 + exposure×50
  severity = CVSS/10
  exploit  = 1.0 if KEV else EPSS 백분위 (없으면 상수, 근거에 명시)
  exposure = scope_w × path_w × reach_w
      scope_w : prod 1.0 / dev 0.2
      path_w  : direct 1.0 / transitive 0.7
      reach_w : used_symbol 1.0 / imported_only 0.6 / unused 0.2 / unknown 0.6
effort: low(patch·minor) / medium(major 또는 overrides) / high(수정 버전 없음)
bucket: NOW risk≥60 / NEXT 30≤risk<60 또는 (risk≥60 & effort=high) / MONITOR risk<30
```

- 주의: 규칙 단계(④)에서는 아직 에이전트의 도달성 판정이 없으므로 `reach_w`는 import 검색 결과 기반 (direct는 `import_sites` 있으면 imported_only, 없으면 unused / transitive는 unknown). 에이전트가 used_symbol/unknown으로 바꾸면 **점수를 재계산하지 않고** 버킷 ±1 조정과 사유로 반영한다 (D6 일관성 유지).
- 가중치는 `config/scoring.yaml`로 분리 (F5-4)하고 golden set 일치율로 튜닝 (D13).

---

## 7. 지원서 작성 현황

롯데 AX 해커톤 지원서에 3,000자 제한 칸이 두 개 있다.

### 7.1 [과제 해결방안] 정의 및 기획안 — 초안 완료

- 파일: `docs/application/01-정의및기획안.txt` (1,856자 / 3,000자)
- 구성: 문제정의 / 해결방안(1~5단계) / 기대효과 / 차별성
- **남은 수정:**
  - "47건 → 3건"은 **가정 숫자**. 데모 레포 실제 스캔 후 실수치로 교체
  - 약 1,100자 여유 → 롯데이노베이트 관점의 활용 시나리오(다수 계열사 서비스 공통 적용 등) 추가 예정
  - **샌드박스 검증(D9)이 아직 반영되지 않음** → 해결방안 5) 조치안 도출에 "격리 환경에서 실제 적용·테스트·재스캔으로 검증" 추가, 차별성에 "검증된 조치안" 추가

### 7.2 [과제 해결방안] 구축방안 — 미작성

평가 항목: AI 모델설계 / 활용데이터 / AI 에이전트 개발방식 / 신뢰성·안정성 확보 방안. 다룰 내용 개요:

| 항목 | 담을 내용 |
|---|---|
| AI 모델설계 | 하이브리드 구조(규칙 점수 + LLM 에이전트), LLM의 역할 한정(도달성·근거·조치안), ±1 조정 제약 |
| 활용데이터 | CycloneDX SBOM, OSV, EPSS, CISA KEV, lockfile 메타데이터, 소스 코드 import 정보, 어드바이저리 본문, changelog |
| 에이전트 개발방식 | tool use 기반 에이전트, tool 목록(get_finding, search_usages, read_file, get_advisory, get_changelog), 구조화 출력(JSON 스키마), 검증 실패 시 재시도 루프 |
| 신뢰성·안정성 | 스키마 검증, ±1 제약 + fallback, 근거 수치 자동 대조, golden set 일치율 평가, 샌드박스 검증(격리·리소스 제한·네트워크 차단·`--ignore-scripts`), human-in-the-loop 승인, 외부 응답 캐시·리플레이, 온프레미스 설계(5.8), 자율성 단계(5.7) |

사용자는 이 칸을 **개념 공부와 함께** 작성하길 원한다. 초안 작성은 claude.ai 대화에서 이어갈 가능성이 높으나, 요청 시 Claude Code에서 `docs/application/02-구축방안.txt`로 작성해도 된다. 작성 후 반드시 글자 수(공백 포함)를 세어 3,000자 이하인지 확인.

---

## 8. 아키텍처 다이어그램 (Archify) — 렌더링 미완

- 도구: **Archify** — https://github.com/tt-a1i/archify (Agent Skill, v3.2.0, Apache-2.0)
- 렌더러는 외부 코드이므로 사용자가 검토·설치한 뒤 실행한다.
- 소스: `docs/architecture/archify.candidate.json` (`diagram_type: architecture`, `locale: ko`, `quality_profile: showcase`)
- 출력 경로: `docs/architecture/sbom-triage-architecture.html` (`meta.output`에 설정됨, 레포 루트 기준 상대경로)
- **막힌 이유:** claude.ai 작업 환경의 보안 정책이 외부에서 받은 Archify 렌더러 실행을 차단함. 스키마 검증·렌더링을 한 번도 통과하지 않았다.

**할 일 (T2):**

1. Archify 설치 (README 기준):
   ```
   Install Archify for me by reading https://raw.githubusercontent.com/tt-a1i/archify/main/llms.txt
   ```
   또는 `npx skills use tt-a1i/archify@archify --agent <agent>` 류의 방법. 설치 후 스킬의 `SKILL.md` 지침을 따른다.
2. 레포 루트(`sbom-triage/`)에서 실행:
   ```bash
   node <archify-skill-path>/bin/archify.mjs finalize architecture \
     docs/architecture/archify.candidate.json \
     docs/architecture/sbom-triage-architecture.html \
     --quality showcase --json
   ```
3. 실패 시 SKILL.md의 repair 절차를 따른다. 예상 리스크:
   - 캔버스 폭 약 1,740px (허용 상한 1,790px, 가로:세로 ≥ 1.55 조건) — 라벨이 작아지면 열 간격·노드 폭 조정
   - `pipeline→repo`, `agent→repo` 두 경로가 모두 꺾이는 선(one-bend)이라 교차·라벨 충돌 가능
   - `region` 경계의 `pad: 20`이 상단 외부 노드(공개 취약점 DB, LLM API)와 겹치지 않는지 확인
   - **노드·관계·라벨의 의미는 바꾸지 말고 좌표·크기만** 조정
4. 다이어그램 구성 (수정 시 의미 보존 기준):
   - 메인 경로(emphasis): 담당자 → 대시보드 → 오케스트레이터 → SBOM·스캔·보강 → 규칙 점수 엔진 → 트리아지 에이전트 / 오케스트레이터 → 검증 샌드박스 (에이전트가 샌드박스를 직접 호출하지 않음)
   - 보조: 파이프라인→응답 캐시→(미스 시, dashed)공개 취약점 DB / 에이전트→LLM API(security, "근거 데이터만 전송") / 파이프라인→대상 레포("lockfile · import 검색") / 에이전트→대상 레포(security, "읽기 전용 tool") / 에이전트→응답 캐시 / 샌드박스→대상 레포("읽기 전용 마운트") / 샌드박스→npm 레지스트리("install 단계만") / 재스캔→응답 캐시 / FastAPI→실행 결과 저장소
   - 경계: region "온프레미스 사내망"(외부 3개 제외 전부), security-group "격리 컨테이너 · egress 제한"(샌드박스)
   - 카드 4장: ① 파이프라인(결정론) / ② 판단(하이브리드) / ③ 조치·검증 / 보안 경계

---

## 9. Claude Code 작업 순서

각 태스크는 HARNESS.md 1장의 작업 루프(READ → PLAN → BUILD → VERIFY → RECORD)를 따른다.

| # | 태스크 | 완료 기준 |
|---|---|---|
| **T0** | `git init`, `.gitignore`(`.env`, `out/`, `node_modules/`, `.venv/`, `fixtures/cache/`는 **커밋 대상**인지 사용자에게 확인), 첫 커밋 | 현재 문서 5개가 커밋됨 |
| **T1** | 5장 변경사항을 REQUIREMENTS / CLAUDE / HARNESS에 반영, REQUIREMENTS 버전 v0.2로 | 세 문서에 샌드박스(F8, P3.5, verify 디렉터리, Verification 스키마)가 일관되게 존재. 이 HANDOFF 5장 상단에 "반영 완료" 표기 |
| **T2** | Archify로 다이어그램 렌더링 (8장) | `finalize` 통과, HTML 생성. 사용자에게 링크 전달 |
| **T3** | 10장 열린 질문 중 **Q1(데모 레포)** 사용자에게 확인 | 데모 레포 확정 |
| **T4** | P0 Setup: `backend/` uv 프로젝트, `models.py`(5.2 포함), `web/` Next.js, `tests/` 뼈대, `.env.example`, Syft·Docker 설치 확인 | HARNESS P0 게이트 통과 |
| **T5** | 데모 레포 사전 스캔 → **대비 사례 A·B 존재 확인** (A: CVSS 높음 + dev/미사용 → MONITOR, B: CVSS 중간 + EPSS 상위 + prod + 실제 호출 → NOW) | 없으면 레포 교체 또는 의존성 버전 조정 후 재확인 |
| **T6~** | HARNESS Phase P1 → P2 → P3 → P3.5 → P4 → P5 순서로 진행 | 각 Phase 게이트 |
| 병행 | 지원서 7.1 수정, 7.2 작성 (사용자 요청 시) | 각 3,000자 이하 |

---

## 10. 열린 질문 (사용자 결정 필요)

| # | 질문 | 영향 | 기본값 (응답 없을 때) |
|---|---|---|---|
| Q1 | ~~데모 레포~~ | 해결 | D22 |
| Q2 | 점수 가중치 (exposure 비중 상향 여부) | ④ 결과 | 초안 유지 후 golden set으로 튜닝 |
| Q3 | 해커톤 심사 기준 비중 (기술 완성도 / 사업성 / 실적용성) | 발표·지원서 비중 | 실적용성 강조 |
| Q4 | 롯데이노베이트가 실제 쓰는 SBOM 포맷 (SPDX vs CycloneDX) | ① 출력 포맷 | CycloneDX, SPDX는 확장 계획 |
| Q5 | LLM API 키·모델 제공 여부, 대회장 네트워크 제약 | ⑤, 리플레이 필요성 | 사용자 개인 키, 리플레이 모드 필수 구현 |
| Q6 | 대회 일정(날짜) | 시간 박스 | 미정 |
| Q7 | `fixtures/cache/`를 git에 커밋할지 (리플레이 재현성 vs 레포 크기) | T0 | 커밋 (데모 재현성 우선) |

---

## 11. 하지 말 것

- ❌ 에이전트(또는 Claude Code 자신)가 **원본 대상 레포에 쓰기**·커밋·푸시하기
- ❌ LLM에게 점수 계산을 맡기거나, 버킷을 ±1 넘게 바꾸도록 허용하기
- ❌ `rationale`에 `Finding`에 없는 숫자 쓰기
- ❌ 외부 API를 캐시 없이 직접 호출하기 (`cache.py` 경유 필수)
- ❌ API 키를 코드·로그·`out/`에 남기기
- ❌ P0가 끝나기 전에 P1 기능 시작하기
- ❌ 샌드박스에서 `--ignore-scripts` 없이 설치하기, 네트워크 무제한으로 build/test 돌리기
- ❌ 컨테이너 이미지·OS 패키지·라이선스 스캔으로 범위 확장 (사용자가 명시적으로 원하지 않는 한)
- ❌ 지원서 문구에 확인되지 않은 수치를 사실처럼 쓰기 (가정치는 가정치로 표시)
