# SBOM Triage Agent — 요구사항 정의서

> 롯데 AX 해커톤 · 롯데이노베이트 [인프라] SW 공급망 스캐닝 AI 에이전트
> 형태: 작동 프로토타입 + 발표 · 기간 1~2일 · 1인 개발
> 상태: v0.2 (검증 샌드박스 반영, 같이 다듬는 중)

---

## 1. 한 줄 정의

**"High 취약점 47개"를 "이번 주에 고칠 3개 / 다음 스프린트 10개 / 지켜볼 34개"로 나눠주고, 각각 왜 그런지와 어떻게 고치는지까지 제시하는 에이전트.**

## 2. 문제 정의

| 문제 | 현재 상황 | 결과 |
|---|---|---|
| 경보 피로 (alert fatigue) | `npm audit`, Dependabot이 CVSS 기준으로 수십 개를 동시에 알림 | 개발자가 알림을 무시하거나 일괄 dismiss |
| 우선순위 근거 부재 | CVSS는 "이론상 최악"일 뿐, 실제 악용 여부·우리 코드 사용 여부를 반영하지 않음 | 진짜 위험한 것과 무관한 것이 같은 무게로 쌓임 |
| 조치 비용 불투명 | 패치 업그레이드인지 메이저 업그레이드인지, 깨질지 알기 어려움 | 조치가 미뤄지고 취약 버전이 장기 방치 |

**과제 문구와의 연결:** "SBOM 생성과 취약점 스캔 결과의 영향도·우선순위 연결 구조 설계" + "AI 에이전트 기반 조치안 도출"

## 3. 기존 도구와의 차이

| | npm audit | Dependabot | Snyk | **이 프로젝트** |
|---|---|---|---|---|
| SBOM 표준 포맷 | ✕ | △ | ○ | ○ (CycloneDX) |
| 실제 악용 신호 (EPSS·KEV) | ✕ | ✕ | △ (유료) | ○ |
| 코드 사용 여부 (reachability) | ✕ | ✕ | △ (유료·일부 언어) | ○ (import·심볼 분석 + 에이전트 판단) |
| dev / prod 구분 | △ | △ | ○ | ○ |
| 조치 비용 (semver·breaking) | ✕ | △ (PR만 생성) | △ | ○ |
| "왜 이 순위인가" 설명 | ✕ | ✕ | △ | ○ (항목별 근거) |

> 발표 시 표현: 기존 도구는 **목록**을 주고, 이 에이전트는 **판단과 근거**를 준다.
>
> ⚠️ 위 표는 조사로 확인한 내용이 아니다. 제출·발표 전에 각 도구의 공식 문서로 재검증하고, 차별점은 9장의 실측 수치를 중심으로 제시한다.

## 4. 사용자 & 시나리오

- **주 사용자:** 서비스 개발팀 리드 / 보안 담당자 (롯데이노베이트가 관리하는 계열사 서비스 레포)
- **핵심 시나리오:**
  1. 사용자가 레포(또는 `package-lock.json`)를 입력한다.
  2. 시스템이 SBOM을 만들고 취약점을 찾는다.
  3. 에이전트가 각 취약점에 맥락을 붙여 3개 버킷으로 분류하고 근거를 쓴다.
  4. "이번 주" 항목의 조치안은 격리 컨테이너에서 설치·테스트·재스캔으로 검증된다.
  5. 사용자는 검증 결과와 조치 명령어를 확인하고 **승인**한다.

## 5. 시스템 구조

```
[입력: 레포 경로 / lockfile + 서비스 맥락]
   │
   ▼
① SBOM 생성 ── Syft → CycloneDX JSON   (fallback: lockfile 직접 파싱)
   │
   ▼
② 취약점 스캔 ── SBOM 컴포넌트를 입력으로 OSV API (querybatch)   (대안: Grype)
   │
   ▼
③ 컨텍스트 보강 (결정론적)
   ├─ EPSS 점수·백분위 (FIRST API)
   ├─ CISA KEV 등재 여부 (JSON 피드)
   ├─ dev / prod, direct / transitive (lockfile)
   ├─ 수정 버전 & semver 점프 크기 (OSV affected.ranges)
   └─ import 위치 목록 (정적 검색)
   │
   ▼
④ 규칙 점수 → 1차 버킷  ←── 재현 가능, 테스트 가능
   │
   ▼
⑤ 에이전트 판단 (LLM + tools)
   ├─ 도달 가능성 판정 (취약 심볼이 실제로 호출되는가)
   ├─ 버킷 조정 (규칙 점수 ±1단계까지만)
   ├─ 근거 설명 생성
   └─ 조치안 제안 (kind / to_version / 완화책) ─ 실행 명령은 코드가 조립
   │
   ▼
⑥ 검증 샌드박스 (NOW만) ── 일회용 컨테이너에서 적용 → 설치 → 빌드·테스트 → 재스캔
   │
   ▼
⑦ 대시보드 (React) ── 버킷 뷰, 상세 근거, 검증 결과, 승인 버튼
```

①~⑥의 호출 순서는 오케스트레이터(`triage/runner.py`)가 맡는다. CLI와 FastAPI는 이 오케스트레이터만 호출한다. **샌드박스를 호출하는 것은 에이전트가 아니라 오케스트레이터다.**

**설계 원칙: 하이브리드.** 숫자로 판단 가능한 것(심각도·악용 신호·조치 비용)은 규칙이, 맥락 해석이 필요한 것(도달 가능성·설명·조치안)은 에이전트가 맡는다. 에이전트는 규칙 점수를 **최대 ±1 버킷**만 움직일 수 있고, 움직이면 반드시 이유를 남긴다. → "LLM이 마음대로 정한 거 아니냐"는 질문에 대한 답.

**설계 원칙: LLM 출력은 실행하지 않는다.** 레포 코드와 어드바이저리는 신뢰할 수 없는 입력이므로 프롬프트 인젝션을 전제한다. LLM의 제안은 코드가 검증한 뒤 구조화된 값으로만 사용하고, 셸 명령 문자열을 그대로 실행하지 않는다.

## 6. 기능 요구사항

우선순위: **P0** = 데모에 반드시 필요 / **P1** = 시간 되면 / **P2** = 발표에서 "확장 계획"으로만 언급

### F1. 입력
| ID | 요구사항 | 우선순위 |
|---|---|---|
| F1-1 | 로컬 레포 경로 입력 (package.json + package-lock.json 포함) | P0 |
| F1-2 | `package-lock.json` 파일 업로드 | P1 |
| F1-3 | GitHub 공개 레포 URL 입력 → clone | P1 |
| F1-4 | pnpm / yarn lockfile | P2 |
| F1-5 | 레포별 서비스 맥락 입력: `service_criticality`(high/medium/low), `internet_facing`(bool). 없으면 `None`으로 두고 "미입력" 표시 | P0 |
| F1-6 | 여러 레포의 run 결과를 묶어 CVE별 영향 서비스 조회 (입력: 데모 레포 + 평가 레포) | P1 |

### F2. SBOM 생성
| ID | 요구사항 | 우선순위 |
|---|---|---|
| F2-1 | Syft로 CycloneDX JSON 생성 후 저장 (`out/<run_id>/sbom.cdx.json`) | P0 |
| F2-2 | Syft 실패 시 lockfile 직접 파싱으로 동일 구조 생성 | P0 |
| F2-5 | SBOM이 스캔의 단일 입력. fallback도 같은 CycloneDX 구조를 생성하고, lockfile 메타데이터는 컴포넌트 purl 기준으로 덧붙임 | P0 |
| F2-3 | 컴포넌트마다 `scope(dev/prod)`, `direct(bool)`, `introduced_by(경로)` 보존 | P0 |
| F2-4 | SBOM 다운로드 버튼 | P1 |

### F3. 취약점 스캔
| ID | 요구사항 | 우선순위 |
|---|---|---|
| F3-1 | `sbom.cdx.json`의 컴포넌트로 OSV `querybatch`를 조회 | P0 |
| F3-2 | 결과를 `Finding` 스키마로 정규화 (아래 8장) | P0 |
| F3-3 | 같은 CVE가 여러 경로로 들어온 경우 하나로 묶고 경로 목록 유지 | P0 |
| F3-4 | Grype 결과와 교차 확인 | P2 |

### F4. 컨텍스트 보강
| ID | 요구사항 | 우선순위 |
|---|---|---|
| F4-1 | EPSS 점수·백분위 일괄 조회 | P0 |
| F4-2 | CISA KEV 피드 다운로드 후 CVE 매칭 | P0 |
| F4-3 | 수정 버전과 semver 점프 크기 (patch / minor / major / 없음) | P0 |
| F4-4 | 소스 코드에서 해당 패키지 import 위치 검색 (`import`, `require`, 동적 import). 각 위치를 `runtime` / `test`로 구분 (`e2e/`, `test/`, `tests/`, `*.spec.*`, `*.test.*`는 `test`). 주석과 문자열 안의 언급은 제외 | P0 |
| F4-5 | 어드바이저리에서 취약 함수/심볼명 추출 (예: 특정 유틸 함수) | P1 |
| F4-6 | 메이저 업그레이드 시 changelog/릴리스 노트에서 breaking change 요약 | P1 |
| F4-7 | 모든 외부 응답은 디스크 캐시 (데모 중 네트워크 장애 대비) | P0 |

### F5. 규칙 기반 점수 & 1차 분류
| ID | 요구사항 | 우선순위 |
|---|---|---|
| F5-1 | 위험 점수(risk)와 조치 비용(effort)을 **분리 계산** | P0 |
| F5-2 | risk·effort 조합으로 1차 버킷 결정 | P0 |
| F5-3 | 점수 계산 과정을 항목별로 기록 (어떤 요소가 몇 점 기여했는지) | P0 |
| F5-4 | 가중치는 설정 파일로 분리 | P1 |

**초안 점수 규칙** (팀 리뷰 대상, 실제 데이터로 Day 1에 튜닝)

```
risk (0~100)
  severity   = CVSS / 10                          × 25
  exploit    = 1.0 if KEV else EPSS 백분위         × 25
  exposure   = scope_w × path_w × reach_w          × 50
      scope_w : prod 1.0 / dev 0.2
      path_w  : direct 1.0 / transitive 0.7
      reach_w : 심볼 사용 1.0 / import만 0.6 / 미사용 0.2 / 미판정 0.6

④ 단계의 reach_w 판정 (에이전트 판정 전)
  direct     : runtime import_sites 있으면 import만, 없거나 test뿐이면 미사용
  transitive : 미판정 (직접 import되지 않으므로 미사용으로 단정하지 않는다)

effort
  low    : patch·minor 업그레이드로 해결
  medium : major 업그레이드 or overrides 필요
  high   : 수정 버전 없음 (완화책만 가능)

bucket
  NOW      : risk ≥ 60
  NEXT     : 30 ≤ risk < 60, 또는 risk ≥ 60인데 effort=high(완화책 먼저 + NEXT에 근본 조치)
  MONITOR  : risk < 30
```

> 가중치 근거: severity + exploit 합이 60 미만이어야 exposure가 낮은 항목이 규칙만으로 NOW가 되지 않는다. 30/35/35에서는 CVSS 9.8·EPSS 백분위 0.9인 dev 미사용 패키지가 62.3점으로 NOW가 되어, ±1 제약 때문에 MONITOR까지 내릴 수 없었다.

### F6. 에이전트
| ID | 요구사항 | 우선순위 |
|---|---|---|
| F6-1 | NOW·NEXT 후보에 대해 도달 가능성 판정 (`used_symbol / imported_only / unused / unknown`) | P0 |
| F6-2 | 버킷 조정은 ±1단계까지, 조정 시 `override_reason` 필수 | P0 |
| F6-3 | 항목별 근거 3줄 이내 (한국어). 수치는 `{cvss}` 같은 자리표시자로 쓰고 코드가 `Finding` 값으로 채운다 | P0 |
| F6-4 | 조치안: `kind`·`to_version`·임시 완화책을 제안. 명령어와 `overrides` 스니펫은 코드가 조립 | P0 |
| F6-5 | 출력은 JSON 스키마 강제 (Pydantic 검증 실패 시 1회 재시도, 이후 규칙 결과로 fallback) | P0 |
| F6-6 | PR 초안 (제목·본문·변경 diff) 생성 — **생성만, 푸시는 하지 않음** | P2 |
| F6-7 | 전체 요약 (경영진용 3문장) | P1 |
| F6-9 | 하향 안전장치: KEV 등재 항목은 하향 금지. EPSS 백분위 0.9 이상이면서 `runtime` import가 있거나 규칙 버킷이 NOW인 항목은 자동 하향하지 않고 규칙 버킷을 유지한 채 `needs_review`로 표시. 임계값은 설정 파일로 분리 | P0 |
| F6-8 | 조치 제안 검증: 패키지명이 Finding과 일치, `to_version`이 유효한 semver이고 `fixed_in` 이상. 위반 시 샌드박스로 보내지 않고 규칙 결과로 fallback | P0 |

**에이전트 도구 (tools)**

| 도구 | 입력 | 출력 | 비고 |
|---|---|---|---|
| `get_finding` | finding_id | 정규화된 Finding + 보강 데이터 | 읽기 전용 |
| `search_usages` | package, symbol? | 파일·라인·코드 조각 목록 | 레포 내부만 |
| `read_file` | path, range | 코드 | 레포 내부만, 크기 제한 |
| `get_advisory` | vuln_id | 어드바이저리 본문 요약·영향 함수 | 캐시 우선 |
| `get_changelog` | package, from, to | breaking change 요약 | P1 |

**Human-in-the-loop 지점:** 에이전트는 판단과 제안까지만. 샌드박스 검증은 오케스트레이터가 복사본에 대해 수행하고, 원본 레포 반영·커밋·PR 생성은 대시보드에서 사람이 승인해야 한다.

### F7. 대시보드
| ID | 요구사항 | 우선순위 |
|---|---|---|
| F7-1 | 상단 요약: 전체 취약점 수 → 버킷별 수 (47 → 3 / 10 / 34 같은 "압축" 연출) | P0 |
| F7-2 | 버킷별 카드 리스트 (패키지, CVE, CVSS, EPSS, KEV 뱃지, dev/prod, 도달성) | P0 |
| F7-3 | 상세 패널: 점수 분해 막대 + 에이전트 근거 + 조치안 + 사용 위치 코드 조각 | P0 |
| F7-4 | "CVSS 순 정렬 vs 에이전트 순 정렬" 토글 (발표 핵심 장면) | P0 |
| F7-5 | 분석 진행 상태 스트리밍 (단계별 로그) | P1 |
| F7-6 | 조치 승인 버튼 → 명령어 복사 / PR 초안 다운로드 | P1 |
| F7-9 | 서비스 영향 화면: CVE를 고르면 영향받는 서비스와 버킷, 서비스 중요도를 표시 | P1 |
| F7-7 | 상세 패널에 검증 단계별 결과, 판정, 검증 강도 표시. 테스트가 없거나, 취약 패키지 사용 코드를 테스트가 실행하지 않을 수 있으면 그 한계를 명시 | P0 |
| F7-8 | 상단에 서비스 맥락(중요도·외부 노출) 표시. 점수에는 반영하지 않음 | P0 |

### F8. 검증 샌드박스
| ID | 요구사항 | 우선순위 |
|---|---|---|
| F8-1 | **NOW 버킷 항목**의 조치안을 일회용 Docker 컨테이너에서 검증 (NEXT·MONITOR는 검증하지 않음) | P0 |
| F8-2 | 원본 레포는 읽기 전용 마운트, 컨테이너 안 작업 디렉터리로 **복사** 후 변경 | P0 |
| F8-3 | 검증 단계: 조치 적용 → 의존성 설치 → `build` 스크립트(있으면) → `test` 스크립트(있으면) → 새 lockfile에서 SBOM을 다시 생성해 OSV 재스캔 | P0 |
| F8-4 | 판정: 대상 취약점 해소 여부 + **새로 생긴 취약점 중 NOW급 존재 여부** + 기준선 대비 빌드 회귀 + 새로 실패한 테스트 이름 | P0 |
| F8-5 | 실패 시 실패 로그를 에이전트에 전달하여 **대안 조치안 재생성 (최대 2회)** → 과제 문구 "조치안 개선"에 대응 | P0 |
| F8-6 | 리소스 제한: CPU·메모리·PID 수·실행 시간(예: 5분) 상한 | P0 |
| F8-7 | 네트워크 제한: 설치 단계만 네트워크 허용 + `--ignore-scripts`, 빌드·테스트 단계는 `--network none` | P0 |
| F8-8 | 레지스트리만 허용하는 egress 프록시 | P2 |
| F8-9 | 검증 결과·로그를 `out/<run_id>/verify/<finding_id>/`에 저장, 리플레이 모드에서 재생 가능 | P0 |
| F8-10 | 조치 전 install/build/test를 run당 1회 실행해 **기준선**을 만들고 조치 후 결과와 비교 | P0 |
| F8-12 | NOW 항목을 패키지@버전 단위로 묶어 해당 패키지의 가장 높은 `fixed_in`으로 1회 검증하고, 결과를 묶인 Finding 전부에 연결. 최소 수정 버전은 PoC에서 30개 중 10개에 새 취약점을 만들었다 | P0 |
| F8-13 | 조치 적용 시 lockfile에서 기존 버전 항목을 제거하고, 조치 후 설치는 `npm install --ignore-scripts`로 수행. 조치 전 기준선은 `npm ci` 유지 | P0 |
| F8-14 | `apply` 성공을 판정 근거로 쓰지 않는다. 대상 취약점 해소는 재스캔으로만 판정 | P0 |
| F8-15 | 판정과 별도로 검증 강도(`tests_run`: 실행된 테스트 수)를 기록. 테스트가 없으면 0 | P0 |
| F8-16 | DB가 필요한 레포를 위한 컨테이너 내부 서비스(예: Mongo) | P2 |
| F8-11 | 컨테이너에서 실행하는 명령은 `kind`·`package`·`to_version`으로 코드가 조립. LLM이 쓴 문자열은 실행하지 않음 | P0 |

**판정 규칙**

| verdict | 조건 |
|---|---|
| `failed` | 대상 취약점 미해소, 또는 새 NOW급 취약점 발생, 또는 기준선에서 통과한 빌드나 테스트가 조치 후 실패(회귀) |
| `inconclusive` | `failed`가 아니면서 시간 초과, `mitigation_only`(적용할 업그레이드 없음), 또는 테스트 이름을 추출하지 못해 비교할 수 없음 |
| `verified` | 위 둘에 해당하지 않음. 스크립트가 없어 `skipped`인 단계는 허용하되 대시보드에 표시 |

## 7. 비기능 요구사항

| ID | 요구사항 |
|---|---|
| N1 | **데모 안정성:** 데모 레포는 전체 결과를 사전 실행·캐시. 오프라인 재생 모드(`DEMO_MODE=replay`) 제공 |
| N2 | **재현성:** 같은 입력 → 같은 규칙 점수. 에이전트 출력은 run별로 저장 |
| N3 | **성능:** 의존성 ~1,000개 레포 기준 전체 분석 3분 이내 (에이전트는 NOW·NEXT 후보만 호출) |
| N4 | **비용:** LLM 호출은 후보 항목 수만큼 + 요약 1회. 항목당 토큰 상한 설정 |
| N5 | **보안:** 레포 코드는 로컬에서만 읽음. 외부 전송은 CVE ID·패키지명·버전과 에이전트 컨텍스트로 한정. API 키는 `.env` |
| N6 | **설명 가능성:** 모든 버킷 결정에 규칙 점수 분해 + (있다면) 에이전트 조정 사유가 함께 표시 |
| N7 | **리플레이 2층:** 외부 HTTP는 응답 캐시로, LLM·Docker를 포함한 실행 과정은 `out/<run_id>/events.jsonl` 재생으로 네트워크·Docker 없이 재현. SSE도 같은 이벤트 로그를 읽는다 |
| N8 | **격리:** 샌드박스 작업이 원본 레포를 변경하지 않으며, 컨테이너에 API 키·`.env`를 전달하지 않는다 |

## 8. 핵심 데이터 스키마

```python
class ServiceContext(BaseModel):         # 근거·표시 전용, 점수 입력 아님
    service_name: str
    service_criticality: Literal["high", "medium", "low"] | None
    internet_facing: bool | None

class Finding(BaseModel):
    id: str                      # "<vuln_id>@<package>@<version>"
    vuln_id: str                 # GHSA-… / CVE-…
    aliases: list[str]
    package: str
    version: str
    scope: Literal["prod", "dev"]
    direct: bool
    paths: list[list[str]]       # 의존성 경로들
    cvss: float | None
    epss: float | None
    epss_percentile: float | None
    kev: bool
    fixed_in: str | None
    bump: Literal["patch", "minor", "major", "none"]
    import_sites: list[CodeRef]

class Triage(BaseModel):
    finding_id: str
    risk: int
    risk_breakdown: dict[str, float]
    effort: Literal["low", "medium", "high"]
    rule_bucket: Literal["NOW", "NEXT", "MONITOR"]
    reachability: Literal["used_symbol", "imported_only", "unused", "unknown"]
    final_bucket: Literal["NOW", "NEXT", "MONITOR"]
    override_reason: str | None   # rule_bucket != final_bucket 이면 필수
    rationale: list[str]          # ≤ 3줄, 자리표시자를 채운 최종 문장
    remediation: Remediation
    verification: Verification | None   # NOW 항목만 채워짐
    needs_review: bool                  # F6-9로 하향이 보류된 항목

class RemediationProposal(BaseModel):    # LLM이 제안할 수 있는 범위
    kind: Literal["upgrade_direct", "override_transitive", "mitigation_only"]
    to_version: str | None               # mitigation_only면 None
    mitigation: str | None               # 수정 버전이 없을 때의 임시 완화책
    breaking_risk: Literal["low", "medium", "high"]
    notes: str | None

class AgentVerdict(BaseModel):           # LLM 출력. 점수 필드가 없다
    reachability: Literal["used_symbol", "imported_only", "unused", "unknown"]
    proposed_bucket: Literal["NOW", "NEXT", "MONITOR"]
    override_reason: str | None
    rationale: list[str]                 # `{cvss}` 같은 자리표시자 사용
    remediation: RemediationProposal

class Remediation(BaseModel):            # 검증을 통과한 제안을 코드가 완성한 결과
    kind: Literal["upgrade_direct", "override_transitive", "mitigation_only"]
    package: str
    from_version: str
    to_version: str | None
    commands: list[str]                  # 코드가 조립. 표시·샌드박스 실행용
    package_json_patch: dict | None      # overrides 스니펫, 코드가 조립
    mitigation: str | None
    breaking_risk: Literal["low", "medium", "high"]
    notes: str | None

class VerifyStep(BaseModel):
    name: Literal["apply", "install", "build", "test", "rescan"]
    status: Literal["passed", "failed", "skipped"]
    duration_ms: int
    log_tail: str                        # 마지막 N줄만

class VerificationBaseline(BaseModel):   # run당 1회, 조치 전 상태
    steps: list[VerifyStep]

class Verification(BaseModel):
    finding_id: str
    attempt: int                         # 1부터, 최대 3 (최초 + 재시도 2)
    remediation_applied: Remediation
    steps: list[VerifyStep]
    target_resolved: bool                # 대상 취약점 해소
    new_findings: list[str]              # 새로 생긴 취약점 id
    new_now_findings: list[str]          # 그중 NOW급
    regressions: list[str]               # 기준선 통과 → 조치 후 실패한 빌드 단계·테스트 이름
    tests_run: int                       # 실제 실행된 테스트 수, 검증 강도
    verdict: Literal["verified", "failed", "inconclusive"]   # F8 판정 규칙
```

`Triage`는 LLM이 직접 만들지 않는다. 오케스트레이터가 `score.py` 결과와 검증된 `AgentVerdict`를 합쳐 생성한다.

## 9. 평가 방법

| 지표 | 방법 | 목표 (해커톤 기준) |
|---|---|---|
| 우선순위 일치도 | golden set(데모 레포 10~15건 + 평가 레포 각 5건)과 버킷 일치율. CVSS 정렬, 규칙 단독, 규칙 + 에이전트를 같은 기준으로 비교 | 에이전트 ≥ 80%, 세 방식 수치를 모두 발표 |
| NOW 누락 | golden이 NOW인데 최종 버킷이 MONITOR인 건수 | 0건, 발생 시 사례와 원인을 공개 |
| 오판 기록 | 틀린 항목과 그에 따른 규칙 수정을 `docs/evaluation.md`에 기록 | 발표에서 1건 이상 공개 |
| 노이즈 감소율 | (전체 − NOW) / 전체 | 수치 자체를 발표에 사용 |
| 근거 정확성 | 근거에 인용된 수치가 실제 데이터와 일치하는지 자동 검증 | 100% (불일치 시 테스트 실패) |
| 조치안 유효성 | 샌드박스 검증 `verdict`와 `tests_run` | 데모 NOW 항목 전부 산출. `verified` 비율과 테스트 확인 건수를 나눠 보고 |

## 10. 데모 시나리오 (발표 3분)

1. **문제 제시 (30초):** `npm audit` 출력 화면 — 빨간 줄 수십 개.
2. **실행 (30초):** 같은 레포를 입력 → 단계별 진행 → "47 → 3 / 10 / 34" 압축.
3. **대비 장면 (60초):** CVSS 순 ↔ 에이전트 순 토글.
   - A: CVSS 높음, 그러나 devDependency + 미사용 → MONITOR
   - B: CVSS 중간, 그러나 EPSS 상위 + prod + 취약 함수 실제 호출 → NOW
   - C: EPSS 상위 + `dependencies` 등록, 그러나 실제 import는 테스트뿐 → 하향
   - 데모 레포 후보 사례(사전 조사, CVSS는 등급 근사): A `nx@17.2.6`, B `body-parser@1.20.2`, C `axios@1.6.2`. B는 HIGH 등급이라 위 조건과 일부 다르며, T5에서 실측 재확인
4. **검증 (30초):** B 항목 상세 패널에서 샌드박스 검증 결과 표시 — 설치·빌드·테스트 결과, 대상 취약점 해소, 신규 NOW 0건 → **승인 대기**. 가능하면 실패 → 재시도 → 성공 사례 1건도 보여준다 ("조치안 개선").
5. **서비스 영향 (30초):** CVE 하나를 골라 3개 서비스 중 어디를 먼저 봐야 하는지 표시 (F7-9, 미완성이면 말로 설명). 이후 확장으로 CI 연동, 타 언어를 언급.

> ⚠️ 리스크: CISA KEV에는 npm 라이브러리가 거의 등재돼 있지 않다. "KEV 등재" 장면은 실데이터로 못 만들 가능성이 높으므로 대비 장면 B는 **EPSS + 도달성** 위주로 구성하고, KEV는 점수 규칙에만 존재하게 한다. 데모 레포 의존성은 Day 0에 실제 스캔해서 A·B 사례가 나오는 조합으로 확정한다.

## 11. 범위 밖 (Out of Scope)

- 자동 커밋·자동 PR 푸시
- 컨테이너 이미지, OS 패키지 스캔
- 라이선스 컴플라이언스
- 사내 자산 인벤토리 연동
- 실시간 모니터링 / 웹훅
- 서비스 맥락의 점수 반영 (이번에는 근거·표시 전용)
- 에이전트의 인프라 직접 관리 (아래 L3~L4)
- 온프레미스 실제 구축 (지원서·발표에서 설계로만 제시)

**자율성 단계 (발표·지원서용)**

| 단계 | 에이전트가 하는 일 | 이번 해커톤 |
|---|---|---|
| L0 | 우선순위·조치안 추천 | ✓ |
| L1 | 샌드박스에서 조치안 검증 | ✓ |
| L2 | 검증된 조치안으로 PR 생성 | 일부 (P2) |
| L3 | 정책 범위 내 자동 병합 (예: patch 버전 + 테스트 통과) | 로드맵 |
| L4 | 컨테이너 이미지·인프라 단 조치 | 로드맵 |

## 12. 일정 (1~2일, 1인)

| 시간 | 목표 | 완료 기준 (게이트) |
|---|---|---|
| Day 0 (사전) | 데모 레포 확정, API 접근 확인, 하네스 세팅 | 데모 레포 스캔 시 A·B 유형 사례 존재 |
| D1 오전 | ①②③ 파이프라인 (CLI) | `python -m triage scan <repo>` → findings.json |
| D1 오후 | ④ 규칙 점수 + golden set 라벨링 + FastAPI | 규칙만으로 golden set 일치율 측정 가능 |
| D2 오전 | ⑤ 에이전트 (도달성·근거·조치안) | 스키마 검증 통과, 일치율 규칙 대비 개선 |
| D2 14:00까지 | ⑥ 검증 샌드박스 | 데모 NOW 항목 전부 `verdict` 산출, 원본 레포 불변 |
| D2 16:00까지 | ⑦ 대시보드 P0 | 데모 시나리오 1~4 화면 동작 |
| D2 18:00 이후 | 기능 동결, 리플레이 모드, 리허설 2회 | 네트워크 끊고도 시연 가능 |

**잘라낼 순서 (시간 부족 시):** F7-5 → F6-6 → F4-6 → F7-9 → F1-6 → F4-5 → F1-3. P0는 자르지 않는다.

## 13. 열린 질문

- [ ] 해커톤 심사 기준 (기술 완성도 vs 사업성 vs 롯데이노베이트 실적용성) 비중
- [ ] 롯데이노베이트가 실제 쓰는 스캐너/포맷이 있는지 (SPDX vs CycloneDX)
- [ ] 사용할 LLM / API 키 제공 여부, 사내망 제약
- [ ] REQUIREMENTS 3장 기존 도구 비교표를 공식 문서로 재검증
- [x] 데모 레포: `gothinkster/node-express-realworld-example-app` 확정 (`fixtures/demo-repo.ref`에 커밋 고정, 라이선스가 없어 코드는 커밋하지 않음)
- [x] 데모 레포는 `--ignore-scripts` 설치 후 `prisma generate`가 필요하고, `--network none`에서 build는 통과, test는 기존 실패 7건 (`docs/poc-results.md`)
- [ ] 레포별 준비 명령(`prisma generate`)을 어떤 설정 형식으로 받을지 (LLM이 아닌 사람이 작성)
