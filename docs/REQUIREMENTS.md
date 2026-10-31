# SBOM Triage Agent — 요구사항 정의서

> 롯데 AX 해커톤 · 롯데이노베이트 [인프라] SW 공급망 스캐닝 AI 에이전트
> 형태: 작동 프로토타입 + 발표 · 기간 1~2일 · 1인 개발
> 상태: v0.1 (초안, 같이 다듬는 중)

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

## 4. 사용자 & 시나리오

- **주 사용자:** 서비스 개발팀 리드 / 보안 담당자 (롯데이노베이트가 관리하는 계열사 서비스 레포)
- **핵심 시나리오:**
  1. 사용자가 레포(또는 `package-lock.json`)를 입력한다.
  2. 시스템이 SBOM을 만들고 취약점을 찾는다.
  3. 에이전트가 각 취약점에 맥락을 붙여 3개 버킷으로 분류하고 근거를 쓴다.
  4. 사용자는 "이번 주" 항목의 조치 명령어/PR 초안을 확인하고 **승인**한다.

## 5. 시스템 구조

```
[입력: 레포 경로 / lockfile]
   │
   ▼
① SBOM 생성 ── Syft → CycloneDX JSON   (fallback: lockfile 직접 파싱)
   │
   ▼
② 취약점 스캔 ── OSV API (querybatch)   (대안: Grype)
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
   └─ 조치안 생성 (명령어 / overrides / 완화책 / PR 초안)
   │
   ▼
⑥ 대시보드 (Next.js) ── 버킷 뷰, 상세 근거, 승인 버튼
```

**설계 원칙: 하이브리드.** 숫자로 판단 가능한 것(심각도·악용 신호·조치 비용)은 규칙이, 맥락 해석이 필요한 것(도달 가능성·설명·조치안)은 에이전트가 맡는다. 에이전트는 규칙 점수를 **최대 ±1 버킷**만 움직일 수 있고, 움직이면 반드시 이유를 남긴다. → "LLM이 마음대로 정한 거 아니냐"는 질문에 대한 답.

## 6. 기능 요구사항

우선순위: **P0** = 데모에 반드시 필요 / **P1** = 시간 되면 / **P2** = 발표에서 "확장 계획"으로만 언급

### F1. 입력
| ID | 요구사항 | 우선순위 |
|---|---|---|
| F1-1 | 로컬 레포 경로 입력 (package.json + package-lock.json 포함) | P0 |
| F1-2 | `package-lock.json` 파일 업로드 | P1 |
| F1-3 | GitHub 공개 레포 URL 입력 → clone | P1 |
| F1-4 | pnpm / yarn lockfile | P2 |

### F2. SBOM 생성
| ID | 요구사항 | 우선순위 |
|---|---|---|
| F2-1 | Syft로 CycloneDX JSON 생성 후 저장 (`out/<run_id>/sbom.cdx.json`) | P0 |
| F2-2 | Syft 실패 시 lockfile 직접 파싱으로 동일 구조 생성 | P0 |
| F2-3 | 컴포넌트마다 `scope(dev/prod)`, `direct(bool)`, `introduced_by(경로)` 보존 | P0 |
| F2-4 | SBOM 다운로드 버튼 | P1 |

### F3. 취약점 스캔
| ID | 요구사항 | 우선순위 |
|---|---|---|
| F3-1 | OSV `querybatch`로 패키지@버전별 취약점 조회 | P0 |
| F3-2 | 결과를 `Finding` 스키마로 정규화 (아래 8장) | P0 |
| F3-3 | 같은 CVE가 여러 경로로 들어온 경우 하나로 묶고 경로 목록 유지 | P0 |
| F3-4 | Grype 결과와 교차 확인 | P2 |

### F4. 컨텍스트 보강
| ID | 요구사항 | 우선순위 |
|---|---|---|
| F4-1 | EPSS 점수·백분위 일괄 조회 | P0 |
| F4-2 | CISA KEV 피드 다운로드 후 CVE 매칭 | P0 |
| F4-3 | 수정 버전과 semver 점프 크기 (patch / minor / major / 없음) | P0 |
| F4-4 | 소스 코드에서 해당 패키지 import 위치 검색 (`import`, `require`, 동적 import) | P0 |
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
  severity   = CVSS / 10                          × 30
  exploit    = 1.0 if KEV else EPSS 백분위         × 35
  exposure   = scope_w × path_w × reach_w          × 35
      scope_w : prod 1.0 / dev 0.2
      path_w  : direct 1.0 / transitive 0.7
      reach_w : 심볼 사용 1.0 / import만 0.6 / 미사용 0.2 / 미판정 0.6

effort
  low    : patch·minor 업그레이드로 해결
  medium : major 업그레이드 or overrides 필요
  high   : 수정 버전 없음 (완화책만 가능)

bucket
  NOW      : risk ≥ 60
  NEXT     : 30 ≤ risk < 60, 또는 risk ≥ 60인데 effort=high(완화책 먼저 + NEXT에 근본 조치)
  MONITOR  : risk < 30
```

### F6. 에이전트
| ID | 요구사항 | 우선순위 |
|---|---|---|
| F6-1 | NOW·NEXT 후보에 대해 도달 가능성 판정 (`used_symbol / imported_only / unused / unknown`) | P0 |
| F6-2 | 버킷 조정은 ±1단계까지, 조정 시 `override_reason` 필수 | P0 |
| F6-3 | 항목별 근거 3줄 이내 (한국어), 인용한 데이터 필드 명시 | P0 |
| F6-4 | 조치안: 실행 명령어 / `overrides` 스니펫 / 임시 완화책 중 해당되는 것 | P0 |
| F6-5 | 출력은 JSON 스키마 강제 (Pydantic 검증 실패 시 1회 재시도, 이후 규칙 결과로 fallback) | P0 |
| F6-6 | PR 초안 (제목·본문·변경 diff) 생성 — **생성만, 푸시는 하지 않음** | P1 |
| F6-7 | 전체 요약 (경영진용 3문장) | P1 |

**에이전트 도구 (tools)**

| 도구 | 입력 | 출력 | 비고 |
|---|---|---|---|
| `get_finding` | finding_id | 정규화된 Finding + 보강 데이터 | 읽기 전용 |
| `search_usages` | package, symbol? | 파일·라인·코드 조각 목록 | 레포 내부만 |
| `read_file` | path, range | 코드 | 레포 내부만, 크기 제한 |
| `get_advisory` | vuln_id | 어드바이저리 본문 요약·영향 함수 | 캐시 우선 |
| `get_changelog` | package, from, to | breaking change 요약 | P1 |

**Human-in-the-loop 지점:** 에이전트는 판단과 초안까지만. 업그레이드 실행, 커밋, PR 생성은 대시보드에서 사람이 승인해야 한다.

### F7. 대시보드
| ID | 요구사항 | 우선순위 |
|---|---|---|
| F7-1 | 상단 요약: 전체 취약점 수 → 버킷별 수 (47 → 3 / 10 / 34 같은 "압축" 연출) | P0 |
| F7-2 | 버킷별 카드 리스트 (패키지, CVE, CVSS, EPSS, KEV 뱃지, dev/prod, 도달성) | P0 |
| F7-3 | 상세 패널: 점수 분해 막대 + 에이전트 근거 + 조치안 + 사용 위치 코드 조각 | P0 |
| F7-4 | "CVSS 순 정렬 vs 에이전트 순 정렬" 토글 (발표 핵심 장면) | P0 |
| F7-5 | 분석 진행 상태 스트리밍 (단계별 로그) | P1 |
| F7-6 | 조치 승인 버튼 → 명령어 복사 / PR 초안 다운로드 | P1 |

## 7. 비기능 요구사항

| ID | 요구사항 |
|---|---|
| N1 | **데모 안정성:** 데모 레포는 전체 결과를 사전 실행·캐시. 오프라인 재생 모드(`DEMO_MODE=replay`) 제공 |
| N2 | **재현성:** 같은 입력 → 같은 규칙 점수. 에이전트 출력은 run별로 저장 |
| N3 | **성능:** 의존성 ~1,000개 레포 기준 전체 분석 3분 이내 (에이전트는 NOW·NEXT 후보만 호출) |
| N4 | **비용:** LLM 호출은 후보 항목 수만큼 + 요약 1회. 항목당 토큰 상한 설정 |
| N5 | **보안:** 레포 코드는 로컬에서만 읽음. 외부 전송은 CVE ID·패키지명·버전과 에이전트 컨텍스트로 한정. API 키는 `.env` |
| N6 | **설명 가능성:** 모든 버킷 결정에 규칙 점수 분해 + (있다면) 에이전트 조정 사유가 함께 표시 |

## 8. 핵심 데이터 스키마

```python
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
    rationale: list[str]          # ≤ 3줄
    remediation: Remediation
```

## 9. 평가 방법

| 지표 | 방법 | 목표 (해커톤 기준) |
|---|---|---|
| 우선순위 일치도 | 데모 레포 취약점 10~15개를 직접 라벨링한 golden set과 버킷 일치율 | ≥ 80% |
| 노이즈 감소율 | (전체 − NOW) / 전체 | 수치 자체를 발표에 사용 |
| 근거 정확성 | 근거에 인용된 수치가 실제 데이터와 일치하는지 자동 검증 | 100% (불일치 시 테스트 실패) |
| 조치안 유효성 | 제안 명령어 실행 후 재스캔 시 해당 취약점 해소 여부 | 데모 NOW 항목 100% |

## 10. 데모 시나리오 (발표 3분)

1. **문제 제시 (30초):** `npm audit` 출력 화면 — 빨간 줄 수십 개.
2. **실행 (30초):** 같은 레포를 입력 → 단계별 진행 → "47 → 3 / 10 / 34" 압축.
3. **대비 장면 (60초):** CVSS 순 ↔ 에이전트 순 토글.
   - A: CVSS 높음, 그러나 devDependency + 미사용 → MONITOR
   - B: CVSS 중간, 그러나 EPSS 상위 + prod + 취약 함수 실제 호출 → NOW
4. **조치 (30초):** B의 조치 명령어 실행 → 재스캔 → 사라짐.
5. **확장 (30초):** CI 연동, 타 언어, 계열사 전체 자산 스캔.

> ⚠️ 리스크: CISA KEV에는 npm 라이브러리가 거의 등재돼 있지 않다. "KEV 등재" 장면은 실데이터로 못 만들 가능성이 높으므로 대비 장면 B는 **EPSS + 도달성** 위주로 구성하고, KEV는 점수 규칙에만 존재하게 한다. 데모 레포 의존성은 Day 0에 실제 스캔해서 A·B 사례가 나오는 조합으로 확정한다.

## 11. 범위 밖 (Out of Scope)

- 자동 커밋·자동 PR 푸시
- 컨테이너 이미지, OS 패키지 스캔
- 라이선스 컴플라이언스
- 사내 자산 인벤토리 연동
- 실시간 모니터링 / 웹훅

## 12. 일정 (1~2일, 1인)

| 시간 | 목표 | 완료 기준 (게이트) |
|---|---|---|
| Day 0 (사전) | 데모 레포 확정, API 접근 확인, 하네스 세팅 | 데모 레포 스캔 시 A·B 유형 사례 존재 |
| D1 오전 | ①②③ 파이프라인 (CLI) | `python -m triage scan <repo>` → findings.json |
| D1 오후 | ④ 규칙 점수 + golden set 라벨링 + FastAPI | 규칙만으로 golden set 일치율 측정 가능 |
| D2 오전 | ⑤ 에이전트 (도달성·근거·조치안) | 스키마 검증 통과, 일치율 규칙 대비 개선 |
| D2 오후 전반 | ⑥ 대시보드 P0 | 데모 시나리오 1~4 화면 동작 |
| D2 오후 후반 | 리플레이 모드, 리허설 2회 | 네트워크 끊고도 시연 가능 |

**잘라낼 순서 (시간 부족 시):** F7-5 → F6-6 → F4-6 → F4-5 → F1-3. P0는 자르지 않는다.

## 13. 열린 질문

- [ ] 해커톤 심사 기준 (기술 완성도 vs 사업성 vs 롯데이노베이트 실적용성) 비중
- [ ] 롯데이노베이트가 실제 쓰는 스캐너/포맷이 있는지 (SPDX vs CycloneDX)
- [ ] 사용할 LLM / API 키 제공 여부, 사내망 제약
- [ ] 데모 레포: 본인 프로젝트 vs 의도적으로 오래된 의존성을 가진 공개 레포
