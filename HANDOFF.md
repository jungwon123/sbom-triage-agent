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
| 스택 | **Python(파이프라인·에이전트·API) + React(대시보드, D31)** |
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
| D3 | 스택 = Python + Next.js (대시보드는 D31로 변경) | 확정 | 사용자 답변 |
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
| D29 | 기본 조치 버전은 가장 높은 수정 버전 | 채택 | 최소 수정 버전은 30개 중 10개에서 새 취약점 발생 |
| D30 | 판정과 검증 강도(`tests_run`)를 분리 표시 | 채택 | verified 20개 중 실제 테스트 확인은 2개 |
| D31 | 대시보드를 Next.js에서 Vite + React로 변경, FastAPI가 정적 서빙 | 채택 | SSR·서버 기능이 불필요, 사내망에 Node 서버를 두지 않음 |
| D32 | 프로토타입 저장소는 파일 유지(DB 없음). 운영 설계는 PostgreSQL, 대규모 대응은 작업 큐와 워커 분리 | 채택 | 단일 사용자 시연에 DB 불필요. 병목은 DB가 아니라 샌드박스와 LLM 호출 |
| D33 | 운영 큐는 PostgreSQL `SKIP LOCKED` + lease + fencing, 샌드박스는 서버당 동시 실행 제한(측정 환경 4개), 확장은 서버 추가 | 채택 (설계) | 운영 PoC: 동시 4개에서 처리량 최고, 큐 유실 0 (`docs/poc-results.md`) |
| D34 | 기본 LLM은 Claude Opus 5.5 (`claude-opus-5-5`). 2026-11-19에 비용을 이유로 Claude Fable 5.2에서 변경했고 Fable도 `LLM_MODEL`만 바꾸면 그대로 동작한다. `thinking` 파라미터는 보내지 않고 깊이는 `LLM_EFFORT`(기본 high)로 조절. 강제 `tool_choice`는 400이므로 `auto` + 프롬프트로 유도. 거절 대비 서버측 fallback(`fallbacks: "default"`) 사용. 본선(2026-11-24~25)에서 OpenAI 도구가 제공될 수 있어 `LLM_PROVIDER=openai` 어댑터를 별도 파일로 둔다 | 채택 | 사용자 지정 (2026-11-18, 모델 변경 2026-11-19) |
| D35 | LLM 2단계 분리(선택): `LLM_CODE_PROVIDER=local`이면 사내 모델만 소스코드를 읽어 도달성을 판정하고, 외부 모델(`LLM_PROVIDER`)은 코드와 파일 이름 없이 사실 값만 받아 등급 제안, 근거, 조치안을 쓴다. 도달성은 항상 사내 모델 값을 쓴다 | 채택 (구현, 실호출 미검증) | 소스코드를 외부로 보내지 않기 위함. 규칙과 계약 검사가 있어 약한 로컬 모델도 안전하게 쓸 수 있음. 정확도는 `triage compare`로 측정 예정 |
| D36 | Slack 알림(`triage notify`): 등급 요약, NOW 항목, 검증 판정, 대시보드 링크를 웹훅으로 보낸다. 코드, 파일 이름, LLM이 쓴 문장은 넣지 않는다. 리플레이 모드에서는 보내지 않는다. 승인 버튼은 넣지 않고 대시보드로 연결한다 | 채택 (구현, 실제 전송 미검증) | 사내 메신저의 Slack 호환 웹훅으로도 바꿀 수 있음. 승인까지 Slack에서 받으려면 외부에서 접근 가능한 수신 주소가 필요해 사내망 설계와 맞지 않음 |
| D37 | 하향 안전장치 확대: EPSS 백분위 0.9 이상이고 규칙 버킷이 NOW이면 import가 없어도 AI가 내리지 못한다 | 채택 | 라벨 20건 측정에서 AI가 EPSS 상위 10% 안의 NOW 2건(minimist, systeminformation)을 "import 없음"만으로 NEXT로 내렸음. 같은 20건을 보고 정한 기준이라 다른 자료에서 다시 확인해야 함 |
| D38 | 점수 조정: EPSS는 백분위 0.8 초과분만 반영하고, 소스가 없어 판독할 수 없는 항목의 노출 가중치를 0.6에서 0.4로 낮춘다 | 채택 | 블라인드 SBOM 2개(47건)에서 규칙이 14건만 맞았고 틀린 33건이 모두 과대평가였음. 286건 중 MONITOR가 3건뿐이라 목록을 줄이지 못했음. 블라인드 47건과 기존 20건을 보고 정한 값이므로 새 블라인드 세트(`fixtures/blind2/`)로 확인한다. 가드 임계값 0.9(D37)는 그대로 |
| D39 | 소스가 없는 항목(`missing`에 `source`)은 전용 판단 단계를 쓴다. 도구 없이 1회 호출하고 어드바이저리 본문으로 버킷을 한 단계까지 조정한다. 도달성은 코드가 `unknown`으로 고정하고 2단계 모드의 코드 판독 모델은 부르지 않는다. 블라인드 라벨 92건에서 일치 56 → 66건, NOW 누락 0건. 한 단계 과소평가가 1 → 4건으로 늘어난 것은 알려진 비용이다 | 채택 | 사용자 요청 (2026-11-19) |
| D40 | 서비스 맥락(`service_criticality`, `internet_facing`, 새 필드 `note`)을 AI 지시문에 전달한다. 점수에는 넣지 않는다. `agent --criticality --internet-facing --service-note`로 기존 실행에도 지정할 수 있다. 블라인드 92건에서 일치 66 → 63건으로 개선이 확인되지 않았다(한 번씩만 실행해 실행 간 편차와 구분되지 않음). 과소평가는 4 → 6건 | 연결만 유지, 효과 미확인 | 사용자 요청 (2026-11-19) |
| D41 | 에이전트는 수정안까지 제안하고 반영 여부는 담당자가 결정한다. 수정안의 범위는 의존성 변경(package.json, lockfile)이며, diff는 AI가 쓰지 않고 샌드박스 사본에서 조치 후 실제로 바뀐 내용을 뜬다(`verify/*.patch`). 결정은 `decisions.jsonl`에 추가 전용으로 남기고(승인, 반려, 보류, 이름, 사유, 시각), 승인은 샌드박스 diff가 있을 때만 가능하며 검증 미통과 건의 승인과 모든 반려, 보류에는 사유가 필요하다. 내보내기는 `out/<run>/export/`에 패치와 PR 초안만 쓰고 원본 레포 반영과 푸시는 하지 않는다. 소스코드 수정안은 범위 밖 | 채택 | 사용자 지정 (2026-11-19) |
| D42 | 승인한 변경은 내보낼 때 샌드박스에서 한 번에 적용해 다시 검증하고(`export --together`, 화면의 "함께 검증하고 내보내기") 그 결과를 패치 하나(`export/combined.patch`)로 낸다. 직접 업그레이드를 먼저, overrides를 나중에 적용한다. 샌드박스를 쓸 수 없으면 건별 패치로 대체하고 그 사유를 표시한다. 조치 후 실행된 테스트 수가 조치 전보다 적으면 `verified`가 아니라 `inconclusive`(`fewer_tests_ran`)로 판정한다 같은 패키지가 직접 의존성이면서 다른 버전으로도 끌려오는 경우에는 건별 명령을 이어 붙이지 않고 npm이 권하는 형태(`"overrides": {"pkg": "$pkg"}`)의 명령 하나로 처리한다(`apply.same_package_command`). 건별 명령을 이어 붙이면 간접 사본이 남는 것을 실제 샌드박스에서 확인했기 때문이다 | 채택 | 사용자 요청 (2026-11-19) |
| D43 | 화면에서 시작하는 느린 작업(함께 검증)은 작업 큐로 처리한다. `POST /export/together`는 202와 작업 정보를 돌려주고 화면은 `GET /jobs/{id}`를 2초마다 확인한다. 작업자는 하나라 샌드박스는 한 번에 하나씩 실행되고, 같은 실행에 같은 작업이 진행 중이면 새로 만들지 않고 그 작업을 돌려준다. 상태는 `out/<run>/jobs/<id>.json`에 남아 화면을 새로 고쳐도 이어진다. 큐 자체는 서버 프로세스 안에 있어서 서버가 다시 시작되면 진행 중이던 작업은 `interrupted`로 표시되고 다시 실행해야 한다. 운영 설계에서는 이 자리를 별도 큐와 작업자로 바꾸며 API와 파일 형식은 그대로 둔다 | 채택 | 사용자 요청 (2026-11-19) |
| D44 | 설계 비판 보고서(`docs/reviews/design-critique.md`)의 수정 반영. (1) 버킷 하한: 악성 패키지는 NOW, KEV는 운영이면 NOW, 개발이면 NEXT 이상. 수정 버전이 없다는 이유로 내려가지 않는다. (2) EPSS 백분위 0.9 이상은 AI가 MONITOR로 내리지 못한다(소스가 없어 import 근거가 없는 경우에도 걸리도록). (3) AI의 조치 버전은 알려진 수정 버전 범위 안, 재제안은 목록에 있는 버전만. (4) 2단계 모드의 재제안에는 로그를 보내지 않고, 에이전트의 자격 증명 파일 읽기를 거부한다. (5) KEV와 EPSS 캐시 하루 만료, 실행 기록과 화면에 KEV 목록 판 표시. (6) purl 없는 SPDX 패키지를 미조회로 집계, 네 자리 버전과 rc 번호 비교. (7) `rescore` 명령으로 저장된 실행을 현재 규칙에 맞춘다. 하지 않은 것: EPSS 없음의 기본 점수(0.5) 조정, 직접 의존성의 import 미검출을 `unknown`으로 바꾸는 일, Maven import 검색, 샌드박스 설정 단계의 네트워크 | 채택 | 설계 비판 검토 (2026-11-19) |
| D45 | 실서비스를 기준으로 설계한다(사용자 지정, 2026-11-19). 첫 단계로 저장 계층을 분리했다. `store/`의 인터페이스 뒤에 `file`(기존 방식, 기본값)과 `postgres` 구현이 있고 `TRIAGE_STORE`로 고른다. PostgreSQL에는 실행, Finding, Triage, 이벤트, 결정, HTTP 캐시가 조회용 컬럼과 원본 JSON(`body`)으로 들어가며 결정 테이블은 추가만 한다. 큰 산출물(SBOM, 에이전트 로그, 패치, 내보내기)은 두 모드 모두 `out/<run_id>/`(운영에서는 공유 볼륨이나 오브젝트 저장소)에 둔다. 여러 실행에 걸친 조회(`GET /api/search`)가 가능해졌다. D32("DB 없음")는 이 결정으로 대체한다. 작업 큐는 아직 프로세스 안에 있고 다음 단계에서 DB 기반 큐와 별도 작업자로 옮긴다 | 채택 | 사용자 지정 (2026-11-19) |
| D46 | 작업 큐를 저장 계층으로 옮기고 작업자를 별도 프로세스로 분리했다. 작업은 종류, 대상 실행, 입력값으로 된 기록이고 API는 기록만 추가한다. 작업자(`python -m triage worker`)가 가장 오래된 대기 작업을 가져가(`FOR UPDATE SKIP LOCKED`, 파일 모드는 `flock`) 종류별 처리 함수(`jobs.HANDLERS`)를 실행한다. 같은 실행의 같은 종류 작업은 한 번에 하나만 있도록 DB의 부분 고유 인덱스가 막는다. 작업자는 5초마다 생존 신호를 갱신하고, 30초 동안 신호가 없는 실행 중 작업은 한 번 대기열로 되돌린 뒤 두 번째에는 `interrupted`로 끝낸다. 죽은 줄 알았던 작업자가 뒤늦게 결과를 쓰지 못하도록 갱신은 작업을 쥔 작업자만 할 수 있다. `TRIAGE_WORKER`가 `external`(PostgreSQL 기본)이면 별도 프로세스가, `inline`(파일 기본)이면 API 안의 스레드가 같은 루프를 돈다. 작업자 하나는 작업을 하나씩 처리하므로 동시 샌드박스 수는 작업자 수와 같다. 화면은 떠 있는 작업자가 없으면 그 사실을 알린다. D43의 프로세스 내 큐를 대체한다 | 채택 | D45의 다음 단계 (2026-11-20) |
| D47 | 로그인과 역할을 붙였다. `TRIAGE_AUTH=oidc`이면 표준 OIDC(인가 코드 + PKCE)로 회사 인증 서버에 로그인한다. ID 토큰은 인증 서버의 공개키로 서명을 확인하고 발급자, 대상, 만료, nonce를 검사하며 비대칭 알고리즘만 받는다. 그룹 클레임(`OIDC_ROLES_CLAIM`)을 열람, 승인, 관리 세 역할로 매핑하고(`OIDC_*_GROUPS`), 어느 그룹에도 없으면 접근을 거부한다(`OIDC_DEFAULT_ROLE`로 바꿀 수 있음). 읽기는 열람, 결정 기록과 내보내기와 함께 검증은 승인 역할이 필요하고 검사는 서버가 한다. 로그인 상태의 결정은 세션의 이름과 계정(`by_id`)으로 기록하고 화면에서 넘어온 이름은 무시한다. 세션은 서버 비밀값으로 서명한 쿠키(HttpOnly, SameSite=Lax, 8시간)여서 API 프로세스끼리 공유할 저장소가 필요 없다. 다른 사이트에서 보낸 쓰기 요청은 Origin으로 거부한다. `TRIAGE_AUTH=off`(기본)는 지금까지와 같아 오프라인 시연이 그대로 돈다. 외부 송신처가 하나 늘어 규칙 6을 고쳤다(`auth.py`는 설정된 인증 서버에만, 인가 코드와 클라이언트 자격 증명만 보낸다). 의존성은 선택 항목 `auth`(PyJWT) | 채택 | 실서비스 전환 3단계. 사용자가 표준 OIDC를 선택 (2026-11-22) |
| D48 | 서비스 등록과 자동 재분류. 서비스는 저장 계층의 기록이다(식별자, 이름, 대상 경로, 서비스 맥락, 담당, 확인 주기, 현재 실행, 마지막 확인 결과). 다시 확인은 대상을 다시 스캔해(①~④, 모델 호출 없음) 현재 실행과 규칙 버킷끼리 비교한다. 변경으로 치는 것은 새 취약점, 사라진 취약점, 규칙 버킷 이동, KEV 등재, 수정 버전 공개이고, 버킷 안에서 점수만 움직인 것은 변경이 아니다. 달라진 것이 없으면 실행을 만들지 않고 확인 시각만 남긴다. 달라졌으면 새 실행을 만들고, 움직이지 않은 항목의 AI 판단은 이전 실행의 기록된 답(`agent_answers.json`)을 현재 계약 검사로 재생해 가져온다. 새로 생기거나 움직인 항목은 규칙 결과로 두고 사람이 `triage agent --changed`로 AI 판단을 시작한다(비용이 드는 일은 자동으로 하지 않는다). 샌드박스 검증과 승인 기록은 실행에 속하므로 새 실행으로 옮기지 않는다. KEV에 새로 오르거나 NOW, NEXT에 새로 들어온 항목이 있으면 Slack 알림을 보낸다. 다시 확인은 작업(`service_check`)이고 작업자가 1분마다 주기가 지난 서비스를 대기열에 넣는다(리플레이 모드에서는 넣지 않는다). 서비스의 작업은 `svc-<id>`라는 이름으로 대기열에 들어가 서비스당 하나만 돈다. 화면 등록은 관리 역할, 다시 확인은 승인 역할이 필요하고 화면에서 등록하는 경로는 `TRIAGE_SERVICE_ROOTS` 아래로 제한한다(심볼릭 링크를 푼 뒤 검사). 원격 저장소를 받아 오는 기능은 넣지 않았다(외부 송신처가 늘어난다) | 채택 | 실서비스 전환 4단계 (2026-11-23) |
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
[담당자] ─검토·조치 승인─▶ [React 대시보드] ─분석 요청·SSE─▶ [FastAPI 오케스트레이터] ──▶ [실행 결과 저장소 out/<run_id>]
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
  - `upgrade_direct`: `npm install <pkg>@<ver> --package-lock-only --ignore-scripts`
  - `override_transitive`: `package.json`에 `overrides` 추가
  - 공통: lockfile에서 기존 버전 항목 제거 → `npm install --package-lock-only` → `npm install --ignore-scripts`. `npm ci`는 조치 후 실패할 수 있다 (`docs/poc-results.md`)
- 데모 환경에 Docker가 없을 가능성 대비: 검증 결과는 사전 실행분을 `out/`에 저장하고 리플레이 모드에서 재생 (N1)

### 6.7 LLM / 에이전트

- Anthropic API tool use, 모델명은 `.env`의 `LLM_MODEL`로 주입 (하드코딩 금지). 기본값 `claude-opus-5-5` (D34)
- 항목당 tool call 최대 6회, 출력은 Pydantic 검증 → 실패 시 오류 메시지 붙여 1회 재시도 → 재실패 시 규칙 결과 fallback
- **근거 사실성 검증**: `rationale`에서 숫자(CVSS, EPSS, 버전 문자열)를 추출해 `Finding` 값과 대조하는 테스트 필수
- LLM 호출은 어댑터(`agent/llm.py`)로 분리 — 온프레미스 시 사내 LLM 교체 대비 (5.8)
- 외부 전송 데이터: CVE/GHSA ID, 패키지명·버전, 보강 수치, **필요한 코드 조각만**. 레포 전체 전송 금지.

### 6.8 점수 규칙 (초안, REQUIREMENTS F5 그대로)

```
risk (0~100) = severity×25 + exploit×25 + exposure×50
  severity = CVSS/10
  exploit  = 1.0 if KEV else max(0, (EPSS 백분위 - 0.8) / 0.2) (없으면 상수, 근거에 명시. D38)
  exposure = scope_w × path_w × reach_w
      scope_w : prod 1.0 / dev 0.2
      path_w  : direct 1.0 / transitive 0.7
      reach_w : used_symbol 1.0 / imported_only 0.6 / unused 0.2 / unknown 0.6
                소스가 없어서 unknown이면 0.4 (D38)
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
| **T4** | P0 Setup: `backend/` uv 프로젝트, `models.py`(5.2 포함), `web/` Vite + React, `tests/` 뼈대, `.env.example`, Syft·Docker 설치 확인 | HARNESS P0 게이트 통과 |
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
