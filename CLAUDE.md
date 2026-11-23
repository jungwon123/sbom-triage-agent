# CLAUDE.md — SBOM Triage Agent

> 이 파일은 **무엇을 만드는지와 지켜야 할 규칙**(context)이다.
> **어떻게 진행하는지**(단계·게이트·검증 루프)는 `HARNESS.md`를 따른다.
> 요구사항 원본은 `docs/REQUIREMENTS.md`. 충돌 시 REQUIREMENTS > CLAUDE > HARNESS 순.

## 1. 프로젝트 한 줄

npm 레포의 취약점을 CVSS 목록이 아니라 **NOW / NEXT / MONITOR** 3개 버킷으로 나누고, 항목별 근거와 샌드박스에서 검증된 조치안을 주는 에이전트. 롯데 AX 해커톤(롯데이노베이트 과제), 1~2일 1인 개발, 작동 프로토타입 + 발표.

## 2. 스택

| 영역 | 선택 |
|---|---|
| 파이프라인·에이전트 | Python 3.12, uv, Pydantic v2, httpx |
| API | FastAPI (SSE로 진행 로그 스트리밍) |
| LLM | Anthropic API (tool use), 기본 모델 **Claude Opus 5.5 (`claude-opus-5-5`)**. `.env`의 `LLM_PROVIDER`·`LLM_MODEL`로 주입하고 코드에 하드코딩하지 않는다. 본선 대비로 OpenAI 어댑터도 둔다 (HANDOFF D34) |
| 외부 데이터 | Syft, OSV API, FIRST EPSS API, CISA KEV JSON |
| 검증 샌드박스 | Docker (일회용 컨테이너) |
| 대시보드 | React (Vite) + TypeScript + Tailwind. 빌드 결과물을 FastAPI가 정적 서빙 (운영에 Node 서버 없음) |
| 저장소 | 저장 계층(`store/`) 뒤에 구현 두 개. `file`(기본, `out/<run_id>/`와 `fixtures/cache`의 JSON)은 오프라인 시연과 테스트용, `postgres`는 운영용. `TRIAGE_STORE`와 `DATABASE_URL`로 고른다. SBOM, 로그, 패치 같은 큰 산출물은 두 모드 모두 `out/<run_id>/`에 둔다 (HANDOFF D45) |
| 테스트 | pytest (백엔드), 타입체크 `tsc --noEmit` (프론트) |

## 3. 디렉터리

```
sbom-triage/
├─ CLAUDE.md / HARNESS.md
├─ docs/REQUIREMENTS.md
├─ backend/
│  └─ triage/
│     ├─ ingest.py       # 입력 형식 판별과 변환: lock 파일, 스캐너 결과, CycloneDX XML, SPDX tag-value, 표와 JSON 목록 → Component
│     ├─ sbom.py         # ① Syft 실행 + lockfile fallback
│     ├─ scan.py         # ② SBOM 컴포넌트 → OSV querybatch → Finding
│     ├─ enrich/         # ③ epss.py, kev.py, semver.py, usages.py(Python 파일 순회)
│     ├─ score.py        # ④ 규칙 점수 (순수 함수)
│     ├─ agent/          # ⑤ llm.py(인터페이스), llm_anthropic.py, llm_openai.py, llm_replay.py, tools.py, prompts.py, run.py
│     ├─ verify/         # ⑥ sandbox.py(Docker), apply.py(명령 조립), run.py(판정)
│     ├─ models.py       # Finding, Triage, Remediation, Verification (단일 진실 원천)
│     ├─ store/          # 저장 계층: base.py(인터페이스), files.py, postgres.py, schema.sql, migrate.py(파일 → DB 가져오기)
│     ├─ cache.py        # 외부 응답 캐시 (저장 계층 경유)
│     ├─ runner.py       # 단계 호출 순서와 이벤트 기록 (CLI·API 공용)
│     ├─ eval.py         # golden 일치율, NOW 누락
│     ├─ decide.py       # 수정안 목록, 담당자 결정 기록, 승인분 내보내기 (원본 레포는 건드리지 않음)
│     ├─ jobs.py         # 화면에서 시작하는 느린 작업의 큐. 작업은 저장 계층의 기록이고 작업자(`triage worker`)가 가져가 실행한다
│     ├─ services.py     # 서비스 등록과 자동 재분류: 다시 스캔해 현재 실행과 비교하고, 달라졌을 때만 새 실행을 만든다 (모델 호출 없음)
│     ├─ notify.py       # Slack 호환 웹훅 알림 (코드 없이 요약만)
│     ├─ auth.py         # 로그인(OIDC)과 역할(열람, 승인, 관리), 서명된 세션 쿠키. `TRIAGE_AUTH=off`가 기본
│     ├─ doctor.py       # 환경 점검
│     └─ api.py          # FastAPI
├─ web/                  # ⑦ React(Vite) 대시보드
├─ Dockerfile            # API와 작업자가 함께 쓰는 이미지 (.dockerignore가 .env, out/, 대상 레포를 뺀다)
├─ deploy/               # docker-compose.yml (PostgreSQL), k8s/ (쿠버네티스 매니페스트, k8s/README.md 참고)
├─ kit/                  # 본선용 하네스 키트 (절차서, 문서 틀, 점검 스크립트). kit/README.md 참고
├─ scripts/gen_types.py  # 스키마에서 프론트 타입 생성
├─ fixtures/
│  ├─ demo-repo/         # 데모 대상 레포 체크아웃 (git 제외)
│  ├─ demo-repo.ref      # 데모 레포 URL과 고정 커밋
│  ├─ eval-repos.ref     # 평가용 공개 레포 URL과 고정 커밋
│  ├─ golden.yaml        # 사람이 라벨링한 정답 버킷
│  └─ cache/             # 외부 API 응답 스냅샷 (리플레이용)
├─ out/.services/, out/svc-<id>/   # 파일 모드의 서비스 등록 기록과 서비스별 작업 대기열
└─ out/<run_id>/         # sbom.cdx.json, findings.json, triage.json, agent_log.jsonl, events.jsonl, verify/(*.patch 포함), decisions.jsonl, export/
```

## 4. 절대 규칙

1. **스키마가 먼저다.** `models.py`가 백엔드·프론트·에이전트 출력의 단일 진실 원천. 필드를 바꾸면 `web/src/lib/types.ts`도 같은 커밋에서 바꾼다. `types.ts`는 `uv run python scripts/gen_types.py`로 생성한다(손으로 고치지 않는다).
2. **규칙과 LLM의 경계를 지킨다.** 점수 계산은 `score.py`의 순수 함수로만. LLM 출력 타입은 점수 필드가 없는 `AgentVerdict`이고 `Triage`는 코드가 조립한다. LLM은 `rule_bucket`을 **±1단계까지만** 조정하며 조정 시 `override_reason` 필수. KEV 하향 금지 등 안전장치(F6-9)는 코드가 강제한다.
3. **근거는 데이터에서만.** 에이전트 `rationale`의 숫자(CVSS, EPSS, 버전)는 `{cvss}` 같은 자리표시자로 쓰고 코드가 `Finding` 값으로 채운다. 자리표시자가 아닌 수치는 검증 테스트가 잡는다.
4. **에이전트는 읽기 전용.** tools는 레포 밖 경로 접근 금지, 파일 쓰기·명령 실행 금지. 샌드박스는 에이전트가 아니라 `runner.py`가 호출한다. 변경은 샌드박스 컨테이너 안의 복사본에만 적용되며, 원본 레포 반영·커밋·PR은 사람 승인 후 별도 경로.
5. **LLM 출력을 실행하지 않는다.** 레포 코드와 어드바이저리는 신뢰할 수 없는 입력이다. 샌드박스 명령은 검증된 `kind`·`package`·`to_version`으로 `verify/apply.py`가 조립한다.
6. **외부 조회는 전부 `cache.py` 경유.** 외부로 보내는 것은 LLM 어댑터, `notify.py`(알림), `auth.py`(로그인)뿐이다. `auth.py`는 `TRIAGE_AUTH=oidc`일 때만 설정된 인증 서버에 인가 코드와 클라이언트 자격 증명을 보내고 분석 데이터는 싣지 않는다 (HANDOFF D47). 알림은 소스코드를 싣지 않는다. LLM 어댑터는 단일 모드에서 에이전트가 읽은 코드 조각을 싣고, 2단계 모드(규칙 9)에서는 코드, 파일 이름, 빌드와 테스트 로그를 싣지 않는다. 에이전트는 `.env` 같은 자격 증명 파일을 읽지 못한다. 데모는 `DEMO_MODE=replay`에서 네트워크와 Docker 없이 돌아가야 한다.
7. **비밀값은 `.env`.** 코드·로그·`out/`에 API 키를 남기지 않고, 샌드박스 컨테이너에도 전달하지 않는다.
11. **권한 검사는 서버가 한다.** `/api/health`와 `/api/me`를 뺀 모든 API 경로는 `auth.py`의 역할 의존성(`auth.viewer`, `auth.approver`, `auth.admin`)을 단다. 읽기는 열람, 결정 기록과 내보내기와 작업 시작(서비스 다시 확인 포함)은 승인, 서비스 등록과 해제는 관리 역할이 필요하다. 화면에서 등록하는 대상 경로는 `TRIAGE_SERVICE_ROOTS` 아래로 제한한다 (HANDOFF D48). 로그인이 켜져 있으면 결정의 이름은 세션에서 가져오고 요청 본문의 이름은 무시한다. 화면에서 버튼을 숨기는 것은 안내일 뿐이다. 시연은 `TRIAGE_AUTH=off`에서 돌아가야 한다 (HANDOFF D47, `tests/test_auth.py`).
8. **P0 먼저.** REQUIREMENTS의 P0가 전부 끝나기 전에는 P1을 시작하지 않는다.
10. **두 저장 모드가 같은 동작을 해야 한다.** 기록(실행 정보, Finding, Triage, 결정, 이벤트, 캐시, 작업)은 `store/`의 인터페이스로만 읽고 쓴다. 저장 방식을 바꾸는 변경은 `tests/test_store.py`에서 파일과 PostgreSQL 양쪽으로 확인한다. 시연은 파일 모드에서 네트워크, Docker, DB 없이 돌아가야 한다 (HANDOFF D45). 작업의 입력은 값으로만 넘긴다(함수나 객체를 넘기지 않는다). API 프로세스는 작업을 기록만 하고 실행은 작업자가 한다 (HANDOFF D46).
9. **코드 판독 모델과 작성 모델의 경계.** `LLM_CODE_PROVIDER`가 설정되면(2단계 모드) 소스코드와 파일 이름은 그 모델에만 전달한다. 작성 모델의 프롬프트는 `prompts.writer_prompt`로만 만들고 도구를 주지 않는다 (HANDOFF D35, `tests/test_two_stage.py`).

## 5. 코드 컨벤션

- Python: 타입힌트 필수, I/O 함수와 순수 함수 분리, 모듈 하나가 파이프라인 한 단계.
- 에러: 외부 데이터 누락은 예외가 아니라 `None` + 로그. 파이프라인은 한 항목 실패로 멈추지 않는다.
- 프론트: 데이터는 전부 FastAPI API로 읽고 `out/`을 직접 읽지 않는다. 실행 선택은 `?run=<id>` 쿼리. 버킷 색은 NOW=red, NEXT=amber, MONITOR=slate 고정.
- 커밋: `feat(score): …`, `fix(agent): …` — 단계 이름을 scope로. 커밋 메시지와 PR 본문에 AI 기여자 표기(`Co-Authored-By`, "Generated with …")를 넣지 않는다.

## 6. 자주 쓰는 명령

```bash
uv run python -m triage doctor                         # 환경 점검 (--llm: LLM 호출 1회 확인)
uv run python -m triage scan fixtures/demo-repo        # ①~④ (레포 디렉터리)
uv run python -m triage scan path/to/bom.cdx.json      # ①~④ (파일 입력: SBOM, 스캐너 결과, lock 파일, 표. 표는 --columns name=<열>,version=<열> --ecosystem npm)
uv run python -m triage inspect data                   # 파일이나 폴더가 무슨 형식이고 읽을 수 있는지 (읽기 전용)
uv run python -m triage seed --kev kev.json --epss epss.csv.gz   # 받은 취약점 데이터 파일을 넣어 네트워크 없이 사용
uv run python -m triage run fixtures/demo-repo --setup "npx prisma generate"   # ①~⑥ 한 번에
uv run python -m triage agent out/<run_id>             # ⑤
docker compose -f deploy/docker-compose.yml up -d postgres   # 운영 저장소 띄우기 (로컬은 127.0.0.1:54329)
docker build -t sbom-triage:dev .                      # API와 작업자 이미지
kubectl kustomize deploy/k8s/overlays/local            # 쿠버네티스 매니페스트 렌더링 (올리기: kubectl apply -k, 절차는 deploy/k8s/README.md)
uv run python -m triage db init                        # 테이블 생성 (DATABASE_URL 필요, 여러 번 실행해도 안전)
uv run python -m triage db import --cache              # 파일로 쌓인 실행과 캐시를 DB로 복사 (db status로 건수 확인)
uv run python -m triage worker                         # 대기 중인 작업을 실행하는 작업자 (PostgreSQL 모드에서 필요, --once는 큐를 비우고 종료)
uv run python -m triage services add shop fixtures/demo-repo --name 쇼핑몰 --every 24   # 서비스 등록 (--baseline out/<run_id>로 기존 실행을 현재 실행으로 지정, --every 0은 요청할 때만)
uv run python -m triage services check --due           # 주기가 지난 서비스를 다시 스캔해 비교 (작업자가 떠 있으면 자동, <id>나 --all도 가능, list와 remove도 있음)
uv run python -m triage agent out/<run_id> --changed   # 다시 확인에서 새로 생기거나 움직인 항목만 AI 판단
uv run python -m triage rescore out/<run_id>           # 규칙이나 검사를 바꾼 뒤 저장된 실행을 현재 코드에 맞춤 (모델 호출 없음)
uv run python -m triage verify out/<run_id>            # ⑥ NOW 항목 샌드박스 검증 (--buckets NOW,NEXT로 범위 확대)
uv run python -m triage decide out/<run_id> body-parser@1.20.2 approved --by 홍길동   # 담당자 결정 기록 (rejected, held는 --reason 필수)
uv run python -m triage export out/<run_id>            # 승인한 변경의 패치와 PR 초안을 out/<run_id>/export/에 생성 (푸시 없음, --together면 승인분을 함께 검증해 패치 하나로)
uv run python -m triage eval out/<run_id>              # golden 일치율
uv run python -m triage compare out/<run_id> --configs rule,api,local,split   # LLM 구성별 비교
uv run python -m triage notify out/<run_id> --dry-run   # Slack 알림 미리 보기 (--dry-run 빼면 전송)
DEMO_MODE=replay uv run uvicorn triage.api:app         # 오프라인 시연
cd web && pnpm dev                                      # 개발 서버 (API는 8000번으로 프록시)
cd web && pnpm build                                    # web/dist 생성, FastAPI가 정적 서빙
uv run python scripts/gen_types.py                      # models.py → web/src/lib/types.ts
bash kit/scripts/check.sh                               # 규칙, 테스트, 리플레이, git 점검
uv run pytest -q
```

## 7. 용어

| 용어 | 뜻 |
|---|---|
| Finding | 취약점 1건 × 패키지@버전 (경로가 여러 개여도 1건) |
| reachability | `used_symbol` / `imported_only` / `unused` / `unknown` |
| bump | 수정 버전까지의 semver 점프: `patch` / `minor` / `major` / `none` |
| golden set | 사람이 직접 매긴 정답 버킷. 데모 레포 10~15건 + 평가 레포 각 5건 |
| NOW 누락 | golden이 NOW인데 최종 버킷이 MONITOR인 건. 목표 0건 |
| 기준선 | 조치 전 install/build/test 결과. 조치 후 결과와 비교해 회귀를 판정 |
| 서비스 맥락 | `service_criticality`·`internet_facing`. 근거·표시 전용이며 점수에 넣지 않는다 |
| verdict | 검증 판정: `verified` / `failed` / `inconclusive` (REQUIREMENTS F8) |
