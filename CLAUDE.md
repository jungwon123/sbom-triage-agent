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
| 저장소 | 프로토타입은 파일(`out/<run_id>/`). DB 없음, 운영 설계는 PostgreSQL (HANDOFF D32) |
| 테스트 | pytest (백엔드), 타입체크 `tsc --noEmit` (프론트) |

## 3. 디렉터리

```
sbom-triage/
├─ CLAUDE.md / HARNESS.md
├─ docs/REQUIREMENTS.md
├─ backend/
│  └─ triage/
│     ├─ sbom.py         # ① Syft 실행 + lockfile fallback
│     ├─ scan.py         # ② SBOM 컴포넌트 → OSV querybatch → Finding
│     ├─ enrich/         # ③ epss.py, kev.py, semver.py, usages.py(Python 파일 순회)
│     ├─ score.py        # ④ 규칙 점수 (순수 함수)
│     ├─ agent/          # ⑤ llm.py(인터페이스), llm_anthropic.py, llm_openai.py, llm_replay.py, tools.py, prompts.py, run.py
│     ├─ verify/         # ⑥ sandbox.py(Docker), apply.py(명령 조립), run.py(판정)
│     ├─ models.py       # Finding, Triage, Remediation, Verification (단일 진실 원천)
│     ├─ cache.py        # 외부 응답 디스크 캐시
│     ├─ runner.py       # 단계 호출 순서와 이벤트 기록 (CLI·API 공용)
│     ├─ eval.py         # golden 일치율, NOW 누락
│     ├─ decide.py       # 수정안 목록, 담당자 결정 기록, 승인분 내보내기 (원본 레포는 건드리지 않음)
│     ├─ jobs.py         # 화면에서 시작하는 느린 작업의 큐 (작업자 1개, 상태는 out/<run>/jobs/)
│     ├─ notify.py       # Slack 호환 웹훅 알림 (코드 없이 요약만)
│     ├─ doctor.py       # 환경 점검
│     └─ api.py          # FastAPI
├─ web/                  # ⑦ React(Vite) 대시보드
├─ kit/                  # 본선용 하네스 키트 (절차서, 문서 틀, 점검 스크립트). kit/README.md 참고
├─ scripts/gen_types.py  # 스키마에서 프론트 타입 생성
├─ fixtures/
│  ├─ demo-repo/         # 데모 대상 레포 체크아웃 (git 제외)
│  ├─ demo-repo.ref      # 데모 레포 URL과 고정 커밋
│  ├─ eval-repos.ref     # 평가용 공개 레포 URL과 고정 커밋
│  ├─ golden.yaml        # 사람이 라벨링한 정답 버킷
│  └─ cache/             # 외부 API 응답 스냅샷 (리플레이용)
└─ out/<run_id>/         # sbom.cdx.json, findings.json, triage.json, agent_log.jsonl, events.jsonl, verify/(*.patch 포함), decisions.jsonl, export/
```

## 4. 절대 규칙

1. **스키마가 먼저다.** `models.py`가 백엔드·프론트·에이전트 출력의 단일 진실 원천. 필드를 바꾸면 `web/src/lib/types.ts`도 같은 커밋에서 바꾼다. `types.ts`는 `uv run python scripts/gen_types.py`로 생성한다(손으로 고치지 않는다).
2. **규칙과 LLM의 경계를 지킨다.** 점수 계산은 `score.py`의 순수 함수로만. LLM 출력 타입은 점수 필드가 없는 `AgentVerdict`이고 `Triage`는 코드가 조립한다. LLM은 `rule_bucket`을 **±1단계까지만** 조정하며 조정 시 `override_reason` 필수. KEV 하향 금지 등 안전장치(F6-9)는 코드가 강제한다.
3. **근거는 데이터에서만.** 에이전트 `rationale`의 숫자(CVSS, EPSS, 버전)는 `{cvss}` 같은 자리표시자로 쓰고 코드가 `Finding` 값으로 채운다. 자리표시자가 아닌 수치는 검증 테스트가 잡는다.
4. **에이전트는 읽기 전용.** tools는 레포 밖 경로 접근 금지, 파일 쓰기·명령 실행 금지. 샌드박스는 에이전트가 아니라 `runner.py`가 호출한다. 변경은 샌드박스 컨테이너 안의 복사본에만 적용되며, 원본 레포 반영·커밋·PR은 사람 승인 후 별도 경로.
5. **LLM 출력을 실행하지 않는다.** 레포 코드와 어드바이저리는 신뢰할 수 없는 입력이다. 샌드박스 명령은 검증된 `kind`·`package`·`to_version`으로 `verify/apply.py`가 조립한다.
6. **외부 조회는 전부 `cache.py` 경유.** 외부로 보내는 것은 LLM 어댑터와 `notify.py`(알림)뿐이다. 알림은 소스코드를 싣지 않는다. LLM 어댑터는 단일 모드에서 에이전트가 읽은 코드 조각을 싣고, 2단계 모드(규칙 9)에서는 코드, 파일 이름, 빌드와 테스트 로그를 싣지 않는다. 에이전트는 `.env` 같은 자격 증명 파일을 읽지 못한다. 데모는 `DEMO_MODE=replay`에서 네트워크와 Docker 없이 돌아가야 한다.
7. **비밀값은 `.env`.** 코드·로그·`out/`에 API 키를 남기지 않고, 샌드박스 컨테이너에도 전달하지 않는다.
8. **P0 먼저.** REQUIREMENTS의 P0가 전부 끝나기 전에는 P1을 시작하지 않는다.
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
uv run python -m triage scan path/to/bom.cdx.json      # ①~④ (SBOM 파일: CycloneDX 또는 SPDX JSON)
uv run python -m triage run fixtures/demo-repo --setup "npx prisma generate"   # ①~⑥ 한 번에
uv run python -m triage agent out/<run_id>             # ⑤
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
