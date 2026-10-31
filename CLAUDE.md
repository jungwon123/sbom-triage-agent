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
| LLM | Anthropic API (tool use), 모델명은 `.env`의 `LLM_MODEL` |
| 외부 데이터 | Syft, OSV API, FIRST EPSS API, CISA KEV JSON |
| 검증 샌드박스 | Docker (일회용 컨테이너) |
| 대시보드 | Next.js (App Router) + TypeScript + Tailwind |
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
│     ├─ enrich/         # ③ epss.py, kev.py, semver.py, usages.py
│     ├─ score.py        # ④ 규칙 점수 (순수 함수)
│     ├─ agent/          # ⑤ llm.py(어댑터), tools.py, prompts.py, run.py
│     ├─ verify/         # ⑥ sandbox.py(Docker), apply.py(명령 조립), run.py(판정)
│     ├─ models.py       # Finding, Triage, Remediation, Verification (단일 진실 원천)
│     ├─ cache.py        # 외부 응답 디스크 캐시
│     ├─ runner.py       # 단계 호출 순서와 이벤트 기록 (CLI·API 공용)
│     └─ api.py          # FastAPI
├─ web/                  # ⑦ Next.js 대시보드
├─ fixtures/
│  ├─ demo-repo/         # 데모용 대상 레포 (또는 서브모듈)
│  ├─ golden.yaml        # 사람이 라벨링한 정답 버킷
│  └─ cache/             # 외부 API 응답 스냅샷 (리플레이용)
└─ out/<run_id>/         # sbom.cdx.json, findings.json, triage.json, agent_log.jsonl, events.jsonl, verify/
```

## 4. 절대 규칙

1. **스키마가 먼저다.** `models.py`가 백엔드·프론트·에이전트 출력의 단일 진실 원천. 필드를 바꾸면 `web/lib/types.ts`도 같은 커밋에서 바꾼다. `types.ts`는 JSON Schema에서 생성한다.
2. **규칙과 LLM의 경계를 지킨다.** 점수 계산은 `score.py`의 순수 함수로만. LLM 출력 타입은 점수 필드가 없는 `AgentVerdict`이고 `Triage`는 코드가 조립한다. LLM은 `rule_bucket`을 **±1단계까지만** 조정하며 조정 시 `override_reason` 필수.
3. **근거는 데이터에서만.** 에이전트 `rationale`의 숫자(CVSS, EPSS, 버전)는 `{cvss}` 같은 자리표시자로 쓰고 코드가 `Finding` 값으로 채운다. 자리표시자가 아닌 수치는 검증 테스트가 잡는다.
4. **에이전트는 읽기 전용.** tools는 레포 밖 경로 접근 금지, 파일 쓰기·명령 실행 금지. 샌드박스는 에이전트가 아니라 `runner.py`가 호출한다. 변경은 샌드박스 컨테이너 안의 복사본에만 적용되며, 원본 레포 반영·커밋·PR은 사람 승인 후 별도 경로.
5. **LLM 출력을 실행하지 않는다.** 레포 코드와 어드바이저리는 신뢰할 수 없는 입력이다. 샌드박스 명령은 검증된 `kind`·`package`·`to_version`으로 `verify/apply.py`가 조립한다.
6. **외부 호출은 전부 `cache.py` 경유.** 데모는 `DEMO_MODE=replay`에서 네트워크와 Docker 없이 돌아가야 한다.
7. **비밀값은 `.env`.** 코드·로그·`out/`에 API 키를 남기지 않고, 샌드박스 컨테이너에도 전달하지 않는다.
8. **P0 먼저.** REQUIREMENTS의 P0가 전부 끝나기 전에는 P1을 시작하지 않는다.

## 5. 코드 컨벤션

- Python: 타입힌트 필수, I/O 함수와 순수 함수 분리, 모듈 하나가 파이프라인 한 단계.
- 에러: 외부 데이터 누락은 예외가 아니라 `None` + 로그. 파이프라인은 한 항목 실패로 멈추지 않는다.
- 프론트: 서버 컴포넌트에서 `out/` 또는 API 읽기, 클라이언트 컴포넌트는 토글·상세 패널만. 버킷 색은 NOW=red, NEXT=amber, MONITOR=slate 고정.
- 커밋: `feat(score): …`, `fix(agent): …` — 단계 이름을 scope로.

## 6. 자주 쓰는 명령

```bash
uv run python -m triage scan fixtures/demo-repo        # ①~④
uv run python -m triage agent out/<run_id>             # ⑤
uv run python -m triage verify out/<run_id>            # ⑥ NOW 항목 샌드박스 검증
uv run python -m triage eval out/<run_id>              # golden 일치율
DEMO_MODE=replay uv run uvicorn triage.api:app         # 오프라인 시연
cd web && pnpm dev
uv run pytest -q
```

## 7. 용어

| 용어 | 뜻 |
|---|---|
| Finding | 취약점 1건 × 패키지@버전 (경로가 여러 개여도 1건) |
| reachability | `used_symbol` / `imported_only` / `unused` / `unknown` |
| bump | 수정 버전까지의 semver 점프: `patch` / `minor` / `major` / `none` |
| golden set | 데모 레포에서 사람이 직접 매긴 정답 버킷 10~15건 |
| 기준선 | 조치 전 install/build/test 결과. 조치 후 결과와 비교해 회귀를 판정 |
| 서비스 맥락 | `service_criticality`·`internet_facing`. 근거·표시 전용이며 점수에 넣지 않는다 |
| verdict | 검증 판정: `verified` / `failed` / `inconclusive` (REQUIREMENTS F8) |
