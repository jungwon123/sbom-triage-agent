# AGENTS.md — Codex와 그 밖의 코딩 에이전트용

이 파일 하나로 작업을 시작할 수 있게 썼다. 자세한 규칙은 `CLAUDE.md`(무엇을 만들고 무엇을 지키는가), 진행 방식은 `HARNESS.md`, 결정 이력은 `HANDOFF.md`(D1 ~ D49)에 있다. 충돌하면 현장 과제 안내 → `docs/REQUIREMENTS.md` → `CLAUDE.md` → `HARNESS.md` → `kit/` 순서로 따른다.

## 1. 한 줄 요약

저장소나 SBOM의 취약점을 CVSS 목록이 아니라 NOW, NEXT, MONITOR 세 버킷으로 나누고, 항목별 근거와 샌드박스에서 검증한 조치안을 주는 에이전트다. 롯데 AX 챌린지 본선(2026-11-24 ~ 25) 과제용이며 파이프라인은 이미 구현되어 있다. 현장에서는 과제와 자료에 맞추는 작업만 한다.

## 2. 시작

```bash
uv sync --extra openai --extra postgres --extra auth   # 필요한 것만 골라도 된다
uv run python -m triage doctor                         # 환경 점검 (--llm: 모델 호출 1회)
uv run pytest -q                                       # 바꾸기 전과 후에 돌린다
bash kit/scripts/check.sh --fast                       # 절대 규칙 정적 점검
```

본선 당일의 첫 지시는 `kit/START.md 읽고 그대로 해.`이다.

## 3. 하지 않는 일 (Claude Code에서는 설정이 막지만 Codex에서는 이 목록이 유일한 장치다)

1. `.env`를 읽거나 출력하지 않는다. 키 값은 코드, 로그, `out/`, 대화 어디에도 남기지 않는다.
2. `data/`(현장 제공 자료), `fixtures/demo-repo/`, `fixtures/eval/`, `.data_manifest.sha256`를 수정하지 않는다. 읽기만 한다.
3. `git push --force`, `git reset --hard`, `rm -rf`를 쓰지 않는다. 원격 push는 사람이 시킬 때만 한다.
4. 사람이 시키기 전에는 커밋하지 않는다. 커밋 메시지와 PR 본문에 AI 기여자 표기(`Co-Authored-By`, "Generated with ...")를 넣지 않는다.
5. 비용이 드는 일(API 모델을 30건 넘게 호출)은 먼저 묻는다.
6. 사용자의 앱(Docker Desktop 등)을 끄거나 다시 띄우지 않는다.
7. 실제 데모 실행(`out/20261118-030615-realworld`)에 결정(승인)을 기록하지 않는다. 확인은 사본으로 한다.

## 4. 절대 규칙 (요약, 원문은 `CLAUDE.md` 4장)

1. **스키마가 먼저다.** `backend/triage/models.py`를 바꾸면 같은 커밋에서 `uv run python scripts/gen_types.py`로 `web/src/lib/types.ts`를 다시 만든다. 손으로 고치지 않는다.
2. **규칙과 LLM의 경계.** 점수는 `score.py`의 순수 함수만 낸다. LLM은 규칙 버킷을 한 단계까지만 옮기고 이유를 적는다. KEV 하향 금지 같은 안전장치는 코드가 강제한다.
3. **근거의 숫자는 데이터에서만.** LLM은 `{cvss}` 같은 자리표시자를 쓰고 코드가 값을 채운다.
4. **에이전트는 읽기 전용.** 도구는 저장소 밖을 읽지 못하고 쓰기와 명령 실행이 없다.
5. **LLM 출력을 실행하지 않는다.** 샌드박스 명령은 `verify/apply.py`가 검증된 값으로 조립한다.
6. **외부 조회는 `cache.py` 경유.** 밖으로 보내는 것은 LLM 어댑터, `notify.py`, `auth.py`뿐이다. `DEMO_MODE=replay`에서는 네트워크와 Docker 없이 돌아야 한다.
7. **비밀값은 `.env`.**
8. **P0 먼저.**
9. **2단계 모드에서는 소스코드와 파일 이름을 코드 판독 모델에만 준다.**
10. **기록은 `store/` 인터페이스로만 읽고 쓴다.** 파일과 PostgreSQL 두 모드가 같은 동작을 해야 한다(`tests/test_store.py`).
11. **권한 검사는 서버가 한다.** `/api/health`, `/api/me`를 뺀 모든 API 경로에 `auth.viewer`, `auth.approver`, `auth.admin` 가운데 하나가 달린다.

절대 규칙을 건드리는 요청(예: AI가 점수를 내게 하기, AI가 쓴 명령 실행, 대상 저장소 수정)은 하지 않고 이유를 말한다.

## 5. 절차서 (Claude Code의 스킬에 해당)

Codex에는 스킬 기능이 없으므로 아래 파일을 직접 읽고 그 절차대로 한다. "○○ 스킬로"라는 지시는 이 표의 파일을 뜻한다.

| 언제 | 읽을 파일 |
|---|---|
| 과제 문서를 받은 직후 | `kit/claude/skills/task-intake/SKILL.md` |
| 자료를 받은 직후 | `kit/claude/skills/data-check/SKILL.md` |
| 자료 형식이 읽히지 않을 때 | `kit/claude/skills/adapt-input/SKILL.md` |
| AI 판단을 돌린 뒤, 규칙이나 프롬프트를 바꾼 뒤 | `kit/claude/skills/agent-eval/SKILL.md` |
| 샌드박스 검증 | `kit/claude/skills/verify-run/SKILL.md` |
| 시연 준비 | `kit/claude/skills/demo/SKILL.md` |
| 중간 점검과 제출 직전 점검 | `kit/claude/skills/review/SKILL.md` |
| 대화가 길어졌을 때, 도구를 바꿀 때 | `kit/claude/skills/handoff/SKILL.md` |

서브에이전트도 없다. `data-scout`(자료 요약)와 `reviewer`(점검)의 일은 `kit/claude/agents/*.md`의 지시를 읽고 직접 하되, 그 일을 하는 동안에는 파일을 고치지 않는다.

`kit/PLAYBOOK.md`와 `kit/prompts.md`는 사람용이므로 읽지 않는다.

## 6. 자료가 어떤 형식으로 오든

먼저 실제 코드로 판별한다. 파일을 통째로 열어 대화에 붙이지 않는다.

```bash
uv run python -m triage inspect data                   # 폴더 전체: 파일마다 형식, 지원 여부, 컴포넌트 수, 빠진 정보
uv run python -m triage inspect data/list.csv --columns name=제품명,version=버전 --ecosystem npm
uv run python -m triage scan data/<파일 또는 저장소>   # 읽히면 바로 스캔
```

| 자료 | 처리 |
|---|---|
| 저장소 | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `pom.xml`, `gradle.lockfile`, `requirements*.txt`, `poetry.lock`, `uv.lock`, `Pipfile.lock`, `go.mod`, `Cargo.lock`, `Gemfile.lock`, `composer.lock`, `packages.lock.json`을 읽는다. 루트에 없으면 세 단계 아래까지 찾아 합친다 |
| SBOM | CycloneDX JSON과 XML, SPDX JSON과 tag-value |
| 스캐너 결과 | Trivy, Grype, OSV-Scanner, Snyk, OWASP Dependency-Check의 JSON. 스캐너가 보고한 취약점은 OSV에 없거나 OSV에 닿지 못해도 남는다 |
| 표, 처음 보는 JSON | CSV, TSV, 객체 배열 JSON. 열 이름으로 추측하고(한글 포함), 안 맞으면 `--columns`로 지정한다. 파서를 새로 쓰기 전에 이 방법부터 쓴다 |
| 네트워크가 막힌 곳 | `uv run python -m triage seed --kev <파일> --epss <파일>`로 받은 취약점 데이터를 넣고 `DEMO_MODE=replay`로 돈다 |
| 위 어디에도 안 맞음 | `inspect`가 이유와 다음 행동을 말한다. 그래도 안 되면 `adapt-input` 절차로 `backend/triage/ingest.py`에 파서를 추가한다(테스트 먼저) |

읽지 못한 것은 조용히 버리지 않는다. 뺀 행 수, 없는 정보(의존 관계, 운영과 개발 구분)는 실행 기록의 `coverage.input_notes`와 `coverage.unsupported`에 남고 발표에서도 그대로 말한다.

## 7. 구조

```
backend/triage/
  ingest.py        입력 형식 판별과 변환 (lock 파일, 스캐너 결과, SBOM 변형, 표)
  sbom.py          ① SBOM (Syft, lock 파일, 파일 입력)
  scan.py          ② OSV 조회와 ③ 보강 → Finding
  enrich/          EPSS, KEV, semver, import 검색
  score.py         ④ 규칙 점수 (순수 함수)
  agent/           ⑤ LLM 판단 (어댑터: anthropic, openai, local, replay)
  verify/          ⑥ Docker 샌드박스 검증
  runner.py        단계 순서와 이벤트 기록 (CLI와 API 공용)
  services.py      서비스 등록과 자동 재분류
  decide.py        수정안, 결정, 내보내기
  jobs.py          작업 큐와 작업자
  store/           저장 계층 (file, postgres)
  auth.py          로그인(OIDC)과 역할
  api.py           FastAPI
web/               React 대시보드 (빌드 결과를 FastAPI가 서빙)
kit/               본선 하네스 키트 (절차서, 문서 틀, 점검 스크립트)
docs/finals/       본선 문서 (TASK, GAP, DATA_NOTES, DECISIONS, HANDOFF, ...)
```

자주 쓰는 명령은 `CLAUDE.md` 6장에 있다.

## 8. 일하는 방식

- 한 번에 파이프라인 한 단계만 고친다. 파일 3개 이상을 바꾸는 작업은 계획 3줄을 먼저 보고하고 사람이 "진행"이라고 한 뒤 구현한다.
- 테스트를 먼저 쓴다. 현장 자료의 실제 사례 2 ~ 3건을 필요한 필드만 줄여 `tests/`에 넣는다. 원본 파일을 복사하지 않는다.
- 외부 데이터가 없으면 예외로 멈추지 않고 `None`으로 두고 `Finding.missing`에 이름을 넣는다.
- 측정하지 않은 수치는 말하지 않는다. 발표 수치는 `uv run python kit/scripts/evidence.py`가 만든 `out/evidence.md`에 있어야 한다.
- 범위, 점수 기준, LLM 제공자는 사람이 정한다. 선택지를 내고 멈춘다. 정한 이유는 `docs/finals/DECISIONS.md`에 남긴다.
- 커밋 형식은 `feat(score): ...`, `fix(agent): ...`처럼 단계 이름을 scope로 쓴다.
- 사용자에게 보이는 한국어 문장은 합니다체로 쓰고 가운뎃점과 줄표(em dash)를 쓰지 않는다. 번호 목록으로 정리한다.
- 작업을 넘길 때는 `handoff` 절차로 `docs/finals/HANDOFF.md`를 갱신한다. 다음 세션은 그 파일과 `git log --oneline -10`부터 읽는다.

## 9. LLM 설정

모델과 제공자는 `.env`의 `LLM_PROVIDER`, `LLM_MODEL`로 주입하고 코드에 모델명을 쓰지 않는다. 기본은 Anthropic(`claude-opus-5-5`)이고 OpenAI 어댑터(`backend/triage/agent/llm_openai.py`)가 있다. OpenAI 어댑터는 실제 호출로 확인하지 않았으므로 처음 쓸 때 `uv run python -m triage doctor --llm`부터 돌린다. 30분 안에 안 되면 `LLM_PROVIDER=none`(규칙만)으로 한 줄기를 먼저 완성한다.
