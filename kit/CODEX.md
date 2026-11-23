# CODEX: Codex CLI로 시작하기 (사람용)

Codex CLI로 이 저장소의 작업을 이어 갈 때의 준비 과정입니다. 설치부터 본선 당일의 첫 문장까지 순서대로 적었습니다.

에이전트가 읽는 규칙은 `AGENTS.md`에 있고, 이 문서는 사람이 따라 하는 절차입니다.

> Codex CLI의 설치 방법과 옵션 이름은 2026-11-23에 공식 문서(github.com/openai/codex, OpenAI의 Codex 문서)에서 확인한 것입니다. 버전에 따라 달라질 수 있으니 처음에 `codex --help`로 한 번 대조합니다. 이 저장소에서 Codex를 실제로 돌려 본 기록은 아직 없습니다(5장).

## 1. 설치와 로그인

둘 중 하나로 설치합니다.

```bash
npm install -g @openai/codex
```

```bash
brew install --cask codex
```

설치를 확인합니다.

```bash
codex --version
```

처음 `codex`를 실행하면 로그인 화면이 나옵니다. "Sign in with ChatGPT"를 고르는 것이 기본 방법입니다. API 키로 쓰는 방법도 있지만 추가 설정이 필요합니다.

## 2. 저장소 준비

### 2.1 지금 쓰던 컴퓨터에서 이어 갈 때

복제할 필요가 없습니다. 기존 폴더에 `.env`, `out/`(실행 결과), `fixtures/demo-repo/`(대상 저장소), `web/dist`가 그대로 있습니다.

```bash
cd <기존 sbom-triage 폴더> && git status --short && git pull
```

### 2.2 다른 컴퓨터에서 새로 받을 때

```bash
git clone https://github.com/jungwon123/sbom-triage-agent.git
```

```bash
cd sbom-triage-agent && uv sync --extra openai --extra postgres --extra auth
```

```bash
cp .env.example .env
```

새로 받은 저장소에는 아래가 없습니다. 필요한 것만 준비합니다.

| 없는 것 | 준비 방법 | 없으면 |
|---|---|---|
| `.env`의 키와 모델 | 직접 열어 입력합니다. Codex에게 시키지 않습니다 | 규칙 결과와 재생 모드만 됩니다 |
| `web/dist` (화면) | `cd web && pnpm install && pnpm build` | 화면이 404입니다 |
| `out/` (실행 결과) | 새로 스캔하거나, 이전 컴퓨터의 `out/`을 복사합니다 | 화면이 비어 있습니다 |
| `fixtures/demo-repo/` | `README.md` 2장의 두 명령으로 받습니다 | 데모 저장소 스캔과 `check.sh`의 재생 점검이 건너뛰어집니다 |
| Docker | Docker Desktop을 띄웁니다 | 샌드박스 검증을 건너뜁니다 |
| Syft | `brew install syft` | 저장소 스캔이 lock 파일 해석으로 대체됩니다 |

### 2.3 준비가 됐는지 확인

```bash
uv run python -m triage doctor
```

```bash
uv run pytest -q
```

```bash
DEMO_MODE=replay uv run python -m triage scan fixtures/blind/sbom-a.cdx.json
```

기준: `doctor`에 실패 표시가 없고, 테스트가 전부 통과하거나 건너뛰고, 스캔이 JSON 요약으로 끝납니다. 자세한 기준은 `docs/GUIDE.md` 10장에 있습니다.

## 3. Codex 실행과 권한 설정

저장소 폴더에서 실행합니다. Codex는 저장소 루트의 `AGENTS.md`를 자동으로 읽습니다.

```bash
codex
```

권한은 두 가지로 정해집니다.

| 설정 | 옵션 | 값 | 권장 |
|---|---|---|---|
| 샌드박스 (어디까지 쓸 수 있나) | `--sandbox`, `-s` | `read-only`, `workspace-write`, `danger-full-access` | `workspace-write` |
| 승인 (언제 물어보나) | `--ask-for-approval`, `-a` | `on-request`, `never` | `on-request` |

```bash
codex --sandbox workspace-write --ask-for-approval on-request
```

- 실행 중에는 `/permissions`로 바꿉니다.
- `--dangerously-bypass-approvals-and-sandbox`(`--yolo`)는 쓰지 않습니다. 샌드박스와 승인이 모두 꺼집니다.
- Claude Code에서는 설정 파일이 `.env` 읽기, 강제 푸시, `rm -rf`를 막았습니다. Codex에는 그 장치가 없고 `AGENTS.md` 3장의 금지 목록만 있습니다. 그래서 승인을 켜 두고, 명령을 승인하기 전에 무엇을 하는지 읽습니다.

이어서 하기와 한 번만 실행하기:

```bash
codex resume --last
```

```bash
codex exec "AGENTS.md를 읽고 절대 규칙을 5줄로 요약해. 파일은 고치지 마."
```

## 4. 본선 전에 한 번 해 볼 것 (15분)

문서만으로 Codex가 일할 수 있는지 확인하는 단계입니다. 아무것도 고치지 않게 합니다.

1. 저장소 폴더에서 `codex`를 실행하고 아래 문장을 줍니다.

```
AGENTS.md를 읽고, 이 저장소가 무엇을 하는지와 절대 규칙을 5줄로 요약해. 그다음 uv run pytest -q 와 bash kit/scripts/check.sh --fast 를 돌려 결과만 보고해. 파일은 고치지 마.
```

2. 확인할 것:
   - 요약이 맞는가. 세 버킷, 규칙 점수와 AI의 경계(한 단계까지만 조정), AI가 쓴 명령을 실행하지 않는다는 점이 들어 있어야 합니다.
   - 두 명령이 승인 요청을 거쳐 실행되고 통과하는가.
   - `.env`를 읽으려 하지 않는가.
3. 이어서 고치지 않는 질문을 하나 더 해 봅니다.

```
docs/GUIDE.md를 읽고, CSV로 된 패키지 목록을 받았을 때 어떤 명령으로 판별하고 스캔하는지 순서대로 말해. 실행은 하지 마.
```

4. 틀린 답이나 막힌 곳이 나오면 `AGENTS.md`나 `docs/GUIDE.md`의 해당 부분을 고칩니다. 문서와 코드가 다르면 코드와 테스트가 맞습니다.

## 5. 아직 확인하지 않은 것

- 이 저장소에서 Codex로 실제 수정 작업을 해 본 적이 없습니다. 4장이 그 확인입니다.
- OpenAI 어댑터(`LLM_PROVIDER=openai`)는 실제 호출로 확인하지 않았습니다. 현장에서 OpenAI 모델을 쓰게 되면 `uv run python -m triage doctor --llm`부터 돌립니다.
- 샌드박스 검증은 npm 저장소만 됩니다.
- Codex의 샌드박스 안에서 Docker와 네트워크를 쓰는 명령(`triage verify`, 실조회 `triage scan`)이 승인 없이 되는지는 확인하지 않았습니다. 막히면 그 명령만 터미널에서 직접 실행합니다.

## 6. 본선 당일

### 6.1 사람이 먼저 할 것

1. 현장 안내(과제, 제공 도구, 제공 자료, 제출 방법, 금지 사항)를 끝까지 읽습니다.
2. 받은 자료와 과제 문서를 저장소의 `data/` 아래에 둡니다.
3. `.env`에 현장에서 쓸 모델 설정(`LLM_PROVIDER`, 키, 모델 이름)을 직접 넣습니다.
4. `git status --short`가 깨끗한지 봅니다.

### 6.2 첫 문장

```
kit/START.md 읽고 그대로 해.
```

Codex가 하는 일: 상태 확인, 환경 점검, 키트 적용, 자료 보호(해시 기록), 자료 판별, 과제 정리(`docs/finals/TASK.md`, `GAP.md`), 짧은 보고. **이 단계에서는 코드를 고치지 않고 멈춥니다.**

### 6.3 그다음

보고를 읽고 범위를 정해 지시합니다. 단계별 문장은 `kit/prompts.md`(P0 ~ P10)에, 1박 2일의 일정과 줄이는 순서는 `kit/PLAYBOOK.md`에 있습니다.

`kit/prompts.md`에서 "○○ 스킬로"라고 적힌 문장은 Codex에서 이렇게 바꿔 씁니다.

```
kit/claude/skills/<이름>/SKILL.md 를 읽고 그 절차대로 해.
```

| 언제 | 절차서 |
|---|---|
| 과제 문서를 받은 직후 | `task-intake` |
| 자료를 받은 직후 | `data-check` |
| 자료 형식이 읽히지 않을 때 | `adapt-input` |
| AI 판단을 돌린 뒤, 규칙이나 프롬프트를 바꾼 뒤 | `agent-eval` |
| 샌드박스 검증 | `verify-run` |
| 시연 준비 | `demo` |
| 중간 점검과 제출 직전 점검 | `review` |
| 대화가 길어졌을 때, 도구를 바꿀 때 | `handoff` |

### 6.4 세션을 바꿀 때

대화가 길어지거나 Claude Code와 Codex 사이를 오갈 때는 먼저 기록을 남기게 합니다.

```
kit/claude/skills/handoff/SKILL.md 를 읽고 그 절차대로 docs/finals/HANDOFF.md 를 갱신해.
```

새 세션의 첫 문장:

```
docs/finals/HANDOFF.md 와 git log --oneline -10 을 읽고, 지금 상태와 다음 할 일을 3줄로 말한 뒤 멈춰.
```

## 7. 작업 중 지킬 것

1. **승인 전에 읽습니다.** 특히 `git push`, 파일 삭제, `data/`나 `fixtures/demo-repo/`를 건드리는 명령은 승인하지 않습니다.
2. **커밋과 푸시는 직접 지시할 때만 하게 합니다.** 저장소가 공개이므로 푸시한 내용은 누구나 봅니다. 커밋 메시지에 AI 기여자 표기(`Co-Authored-By`, "Generated with ...")가 붙지 않았는지 `git log -1`로 확인합니다.
3. **키를 대화에 붙여 넣지 않습니다.** `.env`만 고칩니다.
4. **`fixtures/cache/`가 바뀌면 커밋 전에 확인합니다.** 실조회 스캔이 KEV 목록 파일을 갱신하면 재생 결과의 기준이 달라집니다. `git status --short fixtures/cache`로 봅니다.
5. **바꾼 뒤에는 돌려 봅니다.** `uv run pytest -q`와 `bash kit/scripts/check.sh --fast`.
6. **비용이 드는 실행은 건수를 정해 줍니다.** AI 판단은 `--limit`으로 건수를 제한할 수 있습니다.
7. **한 번에 한 단계만 고치게 합니다.** 파일 3개 이상을 바꾸는 작업은 계획 3줄을 먼저 받고 "진행"이라고 한 뒤 구현하게 합니다(`AGENTS.md` 8장).

## 8. 막혔을 때

| 증상 | 조치 |
|---|---|
| Codex가 규칙을 모르는 것처럼 행동함 | 저장소 루트에서 실행했는지 봅니다. `AGENTS.md`는 저장소 루트에서 현재 폴더까지의 경로에서 읽힙니다 |
| 명령이 샌드박스에 막힘 | 네트워크나 Docker가 필요한 명령입니다. 그 명령만 터미널에서 직접 돌리고 결과를 알려 줍니다 |
| 테스트가 `psycopg`를 찾지 못함 | `uv sync --extra postgres`. 없어도 해당 테스트는 건너뜁니다 |
| 모델이 30분 안에 붙지 않음 | `LLM_PROVIDER=none`으로 규칙 결과만으로 한 줄기를 먼저 완성합니다 |
| 자료 형식이 읽히지 않음 | `uv run python -m triage inspect data`가 말하는 조치부터 합니다. 그다음이 `adapt-input` 절차입니다 |
| 그 밖의 증상 | `docs/GUIDE.md` 11장 |
