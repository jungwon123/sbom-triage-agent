# START — 현장 시작 절차 (에이전트가 읽고 그대로 수행)

## 사람이 먼저 할 것

1. 현장 안내(과제 설명, 제공 도구, 제공 자료, 제출 방법, 금지 사항)를 끝까지 읽는다.
2. 받은 자료를 레포의 `data/` 아래에 둔다. 과제 설명 문서도 같이 둔다.
3. `.env`에 쓸 LLM 설정을 넣는다 (`LLM_PROVIDER`, 키, 모델명). 키는 직접 입력하고 에이전트에게 보여 주지 않는다.
4. 첫 문장: `kit/START.md 읽고 그대로 해.`

---

## 에이전트가 할 것

기준 순서는 **현장 과제 안내 → docs/REQUIREMENTS.md → CLAUDE.md → HARNESS.md → 키트**다. `kit/PLAYBOOK.md`와 `kit/prompts.md`는 사람용이므로 읽지 않는다.

1. **상태 확인.** `git status --short`, `git log --oneline -5`, `uv run pytest -q`. 실패하는 테스트가 있으면 먼저 보고하고 멈춘다.
2. **환경 점검.** `uv run python -m triage doctor`. LLM 키가 있으면 `--llm`을 붙여 한 번 호출해 본다. `.env` 내용은 읽거나 출력하지 않는다.
3. **키트 적용.** `bash kit/scripts/apply.sh`. `docs/finals/`가 이미 있으면 덮어쓰지 않는다.
4. **자료 보호.** `data/`가 있으면 `bash kit/scripts/data_guard.sh init data`.
5. **자료 요약.** 두 명령을 돌린다. 파일 내용을 통째로 열지 않는다.
   - `python3 kit/scripts/profile_input.py data --out out/profile.md` (파일 종류와 개수, 문서 목록)
   - `uv run python -m triage inspect data` (실제 파서로 판별: 파일마다 형식, 지원 여부, 컴포넌트 수, 입력이 보고한 취약점 수, 빠진 정보)
6. **과제 정리.** `task-intake` 절차(`kit/claude/skills/task-intake/SKILL.md`)로 `docs/finals/TASK.md`와 `docs/finals/GAP.md` 초안을 채운다. 과제 문서의 문장을 근거로 인용 위치를 적는다.
7. **보고 (짧게).**
   - 과제가 요구하는 것 3줄, 평가 기준
   - 자료 종류와 현재 파이프라인이 바로 읽을 수 있는지
   - 차이 목록 상위 5개(필수 여부, 예상 작업량)
   - 사람이 정해야 할 것: LLM 제공자, 범위에서 뺄 것

**이 단계에서는 코드를 고치지 않는다.** 범위도 대신 정하지 않는다.

## 필요할 때만 (사용자가 지시하면)

- 읽히지 않는 입력: `adapt-input` 절차. 순서는 (1) `triage inspect`가 말한 조치 (2) 표나 JSON 목록이면 `--columns`와 `--ecosystem` (3) 그래도 안 되면 `backend/triage/ingest.py`에 파서 추가(테스트 먼저)다.
- 취약점 데이터 파일을 받았을 때(네트워크 차단): `uv run python -m triage seed --kev <파일> --epss <파일>`.
- Codex에서 일할 때: 규칙과 금지 행동은 `AGENTS.md`에 있다. 스킬 대신 `kit/claude/skills/<이름>/SKILL.md`를 직접 읽는다.
- LLM 교체: `.env`의 `LLM_PROVIDER`만 바꾼다. 어댑터는 `backend/triage/agent/llm_openai.py`에 이미 있다.
- 네트워크가 막힌 환경: `DEMO_MODE=replay`. 캐시에 없는 응답은 None으로 처리되고 근거에 "확보하지 못한 데이터"로 표시된다.
- Docker가 없는 환경: 검증 단계는 건너뛰고 그 사실이 이벤트에 남는다. 미리 녹화한 실행 결과로 시연한다.
