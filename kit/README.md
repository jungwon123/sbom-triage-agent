# lotte-ax-kit

롯데 AX 챌린지 본선(2026-11-24 ~ 25, 롯데이노베이트 SW 공급망 과제)에서 **SBOM Triage Agent**를 현장 과제에 맞춰 고치기 위한 하네스 키트입니다.
업무 로직은 들어 있지 않습니다. 로직은 `backend/triage/`와 `web/`에 있고, 키트는 그 코드를 다루는 절차서(`claude/skills/`), 문서 틀(`templates/`), 점검 스크립트(`scripts/`), 사람용 일정표와 프롬프트만 담고 있습니다.

- 작성: 이정원, 2026-11-18
- 참고: [ax-kit](https://github.com/jungwon123/ax-kit)의 구조(START, PLAYBOOK, prompts, skills, templates, scripts)를 가져와 이 프로젝트에 맞게 다시 썼습니다.

## ax-kit과 다른 점

| | ax-kit | lotte-ax-kit |
|---|---|---|
| 기간 | 약 1주, 원격 | 1박 2일 현장 (11/24 ~ 11/25 13:00) |
| 출발점 | 빈 프로젝트 + starter | **이미 구현된 파이프라인**. 현장에서는 과제와 자료에 맞추는 작업만 한다 |
| 과제 | 미리 공개 | **당일 공개**. 첫 단계가 과제 정리와 차이 분석이다 |
| 도구 | Claude Code | Claude Code 또는 Codex. Codex는 `AGENTS.md`만으로 시작할 수 있다(규칙 요약, 금지 행동, 절차서 위치, 입력 형식 대응) |
| 자료 | CSV | 미정. 레포, SBOM 파일, 스캐너 결과, 서비스 목록 중 무엇이든 올 수 있다 |
| 핵심 위험 | 운영 루프 미완성 | LLM 교체(OpenAI), npm이 아닌 생태계, 네트워크와 Docker 제한 |
| 증명 | 테스트 + 시연 영상 | 테스트 + 현장 시연 + 질의응답. 수치는 `out/evidence.md`와 일치해야 한다 |

## 구성

| 경로 | 내용 |
|---|---|
| `START.md` | 에이전트가 읽고 그대로 수행하는 현장 시작 절차 |
| `PLAYBOOK.md` | **사람용** 1박 2일 일정표, 줄이는 순서, 안 될 때 |
| `prompts.md` | **사람용** 단계별 프롬프트 (P0 ~ P10) |
| `claude/settings.json` | 권한: 제공 자료와 대상 레포 편집, `.env` 읽기, 강제 push, `rm -rf` 차단. AI 기여자 표기 끔 |
| `claude/skills/` | `task-intake`, `data-check`, `adapt-input`, `agent-eval`, `verify-run`, `demo`, `review`, `handoff` |
| `claude/agents/` | `data-scout`(자료 요약, 읽기 전용), `reviewer`(규칙과 완료 조건 점검, 읽기 전용) |
| `templates/` | TASK, GAP, DATA_NOTES, DECISIONS, SCENARIOS, DEMO_SCRIPT, QA, HANDOFF, SUBMIT_CHECKLIST |
| `scripts/apply.sh` | 키트를 `.claude/`와 `docs/finals/`에 복사 (덮어쓰지 않음) |
| `scripts/profile_input.py` | 제공 자료가 무엇인지 요약: 파일 종류와 개수, 문서 목록. 형식 판별과 지원 여부는 `uv run python -m triage inspect <경로>`가 실제 파서로 알려 준다 |
| `scripts/data_guard.sh` | 제공 자료 해시 기록(`init`)과 무수정 확인(`verify`) |
| `scripts/check.sh` | 테스트, 절대 규칙 정적 점검, 오프라인 리플레이, git(AI 기여자 표기 포함), 키 하드코딩, 환경, 문서 |
| `scripts/evidence.py` | 발표용 근거 수집: 커밋 흐름, 실행별 수치, 에이전트 통계, 검증 판정, 일치율 → `out/evidence.md` |

## 사용법

레포 루트에서:

```bash
bash kit/scripts/apply.sh
```

그다음 Claude Code 또는 Codex의 첫 문장: `kit/START.md 읽고 그대로 해.`

이후는 `PLAYBOOK.md` 일정과 `prompts.md`의 P번호를 따릅니다.

## 원칙

1. **현장 안내가 기준이다.** 충돌하면 현장 과제 안내 → `docs/REQUIREMENTS.md` → `CLAUDE.md` → `HARNESS.md` → 키트 순서로 따른다.
2. **이미 되는 것을 깨지 않는다.** 바꾸기 전에 `uv run pytest`가 통과하는지 보고, 바꾼 뒤에도 본다.
3. **입력을 맞추고 판단 구조는 지킨다.** 새 자료 형식은 어댑터로 `Component`나 `Finding`에 맞춘다. 규칙 점수, ±1 제한, 코드가 만드는 명령은 그대로 둔다.
4. **측정하지 않은 수치는 말하지 않는다.** 발표 수치는 `out/evidence.md`에 있어야 한다.
5. **판단은 사람이 한다.** 큰 결정마다 에이전트는 선택지를 내고 사람이 고른다. 고른 이유는 `docs/finals/DECISIONS.md`에 남긴다.
