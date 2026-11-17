---
name: handoff
description: docs/finals/HANDOFF.md 갱신과 세션 교체. 대화가 길어졌을 때, 첫날을 끝낼 때, 도구를 바꿀 때(Claude Code와 Codex 사이), 제출 직전에 사용.
---

# handoff — 인수인계와 세션 교체

## 절차
1. `git log --oneline -15`, `git status --short`, `docs/finals/GAP.md`, `docs/finals/DECISIONS.md` 마지막 10줄을 본다.
2. `uv run pytest -q`로 통과와 실패 수를 확인한다(0건이거나 건너뜀만이면 "미검증").
3. `docs/finals/HANDOFF.md`를 **현재 코드와 커밋 기준으로** 갱신한다.
   - 요구별 완료 / 진행 중 / 미착수 (완료는 커밋 해시와 테스트 이름)
   - 실행 방법: 설치, 스캔, 에이전트, 검증, API, 화면, 리플레이
   - 시연용 run id와 그 실행의 단계(`meta.json`의 `stages`)
   - LLM 설정(제공자와 모델 이름만, 키는 적지 않는다)
   - 열린 결정, 알려진 문제, 다음 할 일 3개
   - 마감까지 남은 시간과 줄일 범위 후보
4. `HARNESS.md` 7장 진행 로그에 한 줄 추가한다.
5. `docs: handoff` 커밋. 커밋 메시지에 AI 기여자 표기를 넣지 않는다.
6. 사람에게 새 세션 첫 문장을 알려 준다:
   `CLAUDE.md, docs/finals/HANDOFF.md, docs/finals/TASK.md, docs/finals/GAP.md만 읽고 다음 할 일 3개를 제안해.`

## 제출 직전 추가
- `bash kit/scripts/check.sh`, `python3 kit/scripts/evidence.py`
- `docs/finals/SUBMIT_CHECKLIST.md` 항목을 하나씩 확인해 체크
