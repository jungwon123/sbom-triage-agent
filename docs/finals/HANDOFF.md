# HANDOFF (갱신: YYYY-MM-DD HH:MM, 커밋 <해시>)

## 현재 상태

| 요구(T-ID) | 상태 | 증거(커밋, 테스트) |
|---|---|---|
| | | |

- 테스트: 통과 N / 실패 N / 건너뜀 N (0건이면 미검증)
- 현장 자료로 스캔 □ / 에이전트 □ / 검증 □ / 화면 □ / 일치율 측정 □
- 제공 자료 무수정(`data_guard.sh verify`) □ / 오프라인 리플레이 □

## 실행
- 설치: `uv sync --extra openai`, `cd web && pnpm install`
- 스캔: `uv run python -m triage scan <경로>`
- 에이전트: `uv run python -m triage agent out/<run> [--limit N]`
- 검증: `uv run python -m triage verify out/<run> [--setup "..."]`
- 화면: `cd web && pnpm build` 뒤 `uv run uvicorn triage.api:app` → `http://localhost:8000/?run=<run>`
- 리플레이: 위 명령 앞에 `DEMO_MODE=replay`
- LLM: 제공자 / 모델 (키는 `.env`에만)

## 시연용 실행
- run id:
- 단계:

## 열린 결정 (사람 판단 필요)
-

## 알려진 문제
-

## 다음 할 일 3개
1.
2.
3.

## 마감까지 / 줄일 범위 후보
-
