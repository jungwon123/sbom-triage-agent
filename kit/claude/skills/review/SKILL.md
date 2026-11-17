---
name: review
description: 읽기 전용 점검. 모드 A 진행 점검, 모드 B 절대 규칙과 과제 요구 대조, 모드 C 제출 직전 문서와 코드와 발표 수치 일치 확인. 파일을 수정하지 않는다. reviewer 서브에이전트가 주로 사용.
---

# review — 읽기 전용 점검

**이 절차를 따르는 동안 어떤 파일도 수정하지 않는다.** 명령은 읽기, 테스트 실행, `kit/scripts/check.sh`만. 결과는 목록으로 보고하고 수용 여부는 사람이 정한다.

## 모드 A: 진행 점검
1. `docs/finals/GAP.md`, `git log --oneline -15`, `uv run pytest -q` 결과를 본다.
2. 보고: 요구별 완료, 부분, 미착수(증거 커밋과 테스트), 마감까지 위험 3개, 다음 작업 순서.

## 모드 B: 절대 규칙과 과제 요구 대조
각 항목을 **코드와 테스트로** 확인하고 "충족 / 부분 / 없음 + 근거(파일:함수, 테스트 이름)"로 보고한다.

절대 규칙 (CLAUDE.md 4장)
1. 스키마: 바뀐 모델 필드가 `web/src/lib/types.ts`에 반영됐는가(`scripts/gen_types.py --check`).
2. 규칙과 LLM의 경계: 점수는 `score.py`에서만 나오는가. `AgentVerdict`에 점수 필드가 없는가. ±1, 사유 필수, KEV 하향 금지, 하향 보류가 코드로 강제되는가.
3. 근거: rationale의 숫자가 자리표시자로만 들어가는가. 화면의 수치가 Finding 값과 같은가(표본 3건을 직접 대조).
4. 에이전트 읽기 전용: `agent/tools.py`에 쓰기와 실행이 없는가. 레포 밖 경로가 막히는가.
5. LLM 출력 미실행: 샌드박스 명령이 `verify/apply.py`에서만 만들어지는가. 새로 추가된 코드가 LLM 문자열을 셸이나 파일 경로로 넘기지 않는가.
6. 외부 호출: `cache.py` 밖에 HTTP 호출이 없는가. `DEMO_MODE=replay`가 도는가.
7. 비밀값: 코드, 로그, `out/`에 키가 없는가. 컨테이너에 환경 변수를 넘기지 않는가.

과제 요구
8. `docs/finals/TASK.md`의 필수 요구마다 구현과 테스트가 있는가.
9. **편향 점검**: 일치율을 높이려고 정답이나 사례를 골랐는가. 틀린 사례와 `inconclusive`를 숨겼는가. verified의 테스트 실행 수를 밝혔는가.
10. 현장 자료를 수정했는가(`kit/scripts/data_guard.sh verify`). 대상 레포가 그대로인가.

## 모드 C: 제출 직전
1. `bash kit/scripts/check.sh`와 `python3 kit/scripts/evidence.py`를 실행한다.
2. 발표 자료, DEMO_SCRIPT, QA, HANDOFF에 적힌 수치와 "완료, 동작" 문장을 `out/evidence.md`, 코드, 테스트와 대조한다.
3. DEMO_SCRIPT의 화면 문구가 `web/src`의 실제 문자열과 같은지 `grep`으로 확인한다.
4. 보고: 불일치 목록(문서 위치 → 실제 값), 실패 테스트, 제출물 누락(`docs/finals/SUBMIT_CHECKLIST.md` 기준), 커밋의 AI 기여자 표기 유무.
