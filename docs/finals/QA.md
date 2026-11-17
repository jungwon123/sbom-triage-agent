# QA — 예상 질문과 답

답은 한두 문장과 근거(측정값, 테스트 이름, 파일). 측정하지 않은 것은 "측정하지 않았습니다, 이렇게 잴 계획입니다"로 답한다.

| 질문 | 답 | 근거 |
|---|---|---|
| 왜 심각도 25, 악용 가능성 25, 노출도 50인가 | | `docs/REQUIREMENTS.md` F5, `tests/test_score.py` |
| AI가 마음대로 정하는 것 아닌가 | | `agent/run.py` contract_violations, `tests/test_agent_contract.py` |
| AI의 정확도는 얼마인가 | | `out/<run>/eval.json` |
| NOW를 놓친 적이 있는가 | | eval의 now_missed |
| verified는 무엇을 보장하나 | | 실행된 테스트 수, `verify/run.py` verdict |
| 프롬프트 인젝션은 어떻게 막나 | | `verify/apply.py`, `tests/test_apply.py`, `tests/test_tools.py` |
| 기존 도구(Dependabot, Snyk 등)와 무엇이 다른가 | | 공식 문서로 확인한 내용만 |
| 사내망에서 어떻게 돌리나 | | `DEMO_MODE=replay`, LLM 어댑터 |
| npm 말고 다른 언어는 | | `fixtures/maven-demo`, GAP.md |
| 수천 개 서비스로 늘리면 | | `docs/poc-results.md` 운영 PoC |
| 비용은 얼마나 드나 | | agent_log의 토큰 합계 |
| (과제별 질문) | | |
