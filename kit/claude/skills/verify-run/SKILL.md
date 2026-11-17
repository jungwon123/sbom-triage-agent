---
name: verify-run
description: NOW 항목을 Docker 샌드박스에서 검증하고 판정을 읽는다. 판정별 건수, 실제 실행된 테스트 수, 실패 원인을 정리한다. 에이전트 판단 뒤와 시연 준비 때 사용.
---

# verify-run — 샌드박스 검증

대상 레포를 직접 고치지 않는다. 명령은 `verify/apply.py`가 만든 것만 컨테이너에서 실행된다.

## 절차
1. `uv run python -m triage doctor`로 Docker와 이미지(`node:20-slim`)를 확인한다. 꺼져 있으면 사람에게 알리고 멈춘다.
2. `uv run python -m triage verify out/<run> [--setup "<설정 명령>"]`
   - 설정 명령은 설치 뒤에 필요한 생성 단계다(예: `npx prisma generate`). 사람이 정한 것만 쓴다.
3. `out/<run>/verify/*.json`을 읽어 표로 보고한다: 패키지, 올린 버전, 판정, 이유, 시도 횟수, **실행된 테스트 수**, 새 취약점 수.
4. 판정을 해석한다.
   - `verified`인데 테스트 실행 수가 0이면 "설치, 빌드, 재스캔까지만 확인"이라고 적는다.
   - `failed`는 이유별로: `target_remains`(취약점이 남음), `new_now`(새 고위험 취약점), `regression`(새로 실패한 빌드나 테스트 이름), `install_failed`.
   - `inconclusive`는 이유별로: `timeout`, `mitigation_only`, `baseline_test_uncomparable`, `baseline_build_failed`.
5. 대상 레포가 그대로인지 확인한다: `git -C <레포> status --short`가 비어 있어야 한다.

## 주의
- 기준선에서 이미 실패하던 테스트는 회귀가 아니다. 이름으로 비교한다.
- 재시도(F8-5)는 LLM이 켜져 있을 때만 돈다. 꺼져 있으면 1회 판정으로 끝난다.
- 동시에 여러 개를 돌리지 않는다. PoC에서 한 PC 기준 동시 4개를 넘으면 처리량이 줄었다.
- Maven 등 npm이 아닌 항목은 검증 대상에서 빠진다. 빠진 건수를 보고에 적는다.
