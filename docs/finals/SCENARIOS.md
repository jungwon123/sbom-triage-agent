# SCENARIOS — 시연 장면

시연용 실행: `out/<run id>` (단계: sbom, scan, score, agent, verify)
오프라인 재생: `DEMO_MODE=replay uv run uvicorn triage.api:app` → `http://localhost:8000/?run=<run id>`

| # | 장면 | 보여 줄 항목(finding id) | 화면에서 보여야 하는 값 | 값의 출처(evidence 줄) | 대응 테스트 |
|---|---|---|---|---|---|
| 1 | 압축: 전체 → NOW | | | | |
| 2 | 대비 A: CVSS 높지만 미사용 | | | | test_unused_dev_critical_is_not_now |
| 3 | 대비 B: 운영 코드 사용 또는 하향 보류 | | | | test_needs_review_blocks_downgrade |
| 4 | 검증: 단계, 판정, 테스트 수 | | | | test_existing_failures_are_not_regressions |
| 5 | 한계 공개: 틀린 사례 또는 inconclusive | | | | |

## 과제가 요구한 장면
-
