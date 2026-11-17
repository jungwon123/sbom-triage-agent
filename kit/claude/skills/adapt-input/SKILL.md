---
name: adapt-input
description: 새 입력 형식(다른 lockfile, 스캐너 결과, 다른 생태계, 취약점 DB 스냅샷)을 파이프라인에 연결하는 어댑터를 만든다. 현장 자료가 현재 지원 형식과 다를 때 사용.
---

# adapt-input — 입력 어댑터

판단 구조는 건드리지 않고 **입력만 맞춘다.** 어댑터의 출력은 `models.py`의 `Component`(SBOM 단계) 또는 `Finding`(스캔 결과 단계)이다.

## 어디에 붙이나

| 현장 자료 | 붙일 곳 | 출력 |
|---|---|---|
| 다른 lockfile (yarn, pnpm, Gradle) | 먼저 Syft가 읽는지 확인. 안 되면 `sbom.py`에 파서 추가 후 `lockfile_components`에 연결 | `Component` |
| SBOM 파일 변형 (CycloneDX XML, SPDX tag-value) | `sbom.load_file` | CycloneDX dict |
| 다른 생태계 (PyPI, Go) | `models.Ecosystem`, `sbom.parse_purl`, `enrich/usages.py`의 import 패턴, `verify/apply.py`의 이름과 버전 패턴 | `Component` |
| 스캐너 결과 (Trivy, Grype, npm audit) | 새 모듈 `backend/triage/ingest.py`. 취약점 ID와 패키지, 버전만 뽑고 보강(EPSS, KEV, 수정 버전)은 기존 코드로 | `Finding` |
| 취약점 DB 스냅샷 (오프라인) | `cache.py`의 키 규칙에 맞춰 `fixtures/cache/`에 넣는 변환 스크립트 | 캐시 파일 |
| 서비스 목록 | `runner.scan`의 `ServiceContext` | 표시 전용 |

## 절차
1. **테스트 먼저.** 현장 자료의 실제 사례 2~3건을 줄여서 `tests/`에 고정 데이터로 넣고 실패하는 테스트를 쓴다. 원본 파일을 테스트에 복사하지 않는다(필요한 필드만).
2. 계획 3줄(바꿀 파일 / 방법과 버린 대안 / 테스트 케이스)을 보고하고 멈춘다.
3. 구현한다. 지킬 것:
   - 외부 호출은 `cache.fetch_json`만 쓴다.
   - 없는 값은 `None`으로 두고 `Finding.missing`에 이름을 넣는다. 예외로 멈추지 않는다.
   - 패키지 이름과 버전은 그대로 두되, 명령에 쓰이는 값은 `verify/apply.py`의 패턴 검사를 통과해야 한다.
   - `Ecosystem`이나 스키마를 바꾸면 `uv run python scripts/gen_types.py`로 `web/src/lib/types.ts`를 같은 커밋에서 갱신한다.
4. `uv run pytest -q` 전체 통과 → 현장 자료로 `triage scan` → coverage(EPSS, CVSS, 수정 버전 확보율)를 보고한다.
5. 새 생태계의 샌드박스 검증은 별도 결정이다. 하지 않으면 "검증은 npm만"이라고 GAP.md에 적는다.
