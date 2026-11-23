---
name: adapt-input
description: 현장 자료가 읽히지 않을 때 입력을 파이프라인에 연결한다. 먼저 triage inspect로 판별하고, 표나 JSON 목록은 열 지정으로 읽고, 그래도 안 될 때만 ingest.py에 파서를 추가한다.
---

# adapt-input — 입력 맞추기

판단 구조는 건드리지 않고 **입력만 맞춘다.** 모든 입력은 `models.py`의 `Component`(패키지, 버전, 생태계) 목록으로 줄인다. 입력이 스스로 보고한 취약점은 `Component.reported`에 실어 보낸다.

## 이미 읽는 것 (`backend/triage/ingest.py`, `sbom.py`)

| 종류 | 형식 |
|---|---|
| 의존성 파일 | package-lock.json, yarn.lock, pnpm-lock.yaml, pom.xml(직접 의존성만), gradle.lockfile, requirements*.txt, poetry.lock, uv.lock, Pipfile.lock, go.mod, go.sum, Cargo.lock, Gemfile.lock, composer.lock, packages.lock.json |
| SBOM | CycloneDX JSON과 XML(vulnerabilities 절 포함), SPDX JSON과 tag-value |
| 스캐너 결과 | Trivy, Grype, OSV-Scanner, Snyk, OWASP Dependency-Check의 JSON |
| 표와 목록 | CSV, TSV, 객체 배열 JSON. 열 이름은 한글 포함해 추측한다 |
| 취약점 데이터 | KEV JSON과 EPSS CSV는 `triage seed`로 넣는다 |

읽지 못하는 것: 엑셀(CSV로 저장), npm audit 결과(설치 버전이 없다. package-lock.json을 쓴다), SARIF(패키지 버전이 규격에 없다), OS 패키지(apk, deb, rpm).

## 순서 (위에서부터, 되는 데서 멈춘다)

1. **판별.** `uv run python -m triage inspect <파일 또는 폴더>`. 지원이면 바로 `triage scan <경로>`. 미지원이면 출력의 이유와 조치를 따른다.
2. **열 지정.** 표나 JSON 목록인데 열을 잘못 읽었거나 못 찾았으면 `--columns name=<열>,version=<열>[,ecosystem=,group=,vuln=,severity=,cvss=,fixed=,scope=,direct=]`와 `--ecosystem <npm|Maven|PyPI|Go|...>`를 준다. Maven은 그룹이 있어야 하므로 `group` 열이 없으면 이름이 `그룹:아티팩트` 꼴이어야 한다.
3. **모양 바꾸기.** 중첩이 깊은 JSON이나 엑셀은 필요한 열만 뽑아 CSV로 바꾼 사본을 `out/` 아래에 만들어 읽는다. `data/`의 원본은 고치지 않는다.
4. **파서 추가.** 위로 안 될 때만 한다.
   1. 현장 자료의 실제 사례 2 ~ 3건을 필요한 필드만 줄여 `tests/test_ingest.py`에 넣고 실패하는 테스트를 쓴다. 원본 파일을 복사하지 않는다.
   2. 계획 3줄(바꿀 파일 / 방법과 버린 대안 / 테스트 케이스)을 보고하고 멈춘다.
   3. `ingest.py`에 `parse_x(text 또는 doc) -> Parsed`를 쓰고, 파일 이름으로 알아볼 수 있으면 `BY_NAME`에, 내용으로 알아봐야 하면 `_sniff`에 한 줄 추가한다. 컴포넌트는 `component(eco, name, version, ...)`로 만든다(버전이 범위이거나 이름이 없으면 None이 되어 빠진다).
   4. 뺀 행 수와 없는 정보는 `Parsed.notes`에 문장으로 남긴다. 조용히 버리지 않는다.

## 지킬 것

- 파서는 순수 함수다. 파일 읽기와 네트워크 호출을 넣지 않는다. 외부 호출은 `cache.fetch_json`만 쓴다.
- 없는 값은 `None`으로 두고 `Finding.missing`에 이름이 들어가게 한다. 예외로 멈추지 않는다.
- 새 생태계를 추가하면 `models.Ecosystem`, `sbom.PURL_ECOSYSTEMS`, `ingest.ECOSYSTEMS`와 `PURL_TYPE`을 같이 고치고 `uv run python scripts/gen_types.py`로 `web/src/lib/types.ts`를 같은 커밋에서 갱신한다.
- 규칙 점수, 한 단계 조정 제한, 코드가 만드는 명령은 그대로 둔다.

## 끝나면

`uv run pytest -q` 전체 통과 → 현장 자료로 `triage scan` → 실행 기록의 `coverage`(EPSS, CVSS, 수정 버전 확보율, `unsupported`, `input_notes`, `only_in_input`)를 보고한다. 소스가 없는 입력은 코드 사용 여부가 `unknown`이고, 새 생태계의 샌드박스 검증은 별도 결정이다. 하지 않으면 "검증은 npm만"이라고 `docs/finals/GAP.md`에 적는다.
