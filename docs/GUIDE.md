# 사용 가이드: 핵심 기능과 정상 동작 기준

이 문서는 기능마다 **무엇을 하는지, 어떻게 돌리는지, 무엇이 나와야 정상인지, 이상하면 무엇을 볼지**를 적습니다. 규칙의 원문은 `CLAUDE.md` 4장, 요구사항은 `docs/REQUIREMENTS.md`, 결정의 이유는 `HANDOFF.md` 2장에 있습니다.

명령은 저장소 루트에서 실행합니다. `<run>`은 `out/` 아래의 실행 폴더 이름입니다.

## 0. 먼저 알아둘 것

1. **실행(run)** 은 한 번의 분석 결과입니다. `out/<날짜-시각-이름>/`에 쌓이고 화면에서는 `?run=<id>`로 고릅니다.
2. **Finding** 은 취약점 1건과 패키지 버전 1개의 조합입니다. 같은 패키지가 여러 경로로 들어와도 1건입니다.
3. **버킷** 은 NOW(이번 주), NEXT(다음 정기 작업), MONITOR(지켜봄)입니다.
4. **재생 모드**(`DEMO_MODE=replay`)는 네트워크, Docker, 모델 호출 없이 저장된 응답과 기록만으로 돕니다. 캐시에 없는 조회는 실패가 아니라 "없음"으로 남습니다.
5. 값이 없을 때는 멈추지 않습니다. 없는 값은 `None`으로 두고 `Finding.missing`과 실행의 `coverage`에 무엇이 없었는지 남깁니다.

## 1. 입력 판별 (`triage inspect`)

무엇을 하는가: 받은 파일이나 폴더가 어떤 형식이고 읽을 수 있는지 알려 줍니다. 아무것도 고치지 않습니다.

```bash
uv run python -m triage inspect <파일 또는 폴더>
uv run python -m triage inspect list.csv --columns name=제품명,version=버전 --ecosystem npm
```

읽는 형식: 저장소(각 생태계의 lock 파일), CycloneDX JSON과 XML, SPDX JSON과 tag-value, Trivy와 Grype와 OSV-Scanner와 Snyk와 Dependency-Check의 JSON, CSV와 TSV와 객체 배열 JSON.

정상 동작:
- 파일마다 형식, 지원 여부, 컴포넌트 수, 빠진 정보(의존 관계, 운영과 개발 구분 등)가 나옵니다.
- 읽지 못하는 파일은 조용히 넘기지 않고 이유와 다음 행동을 말합니다.
- 표의 열 이름을 추측하지 못하면 `--columns`를 요구합니다.

## 2. 스캔 (`triage scan`): ① SBOM, ② 취약점 조회, ③ 보강, ④ 규칙 점수

```bash
uv run python -m triage scan <저장소 또는 파일>
DEMO_MODE=replay uv run python -m triage scan fixtures/blind/sbom-a.cdx.json
```

정상 동작:
- 끝에 JSON 요약이 나옵니다. `coverage`에 컴포넌트 수, Finding 수, EPSS와 CVSS와 수정 버전이 채워진 비율, KEV 목록의 판(version)이 있습니다.
- `summary.rule`과 `summary.final`이 같습니다. AI 판단 전이므로 최종 버킷은 규칙 버킷입니다.
- 조회하지 못한 컴포넌트는 `coverage.unsupported`에, 입력에서 빠진 정보는 `coverage.input_notes`에 남습니다.
- 같은 입력을 다시 스캔하면 같은 버킷이 나옵니다. 점수는 순수 함수(`score.py`)입니다.

규칙 점수의 구조:
- 위험 점수 100점 = 심각도 25 + 악용 가능성 25 + 노출 50.
- 60점 이상이면 NOW, 30점 이상이면 NEXT, 그 아래는 MONITOR입니다. 단, 60점 이상이어도 조치 비용이 높으면(예: 수정 버전 없음) NEXT입니다.
- 점수와 무관한 하한이 있습니다. 악성 패키지 권고(MAL-)는 NOW입니다. KEV에 오른 취약점은 운영 의존성이면 NOW, 개발 전용이면 최소 NEXT입니다.

이상할 때:
- Finding이 0건이면 `coverage.unsupported`를 봅니다. purl이 없거나 지원하지 않는 생태계일 수 있습니다.
- 재생 모드에서 건수가 적으면 로그의 `replay cache miss`를 봅니다. 캐시에 없는 대상입니다.
- 저장소 스캔에서 Syft가 없으면 lock 파일 해석으로 대체되고 `sbom_source`에 그렇게 적힙니다.

## 3. AI 판단 (`triage agent`): ⑤

```bash
uv run python -m triage agent out/<run>                 # 전체
uv run python -m triage agent out/<run> --changed       # 다시 확인에서 달라진 항목만
uv run python -m triage agent out/<run> --retry-failed  # 지난번 모델 호출이 실패한 항목만
```

화면에서는 "전체 판단 실행"과 "달라진 N건만 판단" 버튼이 같은 일을 작업(`agent`)으로 큐에 넣습니다. 승인 역할이 필요하고, 모델 호출 비용이 듭니다.

AI가 하는 일: 취약한 기능이 실제로 호출되는지 코드를 읽어 판정하고(`reachability`), 버킷을 조정하고, 근거와 조치안을 씁니다.

정상 동작:
- 항목마다 `decided_by`가 `agent`가 됩니다. 모델 호출이 실패한 항목은 `agent_fallback`이 되고 규칙 버킷을 유지합니다.
- 최종 버킷은 규칙 버킷에서 **한 단계까지만** 다릅니다. 다를 때는 `override_reason`이 있습니다.
- KEV 항목과 악성 패키지는 내려가지 않습니다. EPSS가 매우 높은 항목은 AI 혼자 MONITOR로 내리지 못합니다. 이 제한은 코드가 강제하고, 막힌 항목은 `needs_review`로 표시됩니다.
- 근거 문장의 숫자(CVSS, EPSS, 버전)는 실행 기록의 값과 일치합니다. AI는 `{cvss}` 같은 자리표시자를 쓰고 코드가 값을 채웁니다.
- AI의 도구는 읽기 전용입니다. 대상 저장소 밖의 파일과 `.env` 같은 자격 증명 파일은 읽지 못합니다.
- 화면의 작업은 모델을 부를 수 없으면(재생 모드, `LLM_PROVIDER=none`, 대상 없음) 실행하지 않고 이유를 남깁니다. 규칙 결과로 덮어쓰지 않습니다.

2단계 모드(`LLM_CODE_PROVIDER=local`):
- 사내 모델만 소스코드를 읽고 `code_read_by`가 `local_agent`가 됩니다.
- 외부 모델로 나가는 요청에는 코드, 파일 이름, 빌드와 테스트 로그, 도구 정의가 없습니다.
- 실행 기록의 `llm.mode`가 `two_stage`입니다.

이상할 때:
- `agent_fallback`이 많으면 `out/<run>/agent_log.jsonl`에서 실패 사유를 봅니다. 작은 로컬 모델은 도구 호출 형식을 자주 틀립니다.
- 규칙이나 안전장치를 바꾼 뒤에는 `uv run python -m triage rescore out/<run>`으로 저장된 실행을 현재 코드에 맞춥니다. 모델을 다시 부르지 않습니다.

## 4. 샌드박스 검증 (`triage verify`): ⑥

```bash
uv run python -m triage verify out/<run>                      # NOW 항목
uv run python -m triage verify out/<run> --buckets NOW,NEXT
uv run python -m triage verify out/<run> --setup "npx prisma generate"
```

화면에서는 "NOW 항목 검증 실행" 버튼이 작업(`verify`)을 큐에 넣습니다.

무엇을 하는가: 저장소를 일회용 컨테이너에 복사하고, 조치 전 기준선(설치, 빌드, 테스트)을 잰 뒤, 조치안을 적용해 다시 설치와 빌드와 테스트를 돌리고 취약점이 사라졌는지 재스캔합니다.

정상 동작:
- 패키지마다 판정이 나옵니다.

| 판정 | 뜻 |
|---|---|
| `verified` | 조치 후에도 기준선과 같은 수의 테스트가 통과했고 재스캔에서 취약점이 사라졌습니다 |
| `failed` | 조치 때문에 설치, 빌드, 테스트 가운데 무엇인가 깨졌거나 취약점이 남았습니다 |
| `inconclusive` | 판단할 수 없습니다. 사유가 함께 남습니다: 시간 초과(`timeout`), 실행된 테스트 수 감소(`fewer_tests_ran`), Docker 데몬 부재(`sandbox_unavailable`) 등 |

- 대상 저장소의 원본은 바뀌지 않습니다. 변경분은 `out/<run>/verify/<패키지>.patch`로 남습니다.
- 설치는 `--ignore-scripts`로 하고, 빌드와 테스트는 네트워크 없이(`--network none`) 돕니다. 컨테이너는 메모리 2GB, CPU 2개, 권한 전부 제거로 제한됩니다.
- 비밀값은 컨테이너에 전달되지 않습니다.
- 재생 모드, 원본 저장소가 없는 실행(SBOM 파일 입력), Docker가 없는 환경에서는 검증을 건너뛰고 이유를 이벤트에 남깁니다.

이상할 때:
- 전부 `inconclusive`이면 기준선부터 봅니다(`out/<run>/verify/baseline.json`). 조치 전에 이미 테스트가 실패하는 저장소는 회귀를 판정할 수 없습니다.
- 빌드 전에 코드 생성이 필요한 저장소는 `--setup`을 줍니다.
- 지금은 npm 저장소만 검증합니다.

## 5. 담당자 결정과 내보내기 (`triage decide`, `triage export`)

```bash
uv run python -m triage decide out/<run> body-parser@1.20.2 approved --by 홍길동
uv run python -m triage decide out/<run> lodash@4.17.20 held --by 홍길동 --reason "다음 배포에 포함"
uv run python -m triage export out/<run>               # 승인분의 패치와 PR 초안
uv run python -m triage export out/<run> --together    # 승인분을 함께 검증해 패치 하나로
```

정상 동작:
- 승인은 샌드박스가 만든 변경 내용(패치)이 있는 조치안에만 됩니다. 판정이 `verified`가 아닌 조치안을 승인하려면 사유를 적어야 합니다. 반려와 보류도 사유가 필수입니다.
- 결정은 `decisions.jsonl`에 누가, 언제, 무엇을 했는지 쌓입니다. 덮어쓰지 않습니다.
- 내보내기는 `out/<run>/export/`에 패치와 `PR_DRAFT.md`를 만듭니다. 푸시하지 않고 대상 저장소를 고치지 않습니다.
- `--together`는 승인한 변경 전부를 한 번에 적용해 다시 검증합니다. 따로는 통과해도 함께는 깨질 수 있기 때문입니다.
- 내보내기 도중 실패해도 이전 `export/`가 남습니다. 임시 폴더에 쓰고 마지막에 바꿔 넣습니다.

## 6. 서비스 등록과 자동 재분류 (`triage services`)

```bash
uv run python -m triage services add shop <저장소> --name 쇼핑몰 --every 24
uv run python -m triage services check --due
```

무엇을 하는가: 등록한 서비스를 주기마다 다시 스캔해 현재 실행과 비교합니다. 새 취약점, KEV 등재, 버킷 이동, 수정 버전 공개를 찾습니다.

정상 동작:
- 달라진 것이 없으면 새 실행을 만들지 않습니다.
- 달라졌으면 새 실행이 생기고 `changes`에 무엇이 어떻게 바뀌었는지 남습니다. 이 단계는 모델을 부르지 않으므로 새 항목은 AI 판단을 다시 받기 전까지 규칙 결과입니다.
- KEV에 새로 오른 항목과 NOW나 NEXT로 올라온 항목은 알림 대상입니다. 알림(`notify.py`)에는 소스코드가 들어가지 않습니다.
- 작업자가 떠 있으면 주기가 지난 서비스의 확인이 자동으로 큐에 들어갑니다.
- 화면에서 등록할 수 있는 경로는 `TRIAGE_SERVICE_ROOTS` 아래로 제한됩니다.

## 7. 대시보드와 API

```bash
cd web && pnpm build && cd ..
uv run uvicorn triage.api:app              # http://localhost:8000/?run=<id>
```

정상 동작:
- 버킷 색은 NOW 빨강, NEXT 주황, MONITOR 회색으로 고정입니다.
- 항목을 고르면 근거, 점수의 구성, import 위치, 조치안, 검증 단계별 결과가 보입니다.
- 화면은 데이터를 전부 API로 읽습니다. `out/`을 직접 읽지 않습니다.
- `/api/health`와 `/api/me`를 뺀 모든 경로에 역할 검사가 있습니다. 읽기는 열람, 결정과 내보내기와 작업 시작은 승인, 서비스 등록과 해제는 관리 역할입니다.
- 로그인이 꺼져 있으면(`TRIAGE_AUTH=off`) 접속한 사람 모두가 관리 역할입니다. 로컬과 재생 전용이며, 다른 사람이 닿는 곳에서는 `oidc`로 둡니다.
- 로그인이 켜져 있으면 결정의 이름은 세션에서 가져옵니다. 요청 본문의 이름은 무시됩니다.

## 8. 작업 큐와 작업자

오래 걸리는 일(함께 검증하는 내보내기, 검증, AI 판단, 서비스 다시 확인)은 작업으로 기록되고 작업자가 가져가 실행합니다. API 프로세스는 기록만 합니다.

```bash
uv run python -m triage worker             # PostgreSQL 모드에서 필요
uv run python -m triage worker --once      # 큐를 비우고 종료
```

정상 동작:
- 파일 모드에서는 API 프로세스 안의 스레드가 작업자 역할을 해서 따로 띄울 것이 없습니다.
- 같은 실행에 같은 종류의 작업이 이미 대기 중이거나 실행 중이면 새로 만들지 않고 그 작업을 돌려줍니다.
- 작업자가 없으면 화면이 "떠 있는 작업자가 없어 시작하지 못하고 있습니다"라고 말합니다.
- 작업자가 도중에 죽으면 그 작업은 한 번 큐로 돌아가고, 다시 죽으면 `interrupted`로 끝납니다.
- 작업이 끝난 뒤 DB가 잠깐 끊겨도 결과 기록을 약 1분간 다시 시도합니다.

## 9. 저장 방식

| | 파일 (기본) | PostgreSQL |
|---|---|---|
| 설정 | `TRIAGE_STORE=file` | `TRIAGE_STORE=postgres`, `DATABASE_URL` |
| 기록 | `out/<run>/`과 `fixtures/cache/`의 JSON | 테이블 |
| 큰 산출물(SBOM, 로그, 패치) | `out/<run>/` | `out/<run>/` (두 모드 공통) |
| 준비 | 없음 | `docker compose -f deploy/docker-compose.yml up -d postgres`, `uv run python -m triage db init` |

정상 동작: 두 모드가 같은 결과를 냅니다. 이것은 `tests/test_store.py`가 양쪽으로 확인합니다. 파일로 쌓인 실행은 `uv run python -m triage db import --cache`로 DB에 옮깁니다.

## 10. 잘 돌아가는지 한 번에 확인하기

```bash
uv run python -m triage doctor             # 도구, 캐시, 설정 (--llm을 붙이면 모델 호출 1회)
uv run pytest -q                           # 테스트
bash kit/scripts/check.sh --fast           # 절대 규칙 정적 점검
bash kit/scripts/check.sh                  # 위에 더해 재생 스캔, git, 문서 점검
uv run python -m triage eval out/<run>     # 정답 라벨과의 일치율, NOW 누락
```

정상의 기준:
1. `doctor`에 실패 표시가 없습니다. API 키가 없다는 경고는 규칙만 쓸 때는 무시해도 됩니다.
2. 테스트가 전부 통과합니다. PostgreSQL 드라이버나 DB가 없으면 해당 테스트는 건너뜁니다.
3. `check.sh`가 0으로 끝납니다.
4. `eval`에서 **NOW 누락이 0건**입니다. NOW 누락은 정답이 NOW인데 최종 버킷이 MONITOR인 경우입니다. 일치율은 CVSS 정렬, 규칙 단독, 규칙과 AI 세 가지로 비교합니다.

## 11. 흔한 문제

| 증상 | 원인과 조치 |
|---|---|
| 재생 모드에서 Finding이 적거나 없음 | 캐시에 없는 대상입니다. 네트워크가 되는 곳에서 `DEMO_MODE=live`로 한 번 스캔하면 캐시가 채워집니다 |
| 화면이 비어 있음 | `out/`에 실행이 없습니다. 먼저 `scan`을 돌립니다. `out/`은 저장소에 포함되지 않습니다 |
| 화면이 404 | `web/dist`가 없습니다. `cd web && pnpm build` |
| 검증이 건너뛰어짐 | 재생 모드, 원본 저장소 없음, Docker 없음 가운데 하나입니다. 이벤트의 `why`에 적혀 있습니다 |
| 작업이 대기에서 움직이지 않음 | PostgreSQL 모드에서 작업자가 없습니다. `python -m triage worker` |
| 쓰기 요청이 전부 403 | `TRIAGE_PUBLIC_URL`이 브라우저의 주소와 다릅니다. 다른 사이트에서 온 쓰기를 막는 검사가 이 값을 씁니다 |
| AI 판단이 전부 규칙 결과로 남음 | 키가 없거나 모델 이름이 틀렸습니다. `doctor --llm`으로 확인합니다 |
| `fixtures/demo-repo`가 없다는 안내 | 대상 저장소는 포함되어 있지 않습니다. `README.md` 2장의 명령으로 받습니다 |

## 12. 하지 않는 것

1. AI가 점수를 내지 않습니다. 버킷을 두 단계 이상 옮기지 않습니다.
2. AI가 쓴 명령을 실행하지 않습니다.
3. 대상 저장소에 쓰기, 커밋, 푸시를 하지 않습니다.
4. 컨테이너 이미지, OS 패키지, 라이선스 검사는 범위 밖입니다.
5. 샌드박스 검증은 npm이 아닌 생태계를 지원하지 않습니다.
