# SBOM Triage Agent

저장소나 SBOM의 취약점을 CVSS 순서의 목록으로 보여 주지 않고 **NOW, NEXT, MONITOR** 세 버킷으로 나눕니다. 항목마다 근거를 붙이고, 조치안은 일회용 컨테이너에서 실제로 적용해 본 뒤 결과와 함께 내놓습니다.

롯데 AX 챌린지 본선(롯데이노베이트 SW 공급망 과제)을 위해 만들었습니다.

## 1. 무엇을 하는가

```
입력 (저장소, SBOM 파일, 스캐너 결과, lock 파일, 표)
  → ① SBOM 생성        Syft 또는 lock 파일 직접 해석
  → ② 취약점 조회      OSV
  → ③ 보강             EPSS, CISA KEV, 수정 버전과 semver 점프, import 위치
  → ④ 규칙 점수        순수 함수. 같은 입력이면 같은 버킷
  → ⑤ AI 판단          실제 호출 여부 확인, 버킷을 한 단계까지만 조정, 근거와 조치안
  → ⑥ 샌드박스 검증    조치안 적용 → 설치 → 빌드와 테스트 → 재스캔
  → ⑦ 대시보드         버킷, 근거, 검증 결과, 담당자 승인, 패치 내보내기
```

- 점수는 코드가 냅니다. AI는 규칙 버킷을 한 단계까지만 옮길 수 있고 옮길 때는 이유를 적어야 합니다.
- AI가 쓴 명령은 실행하지 않습니다. 샌드박스 명령은 검증된 값(종류, 패키지, 버전)으로 코드가 조립합니다.
- 분석 대상 저장소는 고치지 않습니다. 변경은 컨테이너 안의 사본에만 적용하고, 승인한 변경은 패치 파일과 PR 초안으로 내보냅니다.

기능별로 무엇이 나와야 정상인지는 [docs/GUIDE.md](docs/GUIDE.md)에 있습니다.

## 2. 빠른 시작

필요한 것: Python 3.12, [uv](https://docs.astral.sh/uv/). 대시보드를 고치려면 Node 22와 pnpm, 샌드박스 검증에는 Docker, 저장소 스캔의 정확도를 높이려면 [Syft](https://github.com/anchore/syft)가 필요합니다.

```bash
uv sync                                   # 기본 설치
uv run pytest -q                          # 테스트 (PostgreSQL 테스트는 드라이버와 DB가 없으면 건너뜁니다)
uv run python -m triage doctor            # 환경 점검
```

네트워크, Docker, API 키 없이 바로 돌려 볼 수 있습니다. 저장소에 들어 있는 응답 캐시(`fixtures/cache/`)를 읽습니다.

```bash
DEMO_MODE=replay uv run python -m triage scan fixtures/blind/sbom-a.cdx.json
```

결과는 `out/<실행 id>/`에 쌓이고, 화면으로 보려면 대시보드를 빌드한 뒤 API를 띄웁니다.

```bash
cd web && pnpm install && pnpm build && cd ..
DEMO_MODE=replay uv run uvicorn triage.api:app      # http://localhost:8000
```

실제 조회와 AI 판단을 쓰려면 `.env.example`을 `.env`로 복사해 값을 채웁니다. `.env`는 커밋하지 않습니다.

```bash
uv run python -m triage run <저장소 경로>           # ①~⑥ 한 번에
```

데모 대상 저장소는 라이선스가 없어 이 저장소에 넣지 않았습니다. `fixtures/demo-repo.ref`에 적힌 주소와 커밋으로 받습니다.

```bash
git clone https://github.com/gothinkster/node-express-realworld-example-app fixtures/demo-repo
git -C fixtures/demo-repo checkout 30b68e1e881462b2f4164ea09ab4c4f5699c7b0b
```

## 3. 실행 방식

같은 코드가 세 가지 방식으로 돕니다. 분석 결과는 방식과 무관하게 같습니다.

| 방식 | 저장 | 작업자 | 언제 |
|---|---|---|---|
| 단독 (기본) | 파일 (`out/`, `fixtures/cache/`) | API 프로세스 안의 스레드 | 로컬 작업, 오프라인 재생 |
| Compose | PostgreSQL (`deploy/docker-compose.yml`) | 별도 프로세스 `python -m triage worker` | 한 대에서 운영 |
| 쿠버네티스 | PostgreSQL (클러스터 안 또는 밖) | 작업자 Deployment | 여러 노드에서 운영. [deploy/k8s/README.md](deploy/k8s/README.md) |

선택은 환경 변수로 합니다: `TRIAGE_STORE`(`file`, `postgres`), `TRIAGE_WORKER`(`inline`, `external`), `TRIAGE_AUTH`(`off`, `oidc`), `DEMO_MODE`(`live`, `replay`). 전체 목록과 설명은 [.env.example](.env.example)에 있습니다.

## 4. AI 모델 설정

모델과 제공자는 환경 변수로 넣고 코드에 모델 이름을 쓰지 않습니다.

| 설정 | 동작 |
|---|---|
| `LLM_PROVIDER=anthropic` | 기본. 모델은 `LLM_MODEL` |
| `LLM_PROVIDER=openai` | OpenAI 어댑터. 실제 호출로 확인하지 않았습니다 |
| `LLM_PROVIDER=local` | OpenAI 호환 서버(Ollama, vLLM 등). `LOCAL_LLM_BASE_URL`, `LOCAL_LLM_MODEL` |
| `LLM_PROVIDER=none` | 규칙 결과만 |
| `LLM_CODE_PROVIDER=local` | 2단계 모드. 사내 모델만 소스코드를 읽고, `LLM_PROVIDER`의 모델은 사실(패키지, 버전, 점수, 판독 결과)만 받아 판단문을 씁니다 |

## 5. 디렉터리

```
backend/triage/   파이프라인, 에이전트, 샌드박스, 저장 계층, 작업 큐, API
web/              React 대시보드 (빌드 결과를 FastAPI가 서빙)
tests/            pytest
fixtures/         응답 캐시(재생용), 시험용 SBOM, 정답 라벨, 대상 저장소 참조
deploy/           docker-compose.yml(PostgreSQL), k8s/(쿠버네티스 매니페스트)
kit/              본선 현장용 절차서, 문서 틀, 점검 스크립트
docs/             요구사항, 사용 가이드, 설계 검토, 본선 문서
poc/              초기 실험 스크립트 (제품 코드가 아님)
out/              실행 결과 (git 제외)
```

## 6. 문서 지도

| 문서 | 내용 | 상태 |
|---|---|---|
| [docs/GUIDE.md](docs/GUIDE.md) | 핵심 기능과 정상 동작 기준, 확인 방법, 흔한 문제 | 현행 |
| [AGENTS.md](AGENTS.md) | 코딩 에이전트(Codex 등)가 이 파일 하나로 작업을 시작하기 위한 요약 | 현행 |
| [CLAUDE.md](CLAUDE.md) | 스택, 디렉터리, 절대 규칙 11개, 명령 모음, 용어 | 현행. 규칙의 원문 |
| [HARNESS.md](HARNESS.md) | 작업 순서와 단계별 통과 조건, 날짜별 진행 기록 | 현행. 7장은 누적 기록 |
| [HANDOFF.md](HANDOFF.md) | 결정 이력 D1 ~ D53과 이유 | 2장만 현행. 나머지는 초기 기록 |
| [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md) | 요구사항 원본. 문서가 충돌하면 이 문서가 우선 | 현행 |
| [deploy/k8s/README.md](deploy/k8s/README.md) | 쿠버네티스 구성, 운영에 올릴 때 바꿀 것, 확인한 것과 한계 | 현행 |
| [docs/onprem-llm.md](docs/onprem-llm.md) | 사내 LLM과 2단계 모드의 배경 | 참고 |
| [docs/reviews/](docs/reviews/) | 설계 비판 검토 3회와 지적 사항 | 이력. 수정 내용은 HANDOFF D50, D52 |
| [docs/poc-results.md](docs/poc-results.md) | 초기 실험 결과 | 이력 |
| [docs/labeling-guide.md](docs/labeling-guide.md) | 정답 라벨을 매기는 기준 | 현행 |
| [docs/finals/](docs/finals/) | 본선 현장에서 채우는 문서 틀 (과제 정리, 차이 분석, 결정 등) | 대부분 비어 있음 |
| [kit/README.md](kit/README.md) | 본선용 하네스 키트 설명 | 현행 |
| [kit/CODEX.md](kit/CODEX.md) | Codex CLI로 이어 갈 때의 준비 과정: 설치, 권한 설정, 사전 확인, 본선 당일의 첫 문장 | 현행. 사람용 |
| [docs/architecture/](docs/architecture/) | 아키텍처 다이어그램 (HTML 파일을 브라우저로 엽니다) | 2026-11-23 기준 |

## 7. 확인한 것과 하지 않은 것

- 테스트 269개가 통과합니다. PostgreSQL이 없으면 해당 테스트는 건너뜁니다.
- 쿠버네티스 구성은 k3s 3노드 시험 클러스터에서 확인했습니다. 실제 NFS, 관리형 DB 제품, 공인 인증서, 노드 장애는 확인하지 않았습니다.
- 2단계 모드는 Ollama의 `qwen2.5:7b`로 한 번 돌렸습니다. 외부 모델로 나간 요청에 코드와 파일 이름이 없는 것은 확인했고, 7B 모델의 판독 정확도는 낮았으며 정답 라벨로 측정하지 않았습니다.
- OpenAI 어댑터는 실제 호출로 확인하지 않았습니다.
- 지원하는 생태계는 OSV가 다루는 범위이고, 샌드박스 검증은 npm 저장소만 됩니다.

## 8. 기여와 보안 규칙

- 비밀값은 `.env`에만 둡니다. 코드, 로그, `out/`, 커밋에 키를 남기지 않습니다.
- 분석 대상 저장소(`fixtures/demo-repo/`, `fixtures/eval/`)와 제공 자료(`data/`)는 고치지 않습니다.
- 커밋 메시지는 `feat(score): ...`처럼 단계 이름을 scope로 씁니다.
- 바꾸기 전과 후에 `uv run pytest -q`와 `bash kit/scripts/check.sh --fast`를 돌립니다.
