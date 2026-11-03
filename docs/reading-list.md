# 학습 자료

URL은 2026-11-01에 직접 열어 확인했습니다. 시간은 본문 길이로 어림한 값입니다.

## 해커톤 전 필독 5개 (약 95분)

| 순서 | 자료 | 시간 | 연결되는 결정 |
|---|---|---|---|
| 1 | [OWASP LLM01:2025 Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) | 15분 | LLM 문자열을 실행하지 않는 규칙(D15, F8-11) |
| 2 | [Using EPSS](https://www.first.org/epss/using-epss) | 20분 | EPSS 배점, KEV 우선, CVSS 정렬 비교 |
| 3 | [Tool use with Claude](https://platform.claude.com/docs/en/agents-and-tools/tool-use/overview) | 25분 | 읽기 전용 도구와 호출 루프, `AgentVerdict` |
| 4 | [Docker Engine security](https://docs.docker.com/engine/security/) | 25분 | `--cap-drop ALL`, 자원 제한, 호스트 마운트 위험 |
| 5 | [CISA npm 공급망 침해 경보 (2025-09-23)](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem) | 10분 | 설치 단계 격리의 필요성 |

## 공급망 보안

- [CycloneDX Specification Overview](https://cyclonedx.org/specification/overview/) (20분): `sbom.cdx.json` 구조.
- [OSV API querybatch](https://google.github.io/osv.dev/post-v1-querybatch/) (10분): 응답은 ID 중심이고, 결과가 많으면 `next_page_token`으로 페이지를 넘깁니다.
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (10분): KEV 규칙(F6-9).
- [About SLSA v1.0](https://slsa.dev/spec/v1.0/about) (15분): SBOM과 빌드 무결성의 차이. 이 페이지는 Retired 표시가 있고 최신은 v1.2입니다.

## 우선순위 판단

- [Jacobs 외, Enhancing Vulnerability Prioritization (arXiv:2302.14172)](https://arxiv.org/abs/2302.14172) (20분, 초록과 도입부): EPSS가 심각도만 보는 방식보다 낫다는 근거.
- [Ponta 외, Beyond Metadata (ICSME 2018)](https://arxiv.org/abs/1806.05893) (25분, 초록과 도입부): 도달성 분석의 배경.

## AI 에이전트

- [Building effective agents (2024-12-19)](https://www.anthropic.com/engineering/building-effective-agents) (25분): 단순한 구조부터 시작하라는 권고. 도구 세부는 이후 바뀌었으니 개념 위주로 읽습니다.
- [How we contain Claude across products (2026-05-25)](https://www.anthropic.com/engineering/how-we-contain-claude) (20분): 승인 팝업보다 격리와 egress 제한을 신뢰하는 이유.
- [Writing effective tools for agents (2025-09-11)](https://www.anthropic.com/engineering/writing-tools-for-agents): 예비 자료.

## 샌드박스

- [npm install, ignore-scripts](https://docs.npmjs.com/cli/v10/commands/npm-install) (10분): 설치 스크립트는 건너뛰지만 `npm test`, `npm run`은 스크립트를 실행합니다.
- [Docker None network driver](https://docs.docker.com/engine/network/drivers/none/): 예비 자료.
- [Docker Running containers](https://docs.docker.com/engine/containers/run/): 예비 자료.

## 운영 설계

- [PostgreSQL Locking Clause](https://www.postgresql.org/docs/current/sql-select.html#SQL-FOR-UPDATE-SHARE) (10분): `SKIP LOCKED`의 용도와 범용 작업에 부적합하다는 경고.
- [You Don't Need a Job Queue, Postgres Already Has SKIP LOCKED (Prisma, 2026-07-17)](https://www.prisma.io/blog/you-dont-need-a-job-queue-postgres-already-has-skip-locked) (20분): 벤더 블로그. lease, 재시도, 멱등성.
- [Martin Kleppmann, How to do distributed locking (2016)](https://martin.kleppmann.com/2016/02/08/how-to-do-distributed-locking.html) (40분): fencing의 배경. Redis 부분은 가볍게 읽어도 됩니다.

## 해커톤 뒤에 읽을 책

- [Martin Kleppmann, Chris Riccomini, Designing Data-Intensive Applications 2판 (O'Reilly, 2026)](https://martin.kleppmann.com/2026/03/24/designing-data-intensive-applications-2e.html): 복제, 트랜잭션, 분산 시스템의 문제, 일관성과 합의 주제의 장만 읽습니다. 약 8~12시간으로 어림했고, 장 번호와 ISBN은 확인하지 못했습니다.

## 한국어 자료

- 『데이터 중심 애플리케이션 설계』, 위키북스, 2018: 원서 1판 번역서. 알라딘에 절판으로 표시됩니다. [알라딘 검색](https://www.aladin.co.kr/search/wsearchresult.aspx?SearchTarget=Book&SearchWord=%EB%8D%B0%EC%9D%B4%ED%84%B0+%EC%A4%91%EC%8B%AC+%EC%95%A0%ED%94%8C%EB%A6%AC%EC%BC%80%EC%9D%B4%EC%85%98+%EC%84%A4%EA%B3%84)
- 「SW 공급망 보안 가이드라인 1.0」(2024-04-18): 정부 합동 가이드라인. 원문 PDF URL은 확인하지 못했고, 확인한 것은 [보안뉴스 기사](http://www.boannews.com/news/articleView.html?idxno=128993)입니다. KISA 등 기관 사이트에서 찾아야 합니다.
- [NTIA SBOM Minimum Elements (2021)](https://www.ntia.gov/report/2021/minimum-elements-software-bill-materials-sbom): 영문 예비 자료.
