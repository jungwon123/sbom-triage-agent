# 학습 자료

개념의 뜻은 `docs/keywords.md`에 있고, 이 문서는 그 개념을 원문으로 읽을 때의 목록입니다. 시간은 본문 길이로 어림한 값입니다.

주소를 확인한 날짜는 두 가지입니다.

- "운영을 위해 읽을 것" 장의 자료는 2026-11-24에 열어 확인했습니다. 전부 공식 문서나 표준 문서입니다.
- 그 밖의 자료는 2026-11-01에 열어 확인했습니다. 그 뒤에 다시 열어 보지 않았습니다.

## 지금 읽는다면 (약 75분)

쿠버네티스와 운영 부분이 낯설 때 먼저 읽을 다섯 개입니다. 아래 "운영을 위해 읽을 것"에서 골랐습니다.

| 순서 | 자료 | 시간 | 읽고 나면 설명할 수 있는 것 |
|---|---|---|---|
| 1 | [쿠버네티스란 무엇인가? (한국어)](https://kubernetes.io/ko/docs/concepts/overview/) | 10분 | 쿠버네티스가 무엇을 대신해 주는가 |
| 2 | [Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/) | 15분 | 작업자의 나가는 통신을 어떻게 가두었는가 |
| 3 | [Sidecar Containers](https://kubernetes.io/docs/concepts/workloads/pods/sidecar-containers/) | 5분 | Docker 데몬이 작업자보다 먼저 뜨고 나중에 내려가는 이유 |
| 4 | [Cross-Site Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) | 20분 | 쓰기 요청의 `Origin`을 왜 검사하는가 |
| 5 | [RFC 7636: Proof Key for Code Exchange](https://datatracker.ietf.org/doc/html/rfc7636) | 25분 | PKCE가 막는 공격과 `S256` |

## 판단 구조를 위해 먼저 읽을 5개 (약 95분)

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

## 운영을 위해 읽을 것 (2026-11-24 확인)

괄호 안의 D숫자는 `HANDOFF.md` 2장의 결정 번호입니다.

### 입력 형식

- [Package-URL (PURL) Specification](https://github.com/package-url/purl-spec) (5분): 패키지를 가리키는 표준 주소입니다. 형식은 `scheme:type/namespace/name@version?qualifiers#subpath`이고 예는 `pkg:pypi/django@1.11.1`입니다. SBOM의 컴포넌트를 OSV에 물을 때 씁니다.
- [SPDX Overview](https://spdx.dev/learn/overview/) (10분): CycloneDX와 함께 받는 또 하나의 SBOM 표준입니다.
- [Open Source Vulnerability format](https://ossf.github.io/osv-schema/) (45분, 필요한 필드만): `affected[].ranges`가 수정 버전의 출처입니다. ID 접두사 표에 악성 패키지용 `MAL`이 있습니다(D44).

### 저장 계층 (D45, D52)

- [PostgreSQL JSON Types](https://www.postgresql.org/docs/current/datatype-json.html) (25분): `json`은 입력 문자열을 그대로 두고 `jsonb`는 분해한 이진 형식이라 처리와 색인이 빠릅니다. 본문을 `jsonb`로 저장하는 이유입니다.
- [PostgreSQL Explicit Locking, 13.3.5 Advisory Locks](https://www.postgresql.org/docs/current/explicit-locking.html) (5분, 해당 절만): 세션 단위와 트랜잭션 단위의 차이. 테이블 생성을 직렬화할 때 트랜잭션 단위를 씁니다.
- [psycopg 3 Connection pools](https://www.psycopg.org/psycopg3/docs/advanced/pool.html) (15분): 연결을 빌려줄 때 검사하는 `check`와 `ConnectionPool.check_connection`. 생성자에서 바로 여는 기본 동작이 좋은 선택이 아니었다는 설명이 있고, 예제는 `open=False`로 만든 뒤 명시적으로 엽니다.
- [libpq Database Connection Control Functions](https://www.postgresql.org/docs/current/libpq-connect.html) (20분, 매개변수 표만): `connect_timeout`, `keepalives_idle`, `sslmode`. `sslmode`의 값은 `disable`, `allow`, `prefer`, `require`, `verify-ca`, `verify-full`입니다.
- [Python os.replace](https://docs.python.org/3/library/os.html#os.replace) (5분): 성공하면 원자적으로 바뀝니다. 내보내기 폴더를 바꿔 넣을 때 씁니다.

### 작업 큐 (D46)

- [PostgreSQL Locking Clause](https://www.postgresql.org/docs/current/sql-select.html#SQL-FOR-UPDATE-SHARE) (10분, 2026-11-01 확인): `SKIP LOCKED`의 용도와 범용 작업에 부적합하다는 경고.
- [You Don't Need a Job Queue, Postgres Already Has SKIP LOCKED (Prisma, 2026-07-17)](https://www.prisma.io/blog/you-dont-need-a-job-queue-postgres-already-has-skip-locked) (20분, 2026-11-01 확인): 벤더 블로그. lease, 재시도, 멱등성.
- [Martin Kleppmann, How to do distributed locking (2016)](https://martin.kleppmann.com/2016/02/08/how-to-do-distributed-locking.html) (40분, 2026-11-01 확인): fencing의 배경. Redis 부분은 가볍게 읽어도 됩니다.

### 로그인과 권한 (D47)

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) (3.1절과 3.1.3.7절만, 약 15분): 인가 코드 흐름과 ID 토큰 검증 항목(`iss`, `aud`, `exp`, `nonce`). `auth.py`의 `verify_id_token`이 이 항목을 검사합니다.
- [RFC 7636: Proof Key for Code Exchange](https://datatracker.ietf.org/doc/html/rfc7636) (25분): `code_challenge_method`는 `plain`과 `S256` 두 가지이고 이 프로젝트는 `S256`만 씁니다.
- [RFC 9700: Best Current Practice for OAuth 2.0 Security](https://datatracker.ietf.org/doc/html/rfc9700) (전체 100분, 2.1절만 읽어도 됩니다): PKCE를 쓰라는 권고의 출처입니다.
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) (20분): `Origin` 헤더 확인과 Fetch Metadata(`Sec-Fetch-Site`). 이 프로젝트가 쓰는 두 가지입니다.
- [MDN Using HTTP cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Cookies) (15분): `HttpOnly`, `Secure`, `SameSite`.

### 컨테이너와 쿠버네티스 (D51, D52, D53)

- [Kubernetes Overview](https://kubernetes.io/docs/concepts/overview/) (5분): 한국어판은 [쿠버네티스란 무엇인가?](https://kubernetes.io/ko/docs/concepts/overview/) (10분).
- [Deployments](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/) (20분 이상, 앞부분만): 롤링 업데이트. 기본값은 한 번에 25%까지 내려가고 25%까지 더 뜹니다.
- [Service](https://kubernetes.io/docs/concepts/services-networking/service/) (30분, 앞부분만): 파드의 주소는 바뀌므로 고정된 이름이 필요합니다.
- [Ingress](https://kubernetes.io/docs/concepts/services-networking/ingress/) (15분): 인그레스 컨트롤러가 따로 있어야 동작합니다. 이 페이지는 Ingress API가 동결되었고 Gateway API를 권한다고 적고 있습니다. 이 저장소의 구성은 Ingress를 씁니다.
- [Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/) (15분): 정책을 지원하는 네트워크 플러그인이 있어야 적용됩니다. `ipBlock`과 `except`, 정책은 더해진다는 점. `worker-egress`와 `worker-reaches-llm`이 이 세 가지를 씁니다.
- [Sidecar Containers](https://kubernetes.io/docs/concepts/workloads/pods/sidecar-containers/) (5분): `initContainers`에 `restartPolicy: Always`로 선언합니다. 1.29부터 기본으로 켜져 있고 1.33에서 안정화되었습니다.
- [Secrets](https://kubernetes.io/docs/concepts/configuration/secret/) (20분): 기본 설정에서는 etcd에 암호화되지 않은 채 저장된다는 경고가 있습니다. Secret을 쓴다고 해서 저장 시 암호화까지 되는 것은 아닙니다.
- [Persistent Volumes](https://kubernetes.io/docs/concepts/storage/persistent-volumes/) (25분, 접근 방식 부분만): `ReadWriteOnce`, `ReadOnlyMany`, `ReadWriteMany`, `ReadWriteOncePod`. `out/`은 노드가 여럿이면 `ReadWriteMany`가 필요합니다.
- [Specifying a Disruption Budget](https://kubernetes.io/docs/tasks/run-application/configure-pdb/) (10분): `maxUnavailable`의 뜻. 계획된 중단에만 적용됩니다.
- [Declarative Management of Kubernetes Objects Using Kustomize](https://kubernetes.io/docs/tasks/manage-kubernetes-objects/kustomization/) (15분): `configMapGenerator`가 내용의 해시를 이름에 붙이는 것, base와 overlay.
- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/) (10분): Privileged, Baseline, Restricted 세 단계. 특권 컨테이너는 Baseline에서 금지됩니다. 샌드박스 사이드카가 특권 컨테이너라서, 이 기준을 강제하는 클러스터에서는 쓸 수 없습니다.
- [Docker Compose](https://docs.docker.com/compose/) (5분): 여러 컨테이너를 YAML 하나로 띄우는 도구. 쿠버네티스 없이 한 대에서 운영할 때의 방식입니다.

### 저장소 공개

- [About secret scanning](https://docs.github.com/en/code-security/secret-scanning/introduction/about-secret-scanning) (5분): 깃허브가 저장소에서 키와 토큰을 찾아 알리는 기능. 공개 권고문 본문의 문자열을 키로 잘못 알린 사례가 이 저장소에 한 건 있었습니다.

## 나중에 읽을 책

- [Martin Kleppmann, Chris Riccomini, Designing Data-Intensive Applications 2판 (O'Reilly, 2026)](https://martin.kleppmann.com/2026/03/24/designing-data-intensive-applications-2e.html): 복제, 트랜잭션, 분산 시스템의 문제, 일관성과 합의 주제의 장만 읽습니다. 약 8~12시간으로 어림했고, 장 번호와 ISBN은 확인하지 못했습니다.

## 한국어 자료

- 『데이터 중심 애플리케이션 설계』, 위키북스, 2018: 원서 1판 번역서. 알라딘에 절판으로 표시됩니다. [알라딘 검색](https://www.aladin.co.kr/search/wsearchresult.aspx?SearchTarget=Book&SearchWord=%EB%8D%B0%EC%9D%B4%ED%84%B0+%EC%A4%91%EC%8B%AC+%EC%95%A0%ED%94%8C%EB%A6%AC%EC%BC%80%EC%9D%B4%EC%85%98+%EC%84%A4%EA%B3%84)
- 「SW 공급망 보안 가이드라인 1.0」(2024-04-18): 정부 합동 가이드라인. 원문 PDF URL은 확인하지 못했고, 확인한 것은 [보안뉴스 기사](http://www.boannews.com/news/articleView.html?idxno=128993)입니다. KISA 등 기관 사이트에서 찾아야 합니다.
- [NTIA SBOM Minimum Elements (2021)](https://www.ntia.gov/report/2021/minimum-elements-software-bill-materials-sbom): 영문 예비 자료.
