# 쿠버네티스 배포 (HANDOFF D51)

API와 작업자를 한 이미지로 올리고, 기록은 PostgreSQL에, 큰 산출물(`out/`)은 볼륨에 둡니다.

> 확인한 범위 (2026-11-23), 클러스터 두 곳.
>
> 1. Docker Desktop의 Kubernetes(v1.34.1, 노드 1개)에 `overlays/local`: 초기화 컨테이너의 테이블 생성, 프로브 통과, API 복제 2개, API로 서비스를 등록하고 작업자 파드가 다시 확인을 처리해 실행을 만드는 것(OSV, EPSS, KEV 실조회), 읽기 전용 루트 파일시스템과 uid 10001, 작업자 재시작, 다른 출처의 쓰기 요청 403.
> 2. k3s v1.31.5(노드 3개, 네트워크 정책을 강제)에 `overlays/multinode`: 아래 표. 절차는 6번.
>
> | 항목 | 확인한 것 |
> |---|---|
> | 네트워크 정책 | 다른 네임스페이스와 라벨 없는 파드에서 DB 5432 차단, `triage/db-client` 라벨이 있는 파드만 접속. 정책에 없는 파드의 포트는 네임스페이스 안팎 모두 차단. DB 파드에서 바깥으로 나가는 통신 차단. API 8000은 열림(의도), 애플리케이션의 바깥 조회는 열림(의도) |
> | 샌드박스 사이드카 | 작업자 파드 안에서 기준선과 3개 패키지 검증이 모두 `verified`(테스트 2개 실행, 패치 3개 생성). 화면의 "함께 검증하고 내보내기"가 큐를 거쳐 작업자에서 `verified`. 끝난 뒤 남은 컨테이너와 볼륨 0개. 데몬은 파드의 루프백에서만 수신 |
> | 인그레스 | Traefik에서 TLS를 끝내고 화면과 API 200, 다른 출처의 쓰기 요청 403, `TRIAGE_PUBLIC_URL`과 같은 출처의 쓰기는 통과 |
> | ReadWriteMany 볼륨 | 작업자(노드 1)가 쓴 실행과 패치를 다른 두 노드의 API 파드가 읽음. API 복제는 서로 다른 노드에 배치. `/repos`는 읽기 전용 |
> | 클러스터 밖 DB | `sslmode=require`로 접속, DB 쪽에서 세 노드의 연결이 모두 TLS 1.3인 것을 확인. 초기화 컨테이너가 테이블 생성 |
>
> 이 과정에서 찾아 고친 것 세 가지: 사이드카의 데몬 인자 충돌(데몬이 뜨지 않았음), 샌드박스 복사 단계가 파일 소유자를 보존하려다 실패, 사이드카의 MTU가 파드 네트워크보다 커서 `npm install`이 시간 초과. 4번에 적었습니다.
>
> 여전히 확인하지 못한 것: 실제 NFS나 CephFS(시험은 모든 노드가 같은 디렉터리를 마운트하는 방식), 클라우드의 관리형 DB 제품(시험은 클러스터 밖에 띄운 TLS PostgreSQL), 공인 인증서와 실제 도메인, Calico나 Cilium(시험은 k3s 내장 정책 컨트롤러), 로그인을 켠 상태(`TRIAGE_AUTH=oidc`)의 인그레스 경유 로그인, 작업 도중 노드가 죽었을 때의 이어받기.

## 1. 구성

| 경로 | 내용 |
|---|---|
| `../../Dockerfile` | 이미지 하나. 기본 명령은 API(`uvicorn`), 작업자는 `python -m triage worker` |
| `base/` | 네임스페이스, 설정(ConfigMap), 볼륨 요청 2개(`out`, `repos`), API(Deployment 2개 복제 + Service), 작업자(Deployment), 네트워크 정책, PodDisruptionBudget |
| `components/postgres/` | 클러스터 안 PostgreSQL(시험용). 운영은 백업이 되는 관리형 DB를 쓰고 이 항목을 뺍니다 |
| `components/sandbox-dind/` | 작업자에 Docker 데몬 사이드카를 붙여 샌드박스 검증을 돌립니다. **특권 컨테이너**입니다(아래 4번) |
| `components/ingress/` | 인그레스. 호스트와 TLS 시크릿 이름을 고쳐 씁니다 |
| `overlays/local/` | 노드 하나짜리 시험 클러스터용: PostgreSQL 포함, 복제 1개, ReadWriteOnce 볼륨 |
| `overlays/multinode/` | 노드가 여러 개인 클러스터용(운영 구성의 모양): 클러스터 밖 DB, ReadWriteMany 볼륨, 샌드박스 사이드카, 인그레스. 6번 참고 |
| `secrets.example.env` | 시크릿에 넣을 값의 틀. 채운 파일은 커밋하지 않습니다 |

## 2. 시험 클러스터에 올리기

Docker Desktop의 Kubernetes, kind, minikube 가운데 하나가 켜져 있어야 합니다.

```bash
docker build -t sbom-triage:dev .
```

kind를 쓰면 이미지를 클러스터에 넣습니다(Docker Desktop은 필요 없음).

```bash
kind load docker-image sbom-triage:dev
```

시크릿을 만들고 올립니다. `secrets.example.env`를 저장소 밖으로 복사해 값을 채운 파일을 씁니다.

```bash
kubectl create namespace sbom-triage
```

```bash
kubectl -n sbom-triage create secret generic triage-secrets --from-env-file=<채운 파일>
```

```bash
kubectl apply -k deploy/k8s/overlays/local
```

선택 항목(`components/`)을 넣은 조합을 새로 만들 때는 그 kustomization에도 `namespace: sbom-triage`를 적어야 합니다. `base`의 네임스페이스 설정은 선택 항목이 추가한 리소스에 닿지 않아서, 빠뜨리면 DB가 `default` 네임스페이스에 생깁니다(처음 올렸을 때 실제로 겪은 문제입니다).

```bash
kubectl -n sbom-triage rollout status deploy/triage-api
```

```bash
kubectl -n sbom-triage port-forward svc/triage-api 8000:80
```

지울 때는 네임스페이스를 지웁니다(DB와 볼륨의 데이터도 함께 지워집니다).

```bash
kubectl delete namespace sbom-triage
```

브라우저에서 `http://localhost:8000`을 엽니다. `GET /api/health`의 `queue.workers`가 1 이상이면 작업자가 붙은 것입니다.

분석할 저장소나 SBOM 파일은 `triage-repos` 볼륨(파드 안의 `/repos`)에 있어야 합니다. 이 애플리케이션은 코드를 스스로 받아 오지 않습니다.

## 3. 운영에 올릴 때 바꿀 것

1. **DB**: `components/postgres`를 빼고 `DATABASE_URL`을 관리형 PostgreSQL로 둡니다. 주소 끝에 `?sslmode=require`를 붙이면 TLS로만 붙습니다(인증서까지 검증하려면 `sslmode=verify-full`과 `sslrootcert`). 테이블은 API 파드의 초기화 컨테이너(`triage db init`)가 만듭니다. 애플리케이션 계정에는 테이블을 만들 권한이 필요합니다.
2. **볼륨**: 노드가 둘 이상이면 `out`과 `repos`는 ReadWriteMany여야 합니다(NFS, CephFS, EFS 등). AI 판단 재사용과 패치 내보내기가 `out/`의 파일을 읽기 때문입니다.
3. **주소와 로그인**: `TRIAGE_PUBLIC_URL`을 사람들이 쓰는 https 주소로 두고 `TRIAGE_AUTH=oidc`와 `OIDC_*` 값을 넣습니다. 인그레스에서 TLS를 끝내는 구성에서 `TRIAGE_PUBLIC_URL`이 틀리면 모든 쓰기 요청이 403이 됩니다.
4. **이미지**: 사내 레지스트리에 올리고 `base/kustomization.yaml`의 `images`에서 이름과 태그를 바꿉니다. 태그는 `dev` 대신 커밋 해시를 씁니다.
5. **바깥으로 나가는 통신**: API와 작업자는 열려 있습니다. OSV, EPSS, KEV, 모델 제공자, 인증 서버 주소가 정해지면 egress 정책으로 좁힙니다. 클러스터 안 DB 파드는 바깥으로 나가지 못하게 막아 두었습니다.
6. **API로 들어오는 통신**: API 파드의 8000번은 클러스터 안 어디서나 열려 있습니다(다른 네임스페이스 포함). 인그레스 컨트롤러의 네임스페이스가 정해지면 `api-accepts-http` 정책의 출발지를 그곳으로 좁힙니다.
7. **http 접속**: 인그레스 구성은 https만 강제하지 않습니다. 시험 클러스터의 Traefik은 80번으로도 같은 화면을 내주었습니다. 컨트롤러 쪽에서 https로 돌리는 설정을 켭니다.

## 4. 샌드박스 검증과 특권 컨테이너

검증 단계는 `docker run`으로 일회용 컨테이너를 띄웁니다. 파드 안에는 Docker 데몬이 없으므로 기본 구성에서는 검증을 건너뛰고 그 사실이 이벤트에 남습니다(분류, AI 판단, 서비스 다시 확인은 그대로 됩니다).

`components/sandbox-dind`는 작업자 파드에 Docker 데몬(dind)을 특권 사이드카로 붙입니다. 특권 컨테이너는 노드에 접근할 수 있으므로 다음을 지켜야 합니다.

- 이 용도로만 쓰는 노드에 올립니다(taint와 toleration, nodeSelector).
- 데몬은 파드의 루프백에서만 듣고 자격 증명이 없습니다. 애플리케이션의 시크릿은 샌드박스 컨테이너에 전달하지 않습니다(절대 규칙 7).
- 데몬 인자는 `dockerd`로 시작해야 합니다. 옵션만 주면 이미지의 시작 스크립트가 `0.0.0.0:2375`를 덧붙여 루프백 주소와 충돌하고(데몬이 뜨지 않음), 떴다면 파드 주소로 데몬이 노출됩니다.
- 데몬의 MTU는 1400으로 낮춰 두었습니다. 파드 네트워크의 MTU가 1500보다 작은 클러스터(VXLAN은 1450)에서 Docker 기본값 1500을 쓰면 샌드박스 안의 `npm install`이 응답 없이 시간 초과됩니다.
- 저장소 파일의 소유자가 루트가 아니어도 됩니다. 샌드박스의 복사 단계는 소유자를 보존하지 않습니다.
- 사이드카를 새로 띄울 때마다 샌드박스 이미지(node:20-slim)를 다시 받습니다. 이미지 캐시가 파드의 임시 볼륨에 있기 때문입니다.
- 클러스터 정책이 특권 컨테이너를 금지하면 쓸 수 없습니다. 그때는 검증만 클러스터 밖의 작업자(Docker가 있는 VM에서 `python -m triage worker`, 같은 DB와 `out/` 공유)로 돌립니다.

특권 없이 파드마다 격리하는 방식(쿠버네티스 Job으로 검증 실행, gVisor나 Kata)은 만들지 않았습니다.

## 5. 동작 방식 메모

- API는 상태가 없습니다. 세션은 서명한 쿠키이고 기록은 DB에 있어서 복제 수를 늘려도 됩니다.
- 작업자 하나는 작업을 하나씩 처리합니다. 복제 수가 곧 동시에 도는 작업 수입니다. 같은 서비스의 확인은 DB의 고유 인덱스가 하나로 막습니다.
- 작업자는 종료 신호를 받으면 하던 작업을 끝내고 내려갑니다(유예 15분). 그 전에 강제로 죽으면 30초 뒤 다른 작업자가 한 번 이어받습니다.
- 준비 상태 점검(`/api/health`)은 저장소를 읽으므로 DB가 끊긴 파드는 트래픽에서 빠집니다. 생존 점검은 포트만 보므로 DB 장애로 파드가 전부 재시작되지는 않습니다.

## 6. 노드가 여러 개인 시험 클러스터 (`overlays/multinode`)

정책을 강제하는 클러스터가 없을 때 k3s 노드 3개를 Docker 컨테이너로 띄워 확인한 절차입니다. 호스트에 설치하는 것은 없습니다. 아래에서 `<토큰>`과 `<비밀번호>`는 직접 만든 무작위 값입니다.

```bash
docker network create triage-k3s && docker volume create triage-k3s-shared
```

```bash
docker run -d --name triage-k3s-server --hostname k3s-server --privileged --network triage-k3s -p 127.0.0.1:6550:6443 -p 127.0.0.1:8444:443 -e K3S_TOKEN=<토큰> -v triage-k3s-shared:/shared rancher/k3s:v1.31.5-k3s1 server --tls-san 127.0.0.1
```

에이전트 노드는 이름만 바꿔 두 번 띄웁니다(`agent1`, `agent2`).

```bash
docker run -d --name triage-k3s-agent1 --hostname k3s-agent1 --privileged --network triage-k3s -e K3S_URL=https://triage-k3s-server:6443 -e K3S_TOKEN=<토큰> -v triage-k3s-shared:/shared rancher/k3s:v1.31.5-k3s1 agent
```

접속 설정은 서버 노드의 `/etc/rancher/k3s/k3s.yaml`을 꺼내 포트를 6550으로 바꾼 파일을 `KUBECONFIG`로 지정합니다(`~/.kube/config`는 건드리지 않습니다). 이미지는 노드마다 넣습니다.

```bash
docker save sbom-triage:dev | docker exec -i triage-k3s-server ctr images import -
```

공유 디렉터리를 만듭니다. `out`은 uid 10001이 쓸 수 있어야 합니다.

```bash
docker exec triage-k3s-server sh -c 'mkdir -p /shared/out /shared/repos && chown 10001:10001 /shared/out'
```

DB는 클러스터 밖에 둡니다. 시크릿의 `DATABASE_URL`은 `postgresql://triage:<비밀번호>@<DB 주소>:5432/triage?sslmode=require` 꼴이고, 인그레스용 TLS 시크릿 `triage-tls`를 함께 만듭니다.

```bash
kubectl -n sbom-triage create secret tls triage-tls --cert=<인증서> --key=<키>
```

```bash
kubectl apply -k deploy/k8s/overlays/multinode
```

접속 주소는 `https://triage.localhost:8444`입니다(자체 서명 인증서라 브라우저 경고가 뜹니다). 지울 때는 컨테이너 4개(`triage-k3s-server`, `triage-k3s-agent1`, `triage-k3s-agent2`, DB), 네트워크 `triage-k3s`, 볼륨 `triage-k3s-shared`를 지웁니다.

실제 클러스터에 맞출 때는 `volumes.yaml`을 그 클러스터의 ReadWriteMany 볼륨으로, 호스트 이름과 `TRIAGE_PUBLIC_URL`을 실제 주소로 바꿉니다.
