# 계획: yarn과 pnpm 저장소의 샌드박스 검증

상태: 계획만 있고 구현하지 않았습니다 (2026-11-24). 이 문서는 구현하는 사람이나 코딩 에이전트가 이것만 읽고 시작할 수 있게 썼습니다.

## 1. 지금 되는 것과 안 되는 것

| 단계 | npm (`package-lock.json`) | yarn (`yarn.lock`) | pnpm (`pnpm-lock.yaml`) |
|---|---|---|---|
| ① SBOM, ② 조회, ③ 보강 | 됩니다 | 됩니다 | 됩니다 |
| ④ 규칙 점수, ⑤ AI 판단 | 됩니다 | 됩니다 | 됩니다 |
| ⑥ 샌드박스 검증 | 됩니다 | 안 됩니다 | 안 됩니다 |
| 패치 내보내기 | 됩니다 | 안 됩니다 | 안 됩니다 |

분류는 세 가지 모두 됩니다. 같은 npm 레지스트리의 패키지이고 lock 파일 해석기(`ingest.parse_yarn_lock`, `ingest.parse_pnpm_lock`)가 이미 있기 때문입니다. 검증만 npm 명령과 `package-lock.json`에 묶여 있습니다.

yarn이나 pnpm 저장소에 검증을 돌리면 어떻게 되는지는 실제로 확인하지 않았습니다. 코드로 보면 기준선의 `npm ci`가 `package-lock.json`이 없어 실패하고 `inconclusive`로 끝날 것으로 예상합니다. 구현의 첫 단계가 이 동작을 테스트로 고정하는 것입니다(5장의 1).

## 2. npm에 묶여 있는 곳

| 파일 | 위치 | 묶여 있는 것 |
|---|---|---|
| `backend/triage/verify/sandbox.py` | `run()` | 설치 `npm ci`와 `npm install`, 빌드 `npm run build`, 테스트 `npm test`, 결과로 읽는 파일 `package-lock.json` |
| `backend/triage/verify/sandbox.py` | `NPM` | 설치 옵션 `--ignore-scripts --no-audit --no-fund` |
| `backend/triage/verify/apply.py` | `sandbox_command()`, `same_package_command()` | 직접 의존성 `npm install <패키지>@<버전>`, 간접 의존성은 `package.json`의 `overrides`, lock 파일에서 옛 항목을 지우는 `node -e` 스크립트 |
| `backend/triage/verify/apply.py` | `build()` | 사람에게 보여 주는 명령 문자열 `npm install ...` |
| `backend/triage/verify/run.py` | `rescan()` | `sbom.npm_lock_components(json.loads(lockfile))` |
| `backend/triage/verify/run.py` | `diff`를 부르는 곳 | 패치 대상 파일 이름 `package.json`, `package-lock.json` |
| `backend/triage/verify/run.py` | `run()` | 검증 대상 선택 `ecosystem == "npm"` (이것은 그대로 둡니다. yarn과 pnpm도 생태계는 npm입니다) |

## 3. 설계

### 3.1 패키지 관리자 판별

검증을 시작할 때 저장소 루트를 보고 하나를 고릅니다. 값은 코드가 정하고 AI는 관여하지 않습니다.

| 순서 | 조건 | 결과 |
|---|---|---|
| 1 | `package-lock.json` 또는 `npm-shrinkwrap.json`이 있음 | `npm` |
| 2 | `pnpm-lock.yaml`이 있음 | `pnpm` |
| 3 | `yarn.lock`이 있고 `.yarnrc.yml`이 있거나 lock 파일에 `__metadata:`가 있음 | `yarn-berry` |
| 4 | `yarn.lock`이 있음 | `yarn-classic` |
| 5 | 그 밖 | 검증하지 않고 이유(`no supported lock file`)를 남김 |

- lock 파일이 둘 이상이면 위 순서를 따르고 실행 기록에 그 사실을 남깁니다.
- 3번의 구분 방법(`# yarn lockfile v1` 머리말과 `__metadata:`)은 공식 문서에서 확인하지 못했습니다. 실제 lock 파일로 확인한 뒤 씁니다(7장).
- `package.json`의 `packageManager` 필드는 버전을 알아내는 데만 씁니다. 값은 형식(`이름@숫자.숫자.숫자`)을 검사한 뒤에 씁니다. 저장소의 파일은 신뢰할 수 없는 입력입니다(절대 규칙 5).

새 모듈 `backend/triage/verify/pm.py`에 순수 함수로 둡니다: `detect(files: set[str], yarn_lock_head: str | None, package_json: dict | None) -> Manager | None`.

### 3.2 관리자별 명령

아래 표가 `sandbox.py`와 `apply.py`의 npm 고정 문자열을 대신합니다. 옵션 이름은 공식 문서에서 확인한 것입니다(8장).

| | npm (현재) | yarn classic (v1) | yarn berry (v2 이상) | pnpm |
|---|---|---|---|---|
| 기준선 설치 | `npm ci --ignore-scripts --no-audit --no-fund` | `yarn install --frozen-lockfile --ignore-scripts` | `yarn install --immutable --mode=skip-build` | `pnpm install --frozen-lockfile --ignore-scripts` |
| 조치 후 설치 | `npm install --ignore-scripts ...` | `yarn install --ignore-scripts` | `yarn install --mode=skip-build` | `pnpm install --no-frozen-lockfile --ignore-scripts` |
| 직접 의존성 올리기 | `npm install <p>@<v> --package-lock-only ...` | `package.json`의 버전을 고친 뒤 설치 | `package.json`의 버전을 고친 뒤 `yarn install --mode=update-lockfile` | `pnpm add <p>@<v> --lockfile-only --ignore-scripts` |
| 간접 의존성 고정 | `package.json`의 `overrides` | `package.json`의 `resolutions` | `package.json`의 `resolutions` | pnpm 버전에 따라 다름(3.3) |
| 빌드, 테스트 | `npm run build`, `npm test` | `yarn run build`, `yarn test` | 같음 | `pnpm run build`, `pnpm test` |
| 결과 lock 파일 | `package-lock.json` | `yarn.lock` | `yarn.lock` | `pnpm-lock.yaml` |

지켜야 할 것은 지금과 같습니다.

1. **설치 스크립트를 실행하지 않습니다.** 모든 설치 명령에 해당 옵션을 명시합니다. yarn berry는 기본값이 실행하지 않는 것이고 최신 pnpm도 허용 목록에 없는 패키지의 빌드를 막지만, 기본값에 기대지 않고 옵션을 붙입니다. 저장소의 `.yarnrc.yml`이나 `pnpm-workspace.yaml`이 기본값을 바꿀 수 있기 때문입니다.
2. **빌드와 테스트는 네트워크 없이 돕니다**(`--network none`). 지금과 같습니다.
3. **명령에 들어가는 값은 형식을 검사한 것만 씁니다.** 패키지 이름과 버전의 검사(`apply.NPM_NAME`, `VERSION`)를 그대로 씁니다.
4. **`package.json`을 고칠 때는 문자열 치환이 아니라 JSON으로 읽고 씁니다.** 지금의 `node -e` 방식과 같습니다.

### 3.3 pnpm의 간접 의존성 고정

pnpm은 버전에 따라 override를 적는 곳이 다릅니다.

- 현재 문서(v11 이후 기준): `pnpm-workspace.yaml`의 `overrides`에 적습니다. 문서는 pnpm이 `package.json`의 `pnpm` 필드에서 설정을 읽지 않는다고 적고 있습니다.
- 그 전 버전: `package.json`의 `pnpm.overrides`에 적었습니다. 이 부분은 지금 문서에 없어 이번에 확인하지 못했습니다. 구현 전에 해당 버전의 문서나 변경 기록으로 확인합니다(7장).

그래서 pnpm은 버전을 먼저 정해야 합니다. 방법은 둘 중 하나로 정합니다(7장의 결정 1).

- (가) `package.json`의 `packageManager` 필드에 적힌 버전을 따르고, 없으면 검증하지 않고 이유를 남깁니다.
- (나) lock 파일의 `lockfileVersion`으로 주 버전을 추정합니다.

YAML 파일을 고치는 일은 컨테이너 안에서 해야 하고, 샌드박스 이미지(node)에 YAML 해석기가 기본으로 없습니다. 방법은 둘 중 하나입니다.

- (가) `overrides:` 블록이 없는 파일에만 끝에 블록을 덧붙이고, 이미 있으면 검증하지 않고 이유를 남깁니다. 단순하지만 일부 저장소를 포기합니다.
- (나) 호스트 쪽 Python에서 YAML을 읽고 고친 내용을 컨테이너에 파일로 넣습니다. 이 경우 원본을 고치지 않는다는 규칙을 지키기 위해 사본 볼륨에만 씁니다.

### 3.4 패키지 관리자 바이너리

샌드박스 이미지는 `node:20-slim`이고 npm만 들어 있습니다. yarn과 pnpm을 쓰는 방법은 셋입니다.

| 방법 | 장점 | 단점 |
|---|---|---|
| Corepack (`corepack enable`) | 저장소가 요구하는 버전을 그대로 씁니다 | 실행할 때 내려받으므로 네트워크가 필요합니다. 컨테이너가 `--cap-drop ALL`이고 루트가 아닐 수 있어 shim을 만들 위치를 따로 줘야 합니다. Corepack은 Node.js 25부터 함께 배포되지 않습니다 |
| 전용 이미지 (`TRIAGE_SANDBOX_IMAGE`에 yarn과 pnpm을 미리 설치) | 네트워크 없이 되고 폐쇄망에서 쓸 수 있습니다 | 이미지를 만들고 관리해야 합니다. 저장소가 요구하는 버전과 다를 수 있습니다 |
| `npx <관리자>@<버전>` | 이미지를 바꾸지 않습니다 | 매번 내려받고, 임의의 패키지를 실행하는 경로가 하나 늘어납니다 |

권장은 전용 이미지입니다. 폐쇄망 운영이 전제이고(`deploy/k8s/README.md`), 이미 `TRIAGE_SANDBOX_IMAGE`로 이미지를 바꿀 수 있기 때문입니다. 이미지에 없는 관리자가 필요한 저장소는 검증하지 않고 이유(`package manager not in sandbox image`)를 남깁니다. 최종 선택은 사람이 정합니다(7장의 결정 2).

### 3.5 재스캔과 패치

- `verify/run.py`의 `rescan()`은 관리자에 맞는 해석기를 부릅니다. yarn은 `ingest.parse_yarn_lock(text, package_json)`, pnpm은 `ingest.parse_pnpm_lock(text)`이고 결과를 지금처럼 `Component` 목록으로 넘깁니다.
- `sandbox.Result.lockfile`은 그대로 두고 `lockfile_name`을 추가합니다. 패치(`verify/<패키지>.patch`)는 `package.json`과 그 lock 파일의 차이로 만듭니다. pnpm에서 `pnpm-workspace.yaml`을 고쳤다면 그 파일도 패치에 넣습니다.
- yarn berry의 PnP 모드(`.pnp.cjs`, `node_modules` 없음)는 이번 범위에서 뺍니다. 발견하면 검증하지 않고 이유를 남깁니다.

### 3.6 스키마

`models.py`에 넣을 것은 최소로 합니다.

- `Verification.package_manager: Literal["npm", "yarn-classic", "yarn-berry", "pnpm"] | None = None` (어떤 관리자로 검증했는지. 화면과 PR 초안에 표시)
- `Remediation.commands`는 지금도 문자열 목록이므로 그대로 두고, 내용만 관리자에 맞게 만듭니다.

`models.py`를 바꾸면 같은 커밋에서 `uv run python scripts/gen_types.py`를 돌립니다(절대 규칙 1).

## 4. 범위에서 빼는 것

1. 모노레포의 워크스페이스별 검증. 지금 npm도 루트만 봅니다.
2. yarn berry의 PnP 모드.
3. Maven, PyPI 등 다른 생태계의 검증.
4. bun, deno.
5. 관리자를 바꿔 설치하는 것(yarn 저장소를 npm으로 설치). lock 파일이 달라져 검증의 의미가 없습니다.

## 5. 작업 순서

테스트를 먼저 씁니다. 한 번에 한 단계만 하고, 단계마다 `uv run pytest -q`와 `bash kit/scripts/check.sh --fast`를 돌립니다.

1. **지금 동작을 고정합니다.** `yarn.lock`만 있는 작은 저장소와 `pnpm-lock.yaml`만 있는 작은 저장소를 테스트 안에서 만들고, 검증이 `inconclusive`나 건너뜀으로 끝나며 원본이 바뀌지 않는 것을 확인합니다(`tests/test_sandbox.py`의 `tree_hash` 방식). Docker가 없으면 건너뛰는 표시는 기존 테스트를 따릅니다.
2. **판별을 넣습니다.** `verify/pm.py`의 `detect()`와 `tests/test_pm.py`. 파일 조합별 결과, lock 파일이 둘일 때, `packageManager` 값이 이상할 때를 봅니다. Docker가 필요 없습니다.
3. **명령 표를 넣습니다.** `pm.py`에 관리자별 명령을 돌려주는 순수 함수를 두고 `apply.py`의 `sandbox_command()`가 이것을 쓰게 합니다. `tests/test_apply.py`에 관리자별로 추가합니다: 안전하지 않은 값 거절, `--ignore-scripts`에 해당하는 옵션이 모든 설치 명령에 있는지, 직접과 간접의 명령이 맞는지.
4. **샌드박스를 관리자에 맞춥니다.** `sandbox.run()`이 관리자를 받아 설치, 빌드, 테스트 명령과 결과 lock 파일 이름을 고릅니다. npm의 동작은 바뀌지 않아야 합니다(기존 테스트가 그대로 통과).
5. **재스캔과 패치를 맞춥니다.** `rescan()`과 패치 생성. `tests/test_verdict.py`, `tests/test_decide.py`에 관리자별 사례를 추가합니다.
6. **yarn classic부터 실제로 돌립니다.** 공개 저장소 하나를 `fixtures/eval-repos.ref`에 주소와 커밋으로 추가하고(저장소 자체는 커밋하지 않습니다) 스캔, AI 판단, 검증을 돌려 판정과 실행된 테스트 수를 `HARNESS.md`에 기록합니다. 그다음 pnpm, 마지막이 yarn berry입니다.
7. **문서를 고칩니다.** `README.md` 7장, `docs/GUIDE.md` 4장과 12장, `kit/CODEX.md` 5장, 이 문서의 상태 줄, `HANDOFF.md`의 결정 로그.

## 6. 끝났다고 볼 조건

1. npm 저장소의 검증 결과가 바뀌지 않습니다. 기존 테스트가 전부 통과합니다.
2. yarn classic, yarn berry(node_modules 방식), pnpm 저장소 각각에서 직접 의존성 올리기와 간접 의존성 고정이 한 건 이상 `verified`나 `failed`로 판정됩니다. `inconclusive`만 나오면 끝난 것이 아닙니다.
3. 모든 설치 명령에 설치 스크립트를 막는 옵션이 있고, 이것을 테스트가 확인합니다.
4. 원본 저장소가 바뀌지 않습니다(해시 비교 테스트).
5. 검증할 수 없는 경우(PnP, 이미지에 없는 관리자, 알 수 없는 pnpm 버전)에 실패가 아니라 이유가 남습니다.
6. 파일과 PostgreSQL 두 저장 모드에서 같은 결과가 나옵니다(`Verification`은 `Triage` 안에 저장되므로 `tests/test_store.py`의 기존 왕복 테스트에 새 필드를 넣습니다).
7. 재생 모드에서 저장된 검증 결과가 그대로 보입니다.

## 7. 사람이 정할 것과 확인할 것

| | 내용 | 권장 |
|---|---|---|
| 결정 1 | pnpm 버전을 `packageManager` 필드로만 정할지, lock 파일로 추정할지 | `packageManager` 필드로만. 없으면 건너뛰고 이유를 남김 |
| 결정 2 | yarn과 pnpm 바이너리를 어떻게 넣을지(3.4) | 전용 이미지 |
| 결정 3 | pnpm의 YAML을 컨테이너 안에서 고칠지 호스트에서 고칠지(3.3) | 처음에는 (가), 포기하는 저장소가 많으면 (나) |
| 확인 1 | yarn classic과 berry를 lock 파일로 구분하는 방법 | 실제 lock 파일 두 종류로 확인 |
| 확인 2 | 옛 pnpm이 `package.json`의 `pnpm.overrides`를 읽던 버전 범위 | 해당 버전 문서나 변경 기록 |
| 확인 3 | `pnpm add <p>@<v>`가 저장하는 범위 표기(정확한 버전인지 `^`가 붙는지) | 문서에 없었음. 필요하면 `--save-exact` |
| 확인 4 | `--cap-drop ALL`인 컨테이너에서 yarn과 pnpm의 캐시와 저장소 위치가 쓰기 가능한지 | 실행해서 확인. 필요하면 캐시 경로를 `/work` 아래로 지정 |

## 8. 확인한 공식 문서 (2026-11-24)

| 사실 | 출처 |
|---|---|
| `pnpm install`의 `--frozen-lockfile`, `--lockfile-only`, `--ignore-scripts`, `--offline` | https://pnpm.io/cli/install |
| pnpm의 override는 `pnpm-workspace.yaml`의 `overrides`. `package.json`의 `pnpm` 필드는 읽지 않음 | https://pnpm.io/settings/dependency-resolution , https://pnpm.io/package_json |
| pnpm은 `allowBuilds`에 없는 패키지의 빌드를 기본으로 막음. `onlyBuiltDependencies`는 v11에서 `allowBuilds`로 대체 | https://pnpm.io/settings/build |
| `pnpm add <p>@<v>`와 `--lockfile-only`. 간접 의존성은 `pnpm update`로 올릴 수 없고 `overrides`를 쓰라는 안내 | https://pnpm.io/cli/add , https://pnpm.io/cli/update |
| yarn classic의 `--frozen-lockfile`, `--ignore-scripts` | https://classic.yarnpkg.com/en/docs/cli/install |
| yarn classic의 `resolutions`는 `package.json` 최상위 | https://classic.yarnpkg.com/en/docs/selective-version-resolutions/ |
| yarn berry의 `--immutable`, `--mode=skip-build`, `--mode=update-lockfile` | https://yarnpkg.com/cli/install |
| yarn berry의 `enableScripts` 기본값은 `false` | https://yarnpkg.com/configuration/yarnrc |
| yarn berry에서도 `resolutions`는 `package.json`에 적음(루트만) | https://yarnpkg.com/configuration/manifest |
| `packageManager` 필드와 `corepack enable`. Corepack은 Node.js 14.19.0부터 25.0.0 전까지 함께 배포 | https://github.com/nodejs/corepack |

이 표의 내용은 문서를 읽어 확인한 것이고, 명령을 실제로 실행해 확인한 것은 아닙니다. 실행 확인은 5장의 6에서 합니다.
