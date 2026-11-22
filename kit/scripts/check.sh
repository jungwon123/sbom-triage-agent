#!/usr/bin/env bash
# 중간 점검과 제출 전 점검. 고치지 않고 보고만 한다. 레포 루트에서 실행한다.
# 사용: bash kit/scripts/check.sh [--fast]     (--fast: 테스트와 리플레이 실행을 건너뜀)
set -u
ok() { printf '  [OK] %s\n' "$1"; }
ng() { printf '  [!!] %s\n' "$1"; }
note() { printf '  [..] %s\n' "$1"; }
FAST=0; [ "${1:-}" = "--fast" ] && FAST=1
LOG=${TMPDIR:-/tmp}
SRC=backend/triage
[ -d "$SRC" ] || { echo "레포 루트에서 실행하세요 ($SRC 없음)"; exit 2; }

echo "== 0. 제공 자료와 대상 레포 보존"
bash kit/scripts/data_guard.sh verify || true
for r in fixtures/demo-repo fixtures/eval/*; do
  [ -d "$r/.git" ] || continue
  n=$(git -C "$r" status --porcelain | wc -l | tr -d ' ')
  [ "$n" = "0" ] && ok "$r 변경 없음" || ng "$r 에 변경 ${n}개 (대상 레포는 수정 금지)"
done

echo "== 1. 테스트 (검증 0건은 통과가 아니다)"
if [ $FAST -eq 1 ]; then note "--fast: 건너뜀"; else
  uv run pytest >$LOG/pytest.log 2>&1; rc=$?
  last=$(tail -1 $LOG/pytest.log)
  if [ $rc -eq 0 ]; then ok "pytest: $last"; elif [ $rc -eq 5 ]; then ng "pytest 0건 = 미검증"; else ng "pytest 실패: $last (로그 $LOG/pytest.log)"; grep -E "^FAILED" $LOG/pytest.log | head -8; fi
  grep -qE "[0-9]+ skipped" $LOG/pytest.log && ng "건너뛴 테스트: $(grep -oE '[0-9]+ skipped' $LOG/pytest.log | tail -1) (Docker가 꺼져 있으면 격리 테스트가 빠진다)"
  if [ -f web/package.json ]; then
    if (cd web && pnpm -s exec tsc --noEmit >$LOG/tsc.log 2>&1); then ok "web: tsc --noEmit 통과"; else ng "web: 타입 오류 (로그 $LOG/tsc.log)"; head -6 $LOG/tsc.log; fi
  else note "web/ 없음"; fi
fi

echo "== 2. 절대 규칙 (CLAUDE.md 4장)"
hits=$(grep -rnE "import httpx|import requests|urllib\.request|httpx\.(get|post|Client)" $SRC --include=*.py | grep -v "^$SRC/cache.py" | grep -v "^$SRC/notify.py" | grep -v "^$SRC/auth.py" | head -5)
[ -z "$hits" ] && ok "규칙 6: 외부 HTTP 호출은 cache.py(조회), notify.py(알림), auth.py(로그인)에만 있음" || { ng "규칙 6: cache.py 밖의 HTTP 호출"; echo "$hits" | sed 's/^/      /'; }
hits=$(grep -rnE "subprocess|os\.system|os\.popen|\beval\(|\bexec\(" $SRC/agent --include=*.py | head -5)
[ -z "$hits" ] && ok "규칙 4, 5: agent/ 에 명령 실행 코드 없음" || { ng "규칙 4, 5: agent/ 에 실행 코드"; echo "$hits" | sed 's/^/      /'; }
hits=$(grep -rnE "open\([^)]*['\"][wa]b?['\"]|write_text|write_bytes|unlink|rmtree" $SRC/agent/tools.py | head -5)
[ -z "$hits" ] && ok "규칙 4: 에이전트 도구에 쓰기 코드 없음" || { ng "규칙 4: tools.py 에 쓰기 코드"; echo "$hits" | sed 's/^/      /'; }
hits=$(grep -rnE "['\"](claude-[a-z0-9-]+|gpt-[a-z0-9.-]+|o[0-9]-[a-z0-9-]+)['\"]" $SRC --include=*.py | grep -v "^$SRC/agent/llm_anthropic.py" | grep -v "^$SRC/doctor.py" | head -5)
[ -z "$hits" ] && ok "모델명 하드코딩 없음 (기본값은 llm_anthropic.py 한 곳)" || { ng "모델명 하드코딩"; echo "$hits" | sed 's/^/      /'; }
open_routes=$(grep -nE '^@app\.(get|post|put|delete|patch)\(' $SRC/api.py | grep -v "dependencies=" | grep -vE '"/api/(health|runs/\{run_id\}/(decisions|export/together))"' | head -5)
[ -z "$open_routes" ] && ok "규칙 11: API 경로에 역할 검사가 달려 있음" || { ng "규칙 11: 역할 검사가 없는 API 경로"; echo "$open_routes" | sed 's/^/      /'; }
grep -q "risk" <(sed -n '/^class AgentVerdict/,/^class /p' $SRC/models.py) && ng "규칙 2: AgentVerdict에 점수 필드가 있음" || ok "규칙 2: AgentVerdict에 점수 필드 없음"
for t in test_writer_gets_no_code_and_no_tools test_two_step_jump_rejected test_kev_downgrade_rejected test_raw_number_in_rationale_rejected test_shell_metacharacters_rejected test_symlink_escape_rejected test_original_untouched_and_network_blocked test_nothing_is_readable_without_a_session test_a_viewer_reads_but_cannot_decide_or_export test_a_bad_id_token_gives_no_session; do
  grep -rq "def $t" tests 2>/dev/null || ng "안전장치 테스트 없음: $t"
done
if [ -d web/src ]; then
  hits=$(grep -rnE "['\"\`](\.\./)*out/" web/src 2>/dev/null | head -3)
  [ -z "$hits" ] && ok "프론트는 out/ 을 직접 읽지 않음" || { ng "프론트가 out/ 을 직접 참조"; echo "$hits" | sed 's/^/      /'; }
fi

echo "== 3. 오프라인 리플레이"
if [ $FAST -eq 1 ]; then note "--fast: 건너뜀"; elif [ -f fixtures/demo-repo/package-lock.json ]; then
  if DEMO_MODE=replay uv run python -m triage scan fixtures/demo-repo --name check >$LOG/replay.json 2>$LOG/replay.err; then
    ok "DEMO_MODE=replay 스캔 성공: $(python3 -c "import json;d=json.load(open('$LOG/replay.json'));s=d['summary'];print(s['findings'],'건 →',s['final'])" 2>/dev/null)"
    grep -q "replay cache miss" $LOG/replay.err && ng "캐시에 없는 응답이 있음: $(grep -c 'replay cache miss' $LOG/replay.err)건 (네트워크가 될 때 한 번 실행해 채울 것)"
  else ng "리플레이 스캔 실패 (로그 $LOG/replay.err)"; tail -3 $LOG/replay.err; fi
else note "fixtures/demo-repo 없음 (demo-repo.ref 의 커밋으로 받기)"; fi

echo "== 4. git"
ch=$(git status --porcelain | wc -l | tr -d ' ')
[ "$ch" = "0" ] && ok "커밋 안 된 변경 없음" || { ng "커밋 안 된 변경 ${ch}개"; git status --short | head -6; }
envs=$(git ls-files | grep -E '(^|/)\.env($|\.)' | grep -v '\.example$')
[ -z "$envs" ] && ok ".env 파일 커밋 안 됨" || ng ".env가 커밋됨: $envs"
ai=$(git log --format='%h %s%n%b' | grep -ciE "co-authored-by:.*(claude|anthropic|codex|openai|copilot)|generated with \[?claude")
[ "$ai" = "0" ] && ok "커밋에 AI 기여자 표기 없음" || ng "AI 기여자 표기가 든 커밋 줄 ${ai}개 (GitHub에 올리기 전에 정리)"
git log --oneline -5 | sed 's/^/      /'

echo "== 5. 키, 토큰 하드코딩"
hits=$(grep -rInE "(sk-ant-[A-Za-z0-9_-]{10,}|sk-[A-Za-z0-9_-]{20,}|api[_-]?key\s*[:=]\s*[\"'][A-Za-z0-9_-]{12,})" \
  --exclude-dir=.git --exclude-dir=node_modules --exclude-dir=.venv --exclude-dir=out --exclude-dir=dist --exclude-dir=cache --exclude='.env' . 2>/dev/null | head -5)
[ -z "$hits" ] && ok "의심 문자열 없음" || { ng "확인 필요:"; echo "$hits" | cut -c1-120; }
if [ -d out ]; then
  hits=$(grep -rIlE "sk-ant-[A-Za-z0-9_-]{10,}|sk-[A-Za-z0-9_-]{30,}" out 2>/dev/null | head -3)
  [ -z "$hits" ] && ok "out/ 에 키 없음" || ng "out/ 에 키로 보이는 문자열: $hits"
fi

echo "== 6. 환경"
uv run python -m triage doctor 2>/dev/null | sed 's/^/  /'

echo "== 7. 서버 응답"
for p in 8000 5173; do
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://localhost:$p/" || true)
  if [ -n "$code" ] && [ "$code" != "000" ]; then ok "포트 $p 응답 $code"; else note "포트 $p 응답 없음 (서버를 안 띄웠으면 무시)"; fi
done

echo "== 8. 본선 문서 (docs/finals)"
for f in TASK GAP DATA_NOTES DECISIONS SCENARIOS DEMO_SCRIPT QA HANDOFF SUBMIT_CHECKLIST; do
  if [ -f "docs/finals/$f.md" ]; then ok "docs/finals/$f.md (빈 표 줄 $(grep -cE '^\| *\|' "docs/finals/$f.md" || true))"; else ng "docs/finals/$f.md 없음 → bash kit/scripts/apply.sh"; fi
done
exit 0
