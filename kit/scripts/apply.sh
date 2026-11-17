#!/usr/bin/env bash
# 키트를 이 레포에 적용한다. 이미 있는 파일은 덮어쓰지 않는다. 레포 루트에서 실행한다.
# 사용: bash kit/scripts/apply.sh
set -eu
[ -d kit/claude ] || { echo "레포 루트에서 실행하세요"; exit 2; }
copy() {  # copy <src> <dst>
  if [ -e "$2" ]; then echo "  [..] 이미 있음: $2"; else mkdir -p "$(dirname "$2")"; cp "$1" "$2"; echo "  [OK] $2"; fi
}
echo "== Claude Code 설정 (.claude/, git에서 제외됨)"
for f in $(cd kit/claude && find skills agents -type f); do copy "kit/claude/$f" ".claude/$f"; done
copy kit/claude/settings.json .claude/settings.json
echo "== 본선 문서 틀 (docs/finals/)"
for f in kit/templates/*.md; do copy "$f" "docs/finals/$(basename "$f")"; done
echo "끝. Codex는 AGENTS.md를 읽는다. 절차서는 kit/claude/skills/<이름>/SKILL.md 를 직접 읽게 하면 된다."
