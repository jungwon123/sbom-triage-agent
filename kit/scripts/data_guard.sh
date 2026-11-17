#!/usr/bin/env bash
# 제공 자료 보호: 해시를 기록하고(init) 바뀌지 않았는지 확인한다(verify).
# 사용: bash kit/scripts/data_guard.sh init <자료 폴더> [<폴더2> ...]
#       bash kit/scripts/data_guard.sh verify
set -u
MANIFEST=.data_manifest.sha256
hash_one() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi; }

case "${1:-}" in
  init)
    shift
    [ $# -eq 0 ] && { echo "자료 폴더를 지정하세요: bash kit/scripts/data_guard.sh init data"; exit 2; }
    if [ -f "$MANIFEST" ]; then echo "[!!] $MANIFEST 이 이미 있습니다. 다시 만들려면 직접 지우고 실행하세요."; exit 1; fi
    find "$@" -type f -not -path '*/.git/*' -not -path '*/node_modules/*' -not -path '*/target/*' -not -name '.DS_Store' -print0 \
      | sort -z | while IFS= read -r -d '' f; do hash_one "$f"; done > "$MANIFEST"
    echo "[OK] 자료 $(wc -l < "$MANIFEST" | tr -d ' ')개 파일 해시를 $MANIFEST 에 기록"
    ;;
  verify)
    [ -f "$MANIFEST" ] || { echo "  [..] $MANIFEST 없음 (본선 자료를 받은 뒤 init)"; exit 0; }
    bad=0; missing=0
    while IFS= read -r line; do
      h=${line%% *}; f=${line#*  }
      if [ ! -f "$f" ]; then echo "  [!!] 없어짐: $f"; missing=$((missing+1)); continue; fi
      now=$(hash_one "$f" | cut -d' ' -f1)
      [ "$now" = "$h" ] || { echo "  [!!] 바뀜: $f"; bad=$((bad+1)); }
    done < "$MANIFEST"
    total=$(wc -l < "$MANIFEST" | tr -d ' ')
    if [ $bad -eq 0 ] && [ $missing -eq 0 ]; then echo "  [OK] 자료 ${total}개 그대로"; else echo "  [!!] 바뀜 ${bad}, 없어짐 ${missing} / 전체 ${total}"; exit 1; fi
    ;;
  *) echo "사용: bash kit/scripts/data_guard.sh init <자료 폴더...> | verify"; exit 2 ;;
esac
