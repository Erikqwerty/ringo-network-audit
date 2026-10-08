# shellcheck shell=bash
# Версия Ringo, HTTP и заголовок Server: здесь и там.
[[ -n "$COMPARE" ]] || return 0

cmp_kv() { # подпись, здесь, там
  if [[ "$2" == "$3" ]]; then printf "   • %s: %s %s(одинаково)%s\n" "$1" "${2:-—}" "$D" "$N"
  else printf "   • %s: здесь %s%s%s, там %s%s%s\n" "$1" "$BD" "${2:-—}" "$N" "$BD" "${3:-—}" "$N"; fi
}
cmp_kv "Ringo" "$(v="${RINGO_VER:-${RINGO_FAM:+$RINGO_FAM.x}}"; echo "${v%% *}")" "$(sed -nE 's/^ *Ringo: *([^ ]+).*/\1/p' "$COMPARE" | head -1)"
cmp_kv "HTTP" "HTTP/${hver:-?}" "$(sed -nE 's/^ *• HTTP: *([^ ]+).*/\1/p' "$COMPARE" | head -1)"
cmp_kv "Server" "${srv:-—}" "$(sed -nE 's/^ *• Заголовок Server: *//p' "$COMPARE" | head -1)"
