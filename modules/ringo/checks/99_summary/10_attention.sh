# shellcheck shell=bash
# Итог: что требует внимания — все FAIL и WARN с подписями из count и что делать (lib/remedies.tsv).

if (( ${#FAIL_LIST[@]} + ${#WARN_LIST[@]} )); then
  echo
  echo " ${BD}${B}▸ Итог: что требует внимания${N}"
  attn() { # статус, цвет, подпись
    local fix; [[ -n "$3" ]] || return 0
    printf "   • %s%s%s: %s\n" "$2" "$1" "$N" "$3"
    fix="$(remedy_of "$3")"; [[ -n "$fix" ]] && printf "     %s↳ что делать: %s%s\n" "$D" "$fix" "$N"
    return 0
  }
  for x in "${FAIL_LIST[@]:-}"; do attn FAIL "$R" "$x"; done
  for x in "${WARN_LIST[@]:-}"; do attn WARN "$Y" "$x"; done
  [[ -n "$RESP_DIR" ]] && printf "     %s↳ ответы сервера сохранены: %s%s\n" "$D" "$RESP_DIR" "$N"
fi
