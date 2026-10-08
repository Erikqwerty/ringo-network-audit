# shellcheck shell=bash
# Итог: что требует внимания — все FAIL и WARN с подписями из count.

if (( ${#FAIL_LIST[@]} + ${#WARN_LIST[@]} )); then
  echo
  echo " ${BD}${B}▸ Итог: что требует внимания${N}"
  for x in "${FAIL_LIST[@]:-}"; do [[ -n "$x" ]] && printf "   • %sFAIL%s: %s\n" "$R" "$N" "$x"; done
  for x in "${WARN_LIST[@]:-}"; do [[ -n "$x" ]] && printf "   • %sWARN%s: %s\n" "$Y" "$N" "$x"; done
  [[ -n "$RESP_DIR" ]] && printf "     %s↳ ответы сервера сохранены: %s%s\n" "$D" "$RESP_DIR" "$N"
fi
