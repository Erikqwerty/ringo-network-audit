# shellcheck shell=bash
# Проверка: итог и код возврата. Выполняется по порядку из modules/ringo/run.sh (source, общие переменные).

# ---------- итог ----------
if (( ${#FAIL_LIST[@]} + ${#WARN_LIST[@]} )); then
  echo
  echo " ${BD}${B}▸ Итог: что требует внимания${N}"
  for x in "${FAIL_LIST[@]:-}"; do [[ -n "$x" ]] && printf "   • %sFAIL%s: %s\n" "$R" "$N" "$x"; done
  for x in "${WARN_LIST[@]:-}"; do [[ -n "$x" ]] && printf "   • %sWARN%s: %s\n" "$Y" "$N" "$x"; done
  [[ -n "$RESP_DIR" ]] && printf "     %s↳ ответы сервера сохранены: %s%s\n" "$D" "$RESP_DIR" "$N"
fi
echo
echo "${D}────────────────────────────────────────────────────────────────${N}"
print_totals
if (( FLAKY_CNT )); then
  echo " ${Y}Нестабильный канал: $FLAKY_CNT запрос(ов) ответили только со 2-й попытки —${N}"
  echo " ${Y}проверьте путь (ТСПУ / VPN / балансировщик) по tcpdump на физическом интерфейсе.${N}"
fi
if (( FAIL_CNT )); then
  # FAIL только в опциональных проверках (SCEP Proxy) — не «проблемы с обязательными»
  if [[ -n "$(printf '%s\n' "${FAIL_LIST[@]:-}" | grep -v '(опционально)' | grep .)" || ${#FAIL_LIST[@]} -lt $FAIL_CNT ]]; then
    echo " ${R}${BD}Есть проблемы с обязательными эндпоинтами или TLS.${N}"
  else
    echo " ${R}${BD}Есть проблемы в опциональных проверках.${N}"
  fi
  echo; exit 2
elif (( WARN_CNT )); then
  echo " ${Y}${BD}Есть замечания — сверьтесь с документацией.${N}"; echo; exit 1
else
  echo " ${G}${BD}Соответствует документации.${N}"; echo
fi
