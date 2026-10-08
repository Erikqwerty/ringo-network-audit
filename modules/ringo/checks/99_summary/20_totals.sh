# shellcheck shell=bash
# Счётчики и код возврата модуля: 0 — всё ок, 1 — есть WARN, 2 — есть FAIL.

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
