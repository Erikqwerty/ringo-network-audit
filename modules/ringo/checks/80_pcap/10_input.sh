# shellcheck shell=bash
# Есть что разбирать: файл не пуст и известен IP сервера (по нему фильтруются пакеты). Итог: WARN, если нет.
[[ -n "$PCAP_FILE" ]] || return 0

if [[ ! -s "$PCAP_FILE" ]]; then
  printf "   %s файл пуст или не найден\n" "$(badge WARN)"; count WARN
elif [[ -z "${SRV_IP:-}" ]]; then
  printf "   %s IP сервера не определён — нечего фильтровать\n" "$(badge WARN)"; count WARN
fi
