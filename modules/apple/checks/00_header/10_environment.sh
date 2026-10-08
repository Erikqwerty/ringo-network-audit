# shellcheck shell=bash
# Шапка отчёта: роль, таймаут, утилиты, DNS и прокси из окружения (проверки идут напрямую, минуя прокси).

echo
echo "${BD}Apple MDM — проверка сетевого окружения${N}"
echo "${D}────────────────────────────────────────────────────────────────────${N}"
# метки case в $(…) — со скобкой «(server)»: иначе bash 3.2 падает с syntax error
printf " Роль:      %s\n" "$( case $ROLE in (server) echo "MDM-сервер (исходящие к Apple)";; (client) echo "сеть устройств (Mac/iOS → Apple)";; (*) echo "обе (сервер + устройства)";; esac )"
printf " Таймаут:   %ss на подключение\n" "$TMO"
printf " Хост:      %s · %s\n" "$(hostname 2>/dev/null)" "$(date '+%Y-%m-%d %H:%M:%S')"
tools=""; for x in nc openssl dig python3 curl; do have $x && tools="${tools:+$tools }$x"; done
printf " Утилиты:   %s\n" "${tools:-нет}"
ns=$(awk '/^nameserver/{print $2; exit}' /etc/resolv.conf 2>/dev/null)
[[ -n "$ns" ]] && printf " DNS:       %s\n" "$ns"
px="$(env | grep -iE '^(https?|all)_proxy=' | head -2 | paste -sd' ' -)"
if [[ -n "$px" ]]; then printf " Прокси:    %s%s%s (проверки идут напрямую, минуя прокси)\n" "$Y" "$px" "$N"; fi
echo "${D}────────────────────────────────────────────────────────────────────${N}"
echo "${D} Проверка = прямой TCP + TLS (nc/openssl). Apple не допускает SSL-inspection${N}"
echo "${D} на этих хостах, поэтому издатель сертификата тоже проверяется.${N}"
