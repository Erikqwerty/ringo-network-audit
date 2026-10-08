# shellcheck shell=bash
# Через какой интерфейс идёт трафик до сервера. VPN/туннель искажает картину: TCP может
# завершаться локально, и тогда проверки описывают VPN, а не путь клиентов.
# Задаёт: HN — имя сервера, RIF — интерфейс, IS_TUN=1 — туннель.

HN="${HOST#*://}"; HN="${HN%%/*}"; HN="${HN%%:*}"
RIF=""
if [[ "$(uname -s)" == Darwin ]]; then
  RIF=$(route -n get "$HN" 2>/dev/null | awk '/interface:/{print $2}')
elif command -v ip >/dev/null 2>&1 && command -v getent >/dev/null 2>&1; then
  RIF=$(ip route get "$(getent ahostsv4 "$HN" | awk 'NR==1{print $1}')" 2>/dev/null | sed -nE 's/.* dev ([^ ]+).*/\1/p')
fi
IS_TUN=0; [[ "$RIF" =~ ^(utun|tun|tap|wg|ppp|ipsec|gpd|zt) ]] && IS_TUN=1
if (( IS_TUN && INTERNAL )); then
  # изнутри разрешённая подсеть часто и есть VPN — это не ошибка, важно, с какого IP приходит запрос
  printf " Маршрут: через %s — VPN/туннель %s(для режима «изнутри» это ожидаемо)%s\n" "$RIF" "$D" "$N"
elif (( IS_TUN )); then
  printf " Маршрут: %sчерез %s — VPN/туннель%s\n" "$Y" "$RIF" "$N"
  printf "          %sрезультаты отражают путь VPN, а не клиентов; для аудита исключите хост из туннеля%s\n" "$D" "$N"
elif [[ -n "$RIF" ]]; then
  printf " Маршрут: через %s\n" "$RIF"
fi
