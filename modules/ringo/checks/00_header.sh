# shellcheck shell=bash
# Проверка: шапка: хост, маршрут, IP, версия Ringo и схема API. Выполняется по порядку из modules/ringo/run.sh (source, общие переменные).

# ---------- шапка ----------
echo
echo "${BD}Ringo MDM — проверка эндпоинтов${N}"
echo "${D}────────────────────────────────────────────────────────────────${N}"
printf " Хост:   %s%s%s\n" "$C" "$HOST" "$N"
printf " Режим:  %s\n" "$( ((INTERNAL)) && echo "изнутри (разрешённая подсеть)" || echo "снаружи (внешний клиент)")"
printf " Дата:   %s\n" "$(date '+%Y-%m-%d %H:%M:%S')"

# через какой интерфейс идёт трафик: VPN/туннель искажает картину (TCP может завершаться локально)
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

# IP и порт сервера (для проверок напрямую на IP и для фильтра tcpdump)
SRV_PORT=443; hp="${HOST#*://}"; hp="${hp%%/*}"; [[ "$hp" == *:* ]] && SRV_PORT="${hp##*:}"
# time_connect включает DNS — для оценки «TCP завершается локально» вычитаем time_namelookup
read -r SRV_IP CONN_T DNS_T <<<"$(curl -sk -m 10 -o /dev/null -w '%{remote_ip} %{time_connect} %{time_namelookup}' "$HOST/" 2>/dev/null)"
# при ошибке curl remote_ip пустой и read сдвигает поля — проверяем форму адреса
[[ "${SRV_IP:-}" =~ ^[0-9]+(\.[0-9]+){3}$ || "${SRV_IP:-}" == *:* ]] || SRV_IP=""
[[ -n "${CONN_T:-}" && -n "${DNS_T:-}" ]] && CONN_T=$(awk -v c="$CONN_T" -v d="$DNS_T" 'BEGIN{x=c-d; printf "%.6f", (x>0?x:c)}')
if [[ -z "${SRV_IP:-}" ]]; then
  SRV_IP=$( (dig +short A "$HN" 2>/dev/null; dscacheutil -q host -a name "$HN" 2>/dev/null | awk '/^ip_address:/{print $2}') \
            | grep -E '^[0-9]+(\.[0-9]+){3}$' | head -1)
  CONN_T=""
fi
printf " IP:     %s\n" "${SRV_IP:-не определён}"
# с какого адреса нас видит интернет: от этого зависит, попадаем ли мы в allow-список прокси.
# До частного адреса сервера ходим из локальной сети — тогда важен адрес интерфейса, а не внешний.
MY_IP=""; MY_IP_HOW=""
if [[ "${SRV_IP:-}" =~ ^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.) && -n "$RIF" ]]; then
  MY_IP=$(ifconfig "$RIF" 2>/dev/null | awk '/inet /{print $2; exit}'); MY_IP_HOW="адрес $RIF — сервер в частной сети"
else
  # IPv4 с трёх сервисов: разные адреса — VPN с ротацией выхода, allow-список по IP тогда ненадёжен.
  # Без -4 сервисы с IPv6 отвечают по нему, и IPv4 / IPv6 одной машины выглядели бы как ротация.
  ips=""
  for u in https://api.ipify.org https://ifconfig.me/ip https://icanhazip.com; do
    x=$(curl -4 -s -m 5 "$u" 2>/dev/null | tr -d ' \r\n'); [[ "$x" =~ ^[0-9]+(\.[0-9]+){3}$ ]] && ips="$ips $x"
  done
  MY_IP=$(tr ' ' '\n' <<<"$ips" | grep . | sort -u | paste -sd/ - | sed 's|/| / |g')
  MY_IP6=$(curl -6 -s -m 4 https://api64.ipify.org 2>/dev/null | tr -d ' \r\n'); [[ "$MY_IP6" == *:* ]] || MY_IP6=""
  if [[ "$MY_IP" == */* ]]; then MY_IP_HOW="внешний IPv4 меняется от запроса к запросу — VPN с ротацией выхода"
  else MY_IP_HOW="внешний IPv4"; (( IS_TUN )) && MY_IP_HOW="$MY_IP_HOW; при раздельном туннеле до сервера может быть другим"; fi
  [[ -n "$MY_IP6" ]] && MY_IP_HOW="$MY_IP_HOW; IPv6: $MY_IP6"
fi
printf " Ваш IP: %s %s(%s)%s\n" "${MY_IP:-не определён}" "$D" "$MY_IP_HOW" "$N"
prog " %sопределение версии Ringo и схемы API…%s" "$D" "$N"
detect_ringo
clear_line
if [[ -n "$RINGO_FAM" ]]; then
  printf " Ringo:  %s%s%s %s(%s)%s\n" "$BD" "${RINGO_VER:-${RINGO_FAM}.x}" "$N" "$D" "$VER_HOW" "$N"
else
  printf " Ringo:  %sверсия не определена%s\n" "$D" "$N"
fi
if [[ -n "$API_OPS" ]]; then
  printf " API:    схема %s %s(операций: %d%s)%s\n" "$API_SRC" "$D" "$(grep -c . <<<"$API_OPS")" "${API_SAME:+; $API_SAME}" "$N"
else
  printf " API:    %sсхемы нет — эндпоинты проверяются по встроенному списку без учёта версии%s\n" "$D" "$N"
fi
[[ -n "$API_DIFF" ]] && printf " Отличия: маршруты устройств %s\n" "$API_DIFF"
if [[ -n "$SCHEMA_SAVED" ]]; then
  printf " Снимок: новая схема сохранена в schemas/%s%s%s\n" "$BD" "$(basename "$SCHEMA_SAVED")" "$N"
  is_versioned "$SCHEMA_SAVED" || \
    printf "          %sверсия неизвестна — когда узнаете, переименуйте в swagger_<версия>.json (или запустите с RINGO_TOKEN)%s\n" "$D" "$N"
elif [[ -n "$SCHEMA_NOTE" ]]; then
  printf " Снимок: схема %s\n" "$SCHEMA_NOTE"
fi
# TCP-рукопожатие быстрее ~3 мс до внешнего адреса физически невозможно: его завершает локальный
# VPN-клиент в режиме TUN, и всё, что видно дальше, — это поведение VPN, а не пути до сервера
LOCAL_TCP=0
if [[ -n "${CONN_T:-}" && ! "$SRV_IP" =~ ^(10\.|127\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.) ]] \
   && awk -v x="$CONN_T" 'BEGIN{exit !(x>0 && x<0.003)}'; then
  LOCAL_TCP=1
  printf " %sTCP за %s мс — соединение завершается локально (VPN-клиент в режиме TUN)%s\n" "$Y" "$(awk -v x="$CONN_T" 'BEGIN{printf "%.1f", x*1000}')" "$N"
fi
if (( CAPTURE )) && [[ -n "${SRV_IP:-}" ]]; then
  CAP_IFACE="${CAP_IFACE:-${RIF:-any}}"
  PCAP_FILE="${PCAP_FILE:-./ringo_audit_$(date +%Y%m%d_%H%M%S).pcap}"
  start_capture "$CAP_IFACE" "$PCAP_FILE" "$SRV_IP" && printf " Захват: %s → %s\n" "$CAP_IFACE" "$PCAP_FILE"
fi
echo "${D}────────────────────────────────────────────────────────────────${N}"
echo
