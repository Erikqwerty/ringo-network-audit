# shellcheck shell=bash
# IP и порт сервера: нужны проверкам напрямую на IP (DPI) и фильтру tcpdump.
# Задаёт: SRV_IP, SRV_PORT, CONN_T — время TCP-подключения без DNS (для «TCP завершается локально»).

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
