# shellcheck shell=bash
# С какого адреса нас видит сервер: от этого зависит, попадаем ли мы в allow-список прокси.
# До частного адреса сервера ходим из локальной сети — тогда важен адрес интерфейса, а не внешний.
# Задаёт: MY_IP (несколько через « / » — выход VPN меняется), MY_IP_HOW — пояснение.

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
