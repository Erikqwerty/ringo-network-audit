# shellcheck shell=bash
# DNS изнутри и снаружи: что отвечает системный резолвер этого компьютера и что — публичные
# (Яндекс и Google по UDP 53, Cloudflare и Google по DoH: DoH не подменить на пути).
# Разные адреса изнутри и снаружи — split-horizon: устройство, ушедшее из сети, или с DoH / Private Relay
# придёт на внешний адрес, и там должны быть тот же сертификат и тот же прокси (это проверяет 20_nodes.sh).
# Итог: OK — системный ответ совпадает с публичным; FAIL — имя не резолвится системным DNS;
#       WARN — fake-ip локального прокси (198.18.0.0/15), расхождение снаружи (подмена или split-horizon);
#       INFO — расхождение в режиме --internal (split-horizon ожидаем), публичные резолверы недоступны.
# Задаёт: DNS_SYS, DNS_PUB — IPv4 через пробел, DNS_AAAA — IPv6 системного резолвера.
[[ ! "$HN" =~ ^[0-9.]+$ ]] || { DNS_SYS="$SRV_IP"; DNS_PUB=""; DNS_AAAA=""; return 0; }

dns_v4() { grep -E '^[0-9]+(\.[0-9]+){3}$' | sort -u | paste -sd' ' -; }
prog "   %sDNS…%s" "$D" "$N"
DNS_SYS=$( (dscacheutil -q host -a name "$HN" 2>/dev/null | awk '/^ip_address:/{print $2}'; getent ahostsv4 "$HN" 2>/dev/null | awk '{print $1}') | dns_v4)
DNS_AAAA=$( (dscacheutil -q host -a name "$HN" 2>/dev/null | awk '/^ipv6_address:/{print $2}'; getent ahostsv6 "$HN" 2>/dev/null | awk '{print $1}') \
            | grep ':' | sort -u | paste -sd' ' -)
det_new "DNS: изнутри и снаружи"
det_kv "Как проверяется" "ответ системного резолвера сравнивается с публичными: Яндекс и Google по UDP 53, Cloudflare и Google по DNS-over-HTTPS"
det_sec "Системный резолвер"; det_cmd dscacheutil -q host -a name "$HN"
det_kv "IPv4" "${DNS_SYS:-(нет ответа)}"; det_kv "IPv6" "${DNS_AAAA:-нет}"

# публичные по UDP 53: если не отвечают, а DoH отвечает — наружу закрыт сам DNS, а не имя
DNS_PUB=""; DNS_UDP_OK=0; DNS_UDP_TRIED=0
if have dig; then
  for r in 77.88.8.8 8.8.8.8; do
    DNS_UDP_TRIED=1
    out=$(dig +time=2 +tries=1 +short @"$r" "$HN" A 2>/dev/null)
    det_sec "Публичный DNS $r (UDP 53)"; det_cmd dig +short @"$r" "$HN" A
    if grep -q 'timed out\|no servers' <<<"$out"; then det_text "(нет ответа — UDP 53 до $r закрыт?)"; continue; fi
    DNS_UDP_OK=1; x=$(dns_v4 <<<"$out"); det_text "${x:-(пустой ответ)}"
    DNS_PUB="$DNS_PUB $x"
  done
fi
det_sec "DNS-over-HTTPS"
for u in "https://cloudflare-dns.com/dns-query?name=$HN&type=A" "https://dns.google/resolve?name=$HN&type=A"; do
  det_cmd curl -s -m 8 -H 'accept: application/dns-json' "$u"
  x=$(curl -s -m 8 -H 'accept: application/dns-json' "$u" 2>/dev/null | grep -oE '"data": ?"[0-9.]+"' | grep -oE '[0-9]+(\.[0-9]+){3}' | dns_v4)
  det_text "${x:-(нет ответа)}"; DNS_PUB="$DNS_PUB $x"
done
DNS_PUB=$(tr ' ' '\n' <<<"$DNS_PUB" | dns_v4)
(( DNS_UDP_TRIED && ! DNS_UDP_OK )) && [[ -n "$DNS_PUB" ]] && \
  det_kv "UDP 53 наружу" "закрыт: публичные DNS отвечают только по DoH — устройствам нужен DNS этой сети"
det_kv "Публичные (все)" "${DNS_PUB:-(нет ответа)}"
clear_line

common=""; only_sys=""
for x in $DNS_SYS; do if [[ " $DNS_PUB " == *" $x "* ]]; then common="$common $x"; else only_sys="$only_sys $x"; fi; done
common="${common# }"; only_sys="${only_sys# }"
if [[ -z "$DNS_SYS" ]]; then
  printf "   %s DNS: системный резолвер не знает %s%s\n" "$(badge FAIL)" "$HN" "$N"; count FAIL "DNS: имя $HN не резолвится системным резолвером"
elif [[ "$DNS_SYS" =~ (^| )198\.1[89]\. ]]; then
  printf "   %s DNS: системный резолвер отдаёт %s (fake-ip, 198.18.0.0/15) — имена резолвит локальный прокси%s\n" "$(badge WARN)" "$DNS_SYS" "$N"; count WARN "DNS: fake-ip локального прокси"
elif [[ -z "$DNS_PUB" ]]; then
  printf "   %s DNS: %s — публичные резолверы недоступны, сравнить не с чем\n" "$(badge INFO)" "$DNS_SYS"; count INFO
elif [[ -n "$common" ]]; then
  printf "   %s DNS: системный ответ совпадает с публичным %s(%s)%s\n" "$(badge OK)" "$D" "$common" "$N"; count OK
  [[ -n "$only_sys" ]] && printf "          %s↳ только в системном ответе: %s%s\n" "$D" "$only_sys" "$N"
elif (( INTERNAL )); then
  printf "   %s DNS: split-horizon — изнутри %s, снаружи %s%s\n" "$(badge INFO)" "$DNS_SYS" "$DNS_PUB" "$N"; count INFO
  printf "          %s↳ устройства вне сети или с DoH / iCloud Private Relay придут на %s — проверьте его в «Узлах»%s\n" "$D" "$DNS_PUB" "$N"
else
  printf "   %s DNS: система %s, публичные %s — подмена DNS или split-horizon%s\n" "$(badge WARN)" "$DNS_SYS" "$DNS_PUB" "$N"; count WARN "DNS: системный ответ не совпадает с публичным"
  printf "          %s↳ если запуск изнутри сети клиента — повторите с --internal; иначе DNS по пути подменяет имя%s\n" "$D" "$N"
fi
(( DNS_UDP_TRIED && ! DNS_UDP_OK )) && [[ -n "$DNS_PUB" ]] && \
  printf "          %s↳ UDP 53 до публичных DNS закрыт — это нормально, если в сети свой резолвер%s\n" "$D" "$N"
det_ref
