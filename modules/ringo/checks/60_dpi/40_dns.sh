# shellcheck shell=bash
# DNS: ответ системного резолвера против DNS-over-HTTPS (его не подменить на пути).
# Итог: OK — совпадает; WARN — fake-ip локального прокси (198.18.0.0/15) или подмена / split-horizon;
#       INFO — DoH недоступен. Для сервера, заданного IP-адресом, не выполняется.
(( DPI_PROBE )) && [[ -n "${SRV_IP:-}" ]] || return 0
[[ ! "$HN" =~ ^[0-9.]+$ ]] || return 0

sys_ips=$( (dscacheutil -q host -a name "$HN" 2>/dev/null | awk '/^ip_address:/{print $2}'; getent ahostsv4 "$HN" 2>/dev/null | awk '{print $1}') \
           | grep -E '^[0-9]+(\.[0-9]+){3}$' | sort -u | paste -sd' ' -)
doh_ips=$( (curl -s -m 8 -H 'accept: application/dns-json' "https://cloudflare-dns.com/dns-query?name=$HN&type=A";
            curl -s -m 8 "https://dns.google/resolve?name=$HN&type=A") 2>/dev/null \
           | grep -oE '"data": ?"[0-9.]+"' | grep -oE '[0-9]+(\.[0-9]+){3}' | sort -u | paste -sd' ' -)
det_new "DPI: DNS — системный резолвер против DoH"
det_kv "Как проверяется" "ответ системного DNS сравнивается с DNS-over-HTTPS (его не подменить на пути)"
det_sec "Системный резолвер"; det_cmd dscacheutil -q host -a name "$HN"; det_text "${sys_ips:-(нет ответа)}"
det_sec "DoH"; det_cmd curl -s -m 8 -H 'accept: application/dns-json' "https://cloudflare-dns.com/dns-query?name=$HN&type=A"
det_cmd curl -s -m 8 "https://dns.google/resolve?name=$HN&type=A"; det_text "${doh_ips:-(нет ответа)}"
common=""; for x in $sys_ips; do [[ " $doh_ips " == *" $x "* ]] && common="$x"; done
if [[ "$sys_ips" =~ (^| )198\.1[89]\. ]]; then
  printf "   %s DNS: системный резолвер отдаёт %s (fake-ip, 198.18.0.0/15) — имена резолвит локальный прокси%s\n" "$(badge WARN)" "$sys_ips" "$N"; count WARN "DNS: fake-ip локального прокси"; det_ref
elif [[ -z "$doh_ips" ]]; then
  printf "   %s DNS: DoH недоступен — сравнить не с чем (система: %s)\n" "$(badge INFO)" "${sys_ips:-—}"; det_ref
elif [[ -n "$common" ]]; then
  printf "   %s DNS: системный ответ совпадает с DoH (%s)\n" "$(badge OK)" "$common"; count OK; det_ref
else
  printf "   %s DNS: система %s, DoH %s — подмена DNS или split-horizon%s\n" "$(badge WARN)" "${sys_ips:-—}" "$doh_ips" "$N"; count WARN "DNS: подмена или split-horizon"; det_ref
fi
