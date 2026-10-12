# shellcheck shell=bash
# Узлы: если имя указывает на несколько адресов (round-robin, несколько балансировщиков, разные адреса
# изнутри и снаружи), устройства ходят на любой из них. Один узел со старым сертификатом, другой версией
# Ringo или без живого бэкенда — и «у части устройств не работает». Каждый адрес проверяется отдельно
# (curl --resolve): сертификат, заголовок Server и коды ключевых эндпоинтов, затем узлы сравниваются.
# Итог по узлу: OK — как у основного; FAIL — не отвечает; WARN — другой сертификат или другие коды.
# Один адрес — строки нет, только сведения.
[[ "$HOST" == https://* && -n "${SRV_IP:-}" ]] || return 0

NODES=$(printf '%s\n' "$SRV_IP" ${DNS_SYS:-} ${DNS_PUB:-} | grep -E '^[0-9]+(\.[0-9]+){3}$' | awk '!s[$0]++' | paste -sd' ' -)
NODE_ARR=($NODES)
if (( ${#NODE_ARR[@]} < 2 )); then
  printf "   • Узлы: один адрес (%s)%s\n" "$SRV_IP" "$( [[ -n "${DNS_AAAA:-}" ]] && printf ' и IPv6 %s' "$DNS_AAAA")"
  return 0
fi

# ключевые запросы устройств и агента: «метод путь content-type»
NODE_REQ=("GET /scep?operation=GetCACaps -" "PUT /mdm/checkin application/x-apple-aspen-mdm-checkin"
          "GET /agent/manifest -" "GET /socket.io/?EIO=${EIO:-4}&transport=polling -")
node_src() { # ip -> откуда адрес
  local s=""
  [[ " ${DNS_SYS:-} " == *" $1 "* ]] && s="системный DNS"
  [[ " ${DNS_PUB:-} " == *" $1 "* ]] && s="${s:+$s, }публичный DNS"
  echo "${s:-адрес подключения}"
}
node_probe() { # ip -> N_CERT, N_END, N_SRV, N_CODES, N_ERR
  local ip="$1" r m p ct c pem a=()
  N_CERT=""; N_END=""; N_SRV=""; N_CODES=""; N_ERR=""
  pem=$(with_timeout 10 openssl s_client -connect "$ip:$SRV_PORT" -servername "$HN" </dev/null 2>/dev/null \
        | awk '/-----BEGIN CERTIFICATE-----/{c=1} c{print} /-----END CERTIFICATE-----/{exit}')
  if [[ -n "$pem" ]]; then
    N_CERT=$(openssl x509 -noout -fingerprint -sha256 <<<"$pem" 2>/dev/null | sed 's/.*=//; s/://g' | tail -c 13)
    N_END=$(openssl x509 -noout -enddate <<<"$pem" 2>/dev/null | sed 's/notAfter=//')
  fi
  det_sec "Узел $ip ($(node_src "$ip"))"
  det_cmd openssl s_client -connect "$ip:$SRV_PORT" -servername "$HN"
  det_kv "Сертификат" "${N_CERT:+SHA-256 …$N_CERT, до $N_END}"
  for r in "${NODE_REQ[@]}"; do
    read -r m p ct <<<"$r"; a=(); [[ "$m" != GET ]] && a=(-X "$m" -H "Content-Type: $ct" --data-binary "")
    c=$(curl -sk -m 10 --resolve "$HN:$SRV_PORT:$ip" ${a[@]+"${a[@]}"} -o /dev/null -D "$TMP.nh" -w '%{http_code}' "https://$HN:$SRV_PORT$p" 2>/dev/null)
    [[ -z "$N_SRV" ]] && N_SRV=$(sed -nE 's/^[Ss]erver: *([^[:cntrl:]]*).*/\1/p' "$TMP.nh" 2>/dev/null | head -1)
    det_cmd curl -sk -m 10 --resolve "$HN:$SRV_PORT:$ip" ${a[@]+"${a[@]}"} "https://$HN:$SRV_PORT$p"
    det_text "→ ${c:-000}"
    N_CODES="$N_CODES ${c:-000}"
  done
  N_CODES="${N_CODES# }"
  [[ -z "$N_CERT" && "$N_CODES" == "000 000 000 000" ]] && N_ERR="не отвечает (нет TLS и HTTP)"
  det_kv "Server" "${N_SRV:-—}"; det_kv "Коды" "$N_CODES"
  rm -f "$TMP.nh"
}

printf "   • Узлы: %d адреса — %s\n" "${#NODE_ARR[@]}" "$NODES"
REF_CERT=""; REF_CODES=""; REF_SRV=""; REF_IP=""
for ip in $NODES; do
  prog "   %sузел %s…%s" "$D" "$ip" "$N"
  det_new "Узел $ip"
  det_kv "Как проверяется" "запросы идут на этот адрес напрямую (curl --resolve) с именем $HN; сравнение — с узлом $SRV_IP, на который попал аудит"
  node_probe "$ip"
  clear_line
  if [[ -z "$REF_IP" ]]; then REF_IP="$ip"; REF_CERT="$N_CERT"; REF_CODES="$N_CODES"; REF_SRV="$N_SRV"; fi
  diff=""
  [[ "$ip" != "$REF_IP" && -n "$N_CERT" && "$N_CERT" != "$REF_CERT" ]] && diff="другой сертификат (…$N_CERT, до $N_END)"
  [[ "$ip" != "$REF_IP" && "$N_CODES" != "$REF_CODES" ]] && diff="${diff:+$diff; }другие коды: $N_CODES вместо $REF_CODES"
  [[ "$ip" != "$REF_IP" && -n "$diff" && "$N_SRV" != "$REF_SRV" ]] && diff="$diff; Server: ${N_SRV:-—}"
  if [[ -n "$N_ERR" ]]; then
    printf "   %s узел %s %s(%s)%s: %s\n" "$(badge FAIL)" "$ip" "$D" "$(node_src "$ip")" "$N" "$N_ERR"
    count FAIL "узел $ip не отвечает — часть устройств не подключится"
  elif [[ -n "$diff" ]]; then
    printf "   %s узел %s %s(%s)%s: %s\n" "$(badge WARN)" "$ip" "$D" "$(node_src "$ip")" "$N" "$diff"
    count WARN "узел $ip отвечает не так, как $REF_IP"
  else
    printf "   %s узел %s %s(%s)%s: сертификат …%s, коды %s\n" "$(badge OK)" "$ip" "$D" "$(node_src "$ip")" "$N" "${N_CERT:-?}" "$N_CODES"; count OK
  fi
  det_ref
done
