# shellcheck shell=bash
# Проверка одной цели: DNS → TCP → TLS, итог в ST/MSG/IPSHOW.
# Подключается через source из modules/apple/run.sh; сам не запускается.

# ---------- проверка одной цели ----------
OUTSIDE_LIST="|"; SSLI_LIST=""; ISSUER_LIST=""
check_target() {
  local host="$1" port="$2" tls="$3" req="$4" cust="${5:-0}" fst="WARN" ips ip1 rc
  [[ "$req" == "1" ]] && fst="FAIL"
  ST="OK"; MSG=""; IPSHOW="-"
  resolve_c "$host"; ips="$RESOLVED"
  det_sec "DNS"; det_cmd dig +short A "$host"; det_text "${ips//-/(не резолвится)}"
  if [[ "$ips" == "-" ]]; then ST="$fst"; MSG="DNS: имя не резолвится"; return; fi
  ip1=$(head -1 <<<"$ips"); IPSHOW="$ip1"
  if (( ! cust )) && [[ "$ip1" =~ ^(0\.|127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|169\.254\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.) ]]; then
    ST="$fst"; MSG="резолвится в частный/нулевой адрес — DNS-фильтр или подмена"; return
  fi
  (( cust )) || is_apple_ip "$ip1" || { [[ "$OUTSIDE_LIST" == *"|$host|"* ]] || OUTSIDE_LIST="$OUTSIDE_LIST$host|"; }
  # дальше — по уже полученному IP: сбой системного резолвера не выдаётся за RST
  tcp_probe "$ip1" "$port"; rc=$?
  det_sec "TCP"; det_cmd nc -z ${NC_CT[@]+"${NC_CT[@]}"} -w "$TMO" "$ip1" "$port"
  det_kv "Результат" "$(case $rc in (0) echo "порт открыт";; (1) echo "отказ (RST / порт закрыт)";; (*) echo "таймаут ${TMO} с — пакеты отбрасываются";; esac)"
  case $rc in
    1) ST="$fst"; MSG="соединение отклонено (порт закрыт / RST)"; return ;;
    2) ST="$fst"; MSG="таймаут ${TMO}с — пакеты, вероятно, отбрасывает файрвол"; return ;;
  esac
  if [[ "$tls" == "0" ]]; then MSG="TCP открыт"; return; fi
  tls_probe "$host" "$port" "$tls" "$ip1"
  det_sec "TLS"; det_cmd openssl s_client -connect "$ip1:$port" -servername "$host" $([[ "$tls" == h2 ]] && echo -alpn h2)
  det_kv "Результат" "$TLS_RES"; [[ -n "$TLS_ISS" ]] && det_kv "Издатель сертификата" "$TLS_ISS"
  [[ -n "${TLS_OUT:-}" ]] && det_text "$TLS_OUT"
  det_text "Apple не допускает SSL-inspection: издатель должен быть Apple или DigiCert, иначе трафик расшифровывает прокси."
  # свои цели: издатель не сверяем с Apple, важно лишь что TLS поднимается
  if (( cust )) && [[ "$TLS_RES" != "hs" && "$TLS_RES" != "slow" ]]; then TLS_RES="ok"; fi
  case "$TLS_RES" in
    ok)      MSG="TLS ok · издатель: $TLS_ISS" ;;
    noalpn)  ST="$fst"; MSG="TLS ok, но HTTP/2 (ALPN h2) не согласован — мешает прокси/inspection?" ;;
    hs)      ST="$fst"; MSG="TCP открыт, но TLS-рукопожатие оборвано (IPS / SSL-inspection?)" ;;
    slow)    ST="WARN"; MSG="TLS не уложился в $((TMO+4)) с — медленный канал; повторите с --timeout больше" ;;
    inspect) ST="$fst"; MSG="ПОХОЖЕ НА SSL-INSPECTION · издатель «${TLS_ISS}»"; SSLI_LIST="$SSLI_LIST $host:$port" ;;
    other)   ST="WARN"; MSG="издатель не Apple/DigiCert: «${TLS_ISS}» — проверьте на SSL-inspection"; ISSUER_LIST="$ISSUER_LIST $host:$port" ;;
  esac
}
res_set() { printf -v "RES_${1//[^A-Za-z0-9]/_}_$2" '%s' "$3"; }
res_get() { local n="RES_${1//[^A-Za-z0-9]/_}_$2"; printf '%s' "${!n:-na}"; }
