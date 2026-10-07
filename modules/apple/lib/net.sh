# shellcheck shell=bash
# Сеть: DNS, TCP и TLS-пробы до хостов Apple, признаки SSL-inspection.
# Подключается через source из modules/apple/run.sh; сам не запускается.

# macOS nc: -w не ограничивает время подключения, нужен -G
NC_CT=(); [[ "$(uname -s)" == Darwin ]] && NC_CT=(-G "$TMO")

resolve() { # только IPv4, по одному в строке
  local h="$1" r=""
  if have dig; then r=$(dig +short +time=3 +tries=1 A "$h" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'); fi
  if [[ -z "$r" ]] && have getent; then r=$(getent ahostsv4 "$h" 2>/dev/null | awk '{print $1}' | sort -u); fi
  if [[ -z "$r" ]] && have dscacheutil; then r=$(dscacheutil -q host -a name "$h" 2>/dev/null | awk '/^ip_address:/{print $2}' | sort -u); fi
  if [[ -z "$r" ]] && have host; then r=$(host -W 3 "$h" 2>/dev/null | awk '/has address/{print $4}'); fi
  printf '%s' "$r"
}
resolve_c() { # с кэшем, результат в RESOLVED; "-" = не резолвится. Вызывать без $(…), иначе кэш теряется
  local n="DNSC_${1//[^A-Za-z0-9]/_}"
  RESOLVED="${!n:-}"
  if [[ -z "$RESOLVED" ]]; then
    RESOLVED=$(resolve "$1"); [[ -z "$RESOLVED" ]] && RESOLVED="-"
    printf -v "$n" '%s' "$RESOLVED"
  fi
}
is_apple_ip() { [[ "$1" == 17.* || "$1" == 2403:300:* || "$1" == 2620:149:* || "$1" == 2a01:b740:* ]]; }

tcp_probe() { # 0 — открыт, 1 — отказ, 2 — таймаут
  local h="$1" p="$2" t0=$SECONDS rc
  if have nc; then
    nc -z ${NC_CT[@]+"${NC_CT[@]}"} -w "$TMO" "$h" "$p" >/dev/null 2>&1; rc=$?
  elif have python3; then
    python3 - "$h" "$p" "$TMO" >/dev/null 2>&1 <<'PY'
import socket,sys
s=socket.socket(); s.settimeout(float(sys.argv[3]))
try: s.connect((sys.argv[1],int(sys.argv[2]))); sys.exit(0)
except Exception: sys.exit(1)
PY
    rc=$?
  else
    ( exec 3<>"/dev/tcp/$h/$p" ) >/dev/null 2>&1; rc=$?
  fi
  (( rc == 0 )) && return 0
  (( SECONDS - t0 >= TMO - 1 )) && return 2
  return 1
}

INSPECT_RE='fortinet|fortigate|palo alto|zscaler|blue ?coat|symantec|sophos|check ?point|umbrella|mcafee|forcepoint|netskope|sonicwall|untangle|barracuda|trend ?micro|ideco|usergate|kaspersky|eset|dr\.? ?web|squid|mikrotik|cisco|watchguard|websense|proxy|firewall|gateway|inspection|mitm|filter'

tls_probe() { # host port mode(1|h2) [ip] -> TLS_RES ok|hs|slow|noalpn|inspect|other ; TLS_ISS
  local host="$1" port="$2" mode="$3" ip="${4:-$1}" out rc iss short alpn=()
  TLS_RES="hs"; TLS_ISS=""; TLS_OUT=""
  have openssl || { TLS_RES="ok"; TLS_ISS="openssl не найден — TLS не проверен"; return; }
  [[ "$mode" == "h2" ]] && alpn=(-alpn h2)
  out=$(with_timeout $((TMO+4)) openssl s_client -connect "$ip:$port" -servername "$host" ${alpn[@]+"${alpn[@]}"} </dev/null 2>&1); rc=$?
  # для подробностей отчёта — ключевые строки рукопожатия
  TLS_OUT=$(grep -E 'CONNECTED|^ *[0-9]+ s:|^ +i:|Protocol *:|Cipher is|ALPN|Verify return|errno|alert' <<<"$out" | head -14)
  if ! grep -q 'BEGIN CERTIFICATE' <<<"$out"; then
    # убит по таймауту (124 — timeout, 142 — perl alarm) без обрыва: ответ просто не успел прийти
    (( rc == 124 || rc == 142 )) && ! grep -qiE 'reset|errno=' <<<"$out" && TLS_RES="slow"
    return
  fi
  iss=$(printf '%s\n' "$out" | openssl x509 -noout -issuer 2>/dev/null | sed -E 's/^issuer= *//')
  [[ -z "$iss" ]] && iss=$(grep -m1 -E '^ *i:' <<<"$out" | sed -E 's/^ *i: *//')
  short=$(sed -nE 's/.*CN ?= ?([^,\/]+).*/\1/p' <<<"$iss" | head -1)
  [[ -z "$short" ]] && short="$iss"
  TLS_ISS="${short:0:52}"
  if grep -Eqi 'apple|digicert' <<<"$iss"; then
    TLS_RES="ok"
    if [[ "$mode" == "h2" ]] && ! grep -qi 'ALPN protocol: h2' <<<"$out"; then TLS_RES="noalpn"; fi
  elif grep -Eqi "$INSPECT_RE" <<<"$iss"; then
    TLS_RES="inspect"
  else
    TLS_RES="other"
  fi
}
