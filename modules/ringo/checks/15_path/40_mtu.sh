# shellcheck shell=bash
# MTU и PMTUD: доходят ли полноразмерные пакеты. На VPN, GRE, PPPoE путь уже, чем интерфейс; если ICMP
# «need fragmentation» режется, отправитель об этом не узнаёт — TCP-рукопожатие проходит, а большой ответ
# (цепочка сертификатов, профиль, пакет агента) или большое тело запроса зависает. Классическая «чёрная дыра».
# Как проверяется:
#   1) ping с запретом фрагментации (DF) — наибольший пакет, который доходит (если ICMP не закрыт);
#   2) 128 КБ в каждую сторону по TLS — приём (GET /agent/bundle) и отправка (POST /enroll/auth, text/plain);
#   3) если передача встала — повтор с уменьшенным MSS: с каким размером сегмента она проходит.
# Итог: OK — большие передачи проходят; FAIL — встают, а с меньшим MSS идут (чёрная дыра MTU);
#       WARN — встают при любом MSS, MTU пути меньше интерфейса при сбое передачи;
#       INFO — ICMP закрыт, MTU пути меньше интерфейса (но передачи проходят — PMTUD / MSS clamping работают).
[[ "$HOST" == https://* && -n "${SRV_IP:-}" ]] || return 0

MTU_BYTES=131072
IF_MTU=""
if [[ -n "$RIF" ]]; then
  IF_MTU=$(ifconfig "$RIF" 2>/dev/null | sed -nE 's/.*mtu ([0-9]+).*/\1/p' | head -1)
  [[ -z "$IF_MTU" && -r "/sys/class/net/$RIF/mtu" ]] && IF_MTU=$(cat "/sys/class/net/$RIF/mtu")
fi

# ping с DF: размер данных ICMP (пакет = данные + 28) -> 0, если дошёл (две попытки: разовая потеря — не ответ)
ping_df() {
  local k
  for k in 1 2; do
    if [[ "$(uname -s)" == Darwin ]]; then ping -D -n -c 1 -t 2 -s "$1" "$SRV_IP" >/dev/null 2>&1 && return 0
    else ping -M do -n -c 1 -W 2 -s "$1" "$SRV_IP" >/dev/null 2>&1 && return 0; fi
  done
  return 1
}
# большая передача: направление, MSS (0 — по умолчанию) -> строка mss_probe.py (или эквивалент через curl)
MTU_PY="$(safe_python)"; MTU_DOWN_PATH="/agent/bundle"
big_xfer() {
  local dir="$1" mss="$2" path out rc
  [[ "$dir" == down ]] && path="$MTU_DOWN_PATH" || path="/enroll/auth"
  if [[ -n "$MTU_PY" ]]; then
    "$MTU_PY" "$MOD_DIR/lib/mss_probe.py" "$HN" "$SRV_IP" "$SRV_PORT" "$path" "$dir" "$mss" "$MTU_BYTES" 6 2>/dev/null || echo "err tcp python"
    return
  fi
  # без python: только MSS по умолчанию, через curl (остановка — 6 с без данных)
  if [[ "$dir" == down ]]; then
    out=$(curl -sk -m 30 --speed-time 6 --speed-limit 1 -r "0-$((MTU_BYTES - 1))" --resolve "$HN:$SRV_PORT:$SRV_IP" \
          -o /dev/null -w '%{size_download} %{time_total} %{http_code}' "https://$HN:$SRV_PORT$path" 2>/dev/null); rc=$?
  else
    head -c "$MTU_BYTES" /dev/zero | tr '\0' A >"$FPD/mtu_up.txt"
    out=$(curl -sk -m 30 --speed-time 6 --speed-limit 1 -H 'Content-Type: text/plain' --data-binary "@$FPD/mtu_up.txt" \
          --resolve "$HN:$SRV_PORT:$SRV_IP" -o /dev/null -w '%{size_upload} %{time_total} %{http_code}' "https://$HN:$SRV_PORT$path" 2>/dev/null); rc=$?
  fi
  read -r b t c <<<"${out:-0 0 000}"
  if (( rc == 0 )); then echo "ok ${b%.*} $(awk -v x="$t" 'BEGIN{printf "%d", x*1000}') $c -"
  elif (( rc == 28 )); then echo "stall ${b%.*} recv"
  else echo "err tcp curl rc=$rc"; fi
}
xfer_txt() { # строка результата -> по-русски
  local r b ms c x; read -r r b ms c x <<<"$1"
  case "$r" in
    ok)    echo "прошло $((b / 1024)) КБ за $ms мс (HTTP $c)" ;;
    stall) case "$ms" in tls) echo "встало на TLS-рукопожатии" ;; *) echo "встало на $((b / 1024)) КБ — данные перестали идти" ;; esac ;;
    *)     echo "соединение не установлено: ${1#err }" ;;
  esac
}

# ---- 1) ICMP ----
prog "   %sMTU: ping с запретом фрагментации…%s" "$D" "$N"
PMTU=""; ICMP_OK=0
if ping_df 56; then
  ICMP_OK=1
  hi=$(( ${IF_MTU:-1500} - 28 ))
  if ping_df "$hi"; then PMTU=$(( hi + 28 ))
  else
    lo=56
    while (( hi - lo > 4 )); do
      mid=$(( (lo + hi) / 2 ))
      if ping_df "$mid"; then lo=$mid; else hi=$mid; fi
    done
    PMTU=$(( lo + 28 ))
  fi
fi

# ---- 2) большие передачи с MSS по умолчанию ----
prog "\r\033[K   %sMTU: 128 КБ от сервера и на сервер…%s" "$D" "$N"
DOWN=$(big_xfer down 0)
read -r r b _ c _ <<<"$DOWN"
if [[ "$r" == ok && ! "$c" =~ ^20[06]$ ]]; then MTU_DOWN_PATH="/enroll"; DOWN=$(big_xfer down 0); fi   # пакета агента нет
UP=$(big_xfer up 0)

# ---- 3) с каким MSS передача проходит ----
mss_search() { # направление -> MSS_OK (пусто — ни с каким), MSS_LOG
  local m res; MSS_OK=""; MSS_LOG=""
  [[ -n "$MTU_PY" ]] || return 0
  for m in 1360 1300 1200 1000 800 536; do
    res=$(big_xfer "$1" "$m"); MSS_LOG="$MSS_LOG"$'\n'"MSS $m: $(xfer_txt "$res")"
    [[ "$res" == ok* ]] && { MSS_OK="$m"; MSS_HOW=$(awk '{print $5}' <<<"$res"); return 0; }
  done
}
DOWN_MSS=""; UP_MSS=""; DOWN_LOG=""; UP_LOG=""; MSS_HOW=""
if [[ "$DOWN" != ok* ]]; then prog "\r\033[K   %sMTU: подбор MSS для приёма…%s" "$D" "$N"; mss_search down; DOWN_MSS="$MSS_OK"; DOWN_LOG="$MSS_LOG"; DOWN_HOW="$MSS_HOW"; fi
if [[ "$UP" != ok* ]]; then prog "\r\033[K   %sMTU: подбор MSS для отправки…%s" "$D" "$N"; mss_search up; UP_MSS="$MSS_OK"; UP_LOG="$MSS_LOG"; fi
clear_line

mtu_det_common() {
  det_kv "Интерфейс" "${RIF:-?}, MTU ${IF_MTU:-?}"
  det_kv "MTU пути по ICMP" "$( ((ICMP_OK)) && echo "$PMTU (наибольший пакет с DF, который дошёл)" || echo "не измерен — ICMP до сервера закрыт")"
}

# строка ICMP
det_new "MTU пути: ping с запретом фрагментации"
det_kv "Как проверяется" "ping с флагом DF (не фрагментировать) и разным размером — ищется наибольший пакет, который доходит до $SRV_IP"
if [[ "$(uname -s)" == Darwin ]]; then det_cmd ping -D -n -c 1 -t 2 -s "$(( ${PMTU:-1500} - 28 ))" "$SRV_IP"
else det_cmd ping -M do -n -c 1 -W 2 -s "$(( ${PMTU:-1500} - 28 ))" "$SRV_IP"; fi
mtu_det_common
det_text "Пакет = данные ping + 28 байт заголовков. MTU пути меньше интерфейса — по дороге туннель (VPN, GRE, PPPoE)."
if (( ! ICMP_OK )); then
  printf "   %s MTU пути: ICMP до сервера закрыт — по ping не измерить, смотрите большие передачи ниже\n" "$(badge INFO)"; count INFO
elif [[ -n "$IF_MTU" ]] && (( PMTU < IF_MTU )); then
  if [[ "$DOWN" == ok* && "$UP" == ok* ]]; then
    printf "   %s MTU пути %d меньше MTU интерфейса %d — по дороге туннель; большие передачи проходят%s\n" "$(badge INFO)" "$PMTU" "$IF_MTU" "$N"; count INFO
  else
    printf "   %s MTU пути %d меньше MTU интерфейса %d, а большие передачи встают%s\n" "$(badge WARN)" "$PMTU" "$IF_MTU" "$N"
    count WARN "MTU пути $PMTU меньше MTU интерфейса $IF_MTU"
  fi
else
  printf "   %s MTU пути %d %s(равен MTU интерфейса)%s\n" "$(badge OK)" "$PMTU" "$D" "$N"; count OK
fi
det_ref

# строки больших передач
mtu_row() { # направление, результат, MSS, с которым прошло, журнал подбора, подпись
  local dir="$1" res="$2" mss="$3" log="$4" what="$5"
  det_new "MTU: большая передача — $what"
  det_kv "Как проверяется" "$((MTU_BYTES / 1024)) КБ по TLS напрямую на $SRV_IP; если данные перестают идти на 6 с — передача встала"
  if [[ "$dir" == down ]]; then det_cmd curl -sk -r "0-$((MTU_BYTES - 1))" --resolve "$HN:$SRV_PORT:$SRV_IP" -o /dev/null "https://$HN:$SRV_PORT$MTU_DOWN_PATH"
  else det_cmdline "head -c $MTU_BYTES /dev/zero | tr '\\0' A | curl -sk -H 'Content-Type: text/plain' --data-binary @- --resolve $HN:$SRV_PORT:$SRV_IP https://$HN:$SRV_PORT/enroll/auth"; fi
  mtu_det_common
  det_kv "MSS по умолчанию" "$(xfer_txt "$res")"
  [[ -n "$log" ]] && { det_sec "Подбор MSS (mss_probe.py)"; det_text "${log#$'\n'}"; }
  [[ "$dir" == down && -n "$log" && "${DOWN_HOW:-}" == post ]] && \
    det_text "macOS не даёт уменьшить MSS приёма: подбор для этого направления неточен, повторите проверку с Linux."
  if [[ "$res" == ok* ]]; then
    printf "   %s %s: %s\n" "$(badge OK)" "$what" "$(xfer_txt "$res")"; count OK
  elif [[ -n "$mss" ]]; then
    printf "   %s %s: %s, а с MSS %d — проходит: чёрная дыра MTU (путь ≈ %d)%s\n" "$(badge FAIL)" "$what" "$(xfer_txt "$res")" "$mss" "$((mss + 40))" "$N"
    count FAIL "чёрная дыра MTU: $what встаёт, с MSS $mss проходит"
  else
    printf "   %s %s: %s%s\n" "$(badge WARN)" "$what" "$(xfer_txt "$res")" "$N"
    count WARN "$what: большая передача не прошла"
  fi
  det_ref
}
mtu_row down "$DOWN" "$DOWN_MSS" "$DOWN_LOG" "приём от сервера"
mtu_row up "$UP" "$UP_MSS" "$UP_LOG" "отправка на сервер"
