# shellcheck shell=bash
# Сервер принимает TLS 1.2 и TLS 1.3 (требование документации Ringo).
# Сначала curl; если он не справился — openssl: curl на macOS часто сам не умеет нужную версию.
# Итог: OK — принято; FAIL — сервер отклонил версию; WARN — проверить не удалось (сеть или утилиты).
[[ "$HOST" == https://* ]] || return 0

# результат: TLS_RES=ok|fail|unknown, TLS_VIA=curl|openssl, TLS_DETAIL=пояснение
tls_check() {
  local v="$1" args cout out rc hn hp sni flag
  TLS_RES="unknown"; TLS_VIA=""; TLS_DETAIL=""
  if [[ "$v" == "1.2" ]]; then args=(--tlsv1.2 --tls-max 1.2); flag="-tls1_2"; else args=(--tlsv1.3); flag="-tls1_3"; fi

  cout=$(curl -sS -k -m 10 -o /dev/null "${args[@]}" "$HOST/" 2>&1); rc=$?
  det_sec "Проверка через curl"; det_cmd curl -sSk -m 10 -o /dev/null "${args[@]}" "$HOST/"
  det_kv "Код возврата curl" "$rc$( ((rc == 0)) && echo " — рукопожатие прошло")"; [[ -n "$cout" ]] && det_text "$cout"
  if (( rc == 0 )); then TLS_RES="ok"; TLS_VIA="curl"; return; fi

  # curl не справился: может быть и отказ сервера, и ограничение самого curl (частый случай на macOS)
  TLS_DETAIL="curl rc=$rc"
  if command -v openssl >/dev/null 2>&1; then
    hn="${HOST#https://}"; hn="${hn%%/*}"; sni="${hn%%:*}"
    [[ "$hn" == *:* ]] && hp="$hn" || hp="$hn:443"
    out=$(with_timeout 12 openssl s_client -connect "$hp" -servername "$sni" "$flag" </dev/null 2>&1)
    det_sec "Проверка через openssl (curl не дал ответа)"; det_cmd openssl s_client -connect "$hp" -servername "$sni" "$flag"
    det_text "$(grep -E 'CONNECTED|Protocol|Cipher is|alert|error|Verify return' <<<"$out" | head -12)"
    if echo "$out" | grep -Eqi "unknown option|unrecognized option|usage:"; then
      : # этот openssl не умеет такой флаг — вердикта нет
    elif echo "$out" | grep -Eq "Protocol *: TLSv${v//./\\.}|New, TLSv${v//./\\.}, Cipher is [A-Za-z0-9]"; then
      TLS_RES="ok"; TLS_VIA="openssl"; TLS_DETAIL=""; return
    elif echo "$out" | grep -Eqi "Cipher is \(NONE\)|alert protocol version|handshake failure|no protocols available|wrong version number|unsupported protocol"; then
      TLS_RES="fail"; TLS_VIA="openssl"; TLS_DETAIL="сервер отклонил TLS $v"; return
    else
      TLS_DETAIL="$TLS_DETAIL; openssl без чёткого ответа"
    fi
  fi

  # openssl вердикта не дал: rc 2/4 у curl = «не умею», а не «сервер не смог»
  if (( rc == 2 || rc == 4 )) || echo "$cout" | grep -qiE "doesn't support|not supported|unknown option"; then
    TLS_RES="unknown"; TLS_DETAIL="ваш curl не поддерживает эту проверку (rc=$rc), openssl недоступен"
  elif (( rc == 28 || rc == 52 || rc == 56 || rc == 7 )); then
    TLS_RES="unknown"; TLS_DETAIL="$(net_hint "$rc") — это сеть, а не версия TLS"
  else
    TLS_RES="fail"; TLS_VIA="curl"
  fi
}

for v in 1.2 1.3; do
  prog "   %s…%s" "$D" "$N"
  det_new "TLS $v"; det_kv "Что проверяется" "сервер принимает соединение по TLS $v (требование документации Ringo)"
  tls_check "$v"
  clear_line
  case "$TLS_RES" in
    ok)   printf "   %s TLS %s поддерживается %s(проверено через %s)%s\n" "$(badge OK)" "$v" "$D" "$TLS_VIA" "$N"; count OK ;;
    fail) printf "   %s TLS %s сервером не принят %s(%s %s)%s\n" "$(badge FAIL)" "$v" "$D" "$TLS_VIA" "$TLS_DETAIL" "$N"; count FAIL "TLS $v не принимается" ;;
    *)    printf "   %s TLS %s не удалось проверить %s(%s)%s\n" "$(badge WARN)" "$v" "$D" "$TLS_DETAIL" "$N"; count WARN "TLS $v не проверен" ;;
  esac
  det_ref
done
