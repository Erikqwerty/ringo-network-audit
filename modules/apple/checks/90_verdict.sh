# shellcheck shell=bash
# Проверка: вердикт по ключевым сценариям и итог. Выполняется по порядку из modules/apple/run.sh (source, общие переменные).

# ---------- вердикт ----------
echo
echo "${D}────────────────────────────────────────────────────────────────────${N}"
echo " ${BD}Вердикт по ключевым сценариям${N}"
# вердикт СТАТУС текст [на чём основан] — основание уходит в подробности отчёта
verdict() {
  det_new "Вердикт"; det_text "$2"; [[ -n "${3:-}" ]] && { det_sec "На чём основан"; det_text "$3"; }
  printf "   %s %s\n" "$(badge "$1")" "$2"; det_ref
}
st_of() { [[ "$(res_get "$1" "$2")" == ok ]] && echo "доступен" || echo "недоступен"; }

if (( NO_BUILTIN == 0 )); then
  if [[ "$ROLE" != "server" ]]; then
    a=$(res_get courier.push.apple.com 5223); b=$(res_get courier.push.apple.com 443)
    why="courier.push.apple.com:5223 — $(st_of courier.push.apple.com 5223)"$'\n'"courier.push.apple.com:443 — $(st_of courier.push.apple.com 443)"$'\n'"Устройство держит постоянное соединение с APNs; 443 — запасной канал, если 5223 закрыт."
    if   [[ "$a" == ok ]]; then verdict OK "Push на устройства: APNs доступен по 5223" "$why"
    elif [[ "$b" == ok ]]; then verdict WARN "Push на устройства: 5223 закрыт, работает только запасной канал 443" "$why"
    else verdict FAIL "Push на устройства: APNs недоступен (5223 и 443) — устройства не получат MDM-команды" "$why"; count FAIL; fi
    al=$(res_get albert.apple.com 443)
    [[ "$al" == ok ]] && verdict OK "Активация: albert.apple.com доступен (сертификаты активации/identity)" "albert.apple.com:443 — доступен" \
                      || verdict FAIL "Активация: albert.apple.com недоступен — устройство не активируется" "albert.apple.com:443 — недоступен (подробности — в строке хоста выше)"
  fi
  if [[ "$ROLE" != "client" ]]; then
    a=$(res_get api.push.apple.com 443); b=$(res_get api.push.apple.com 2197)
    why="api.push.apple.com:443 — $(st_of api.push.apple.com 443)"$'\n'"api.push.apple.com:2197 — $(st_of api.push.apple.com 2197)"$'\n'"MDM-сервер отправляет push через HTTP/2 (ALPN h2) на один из этих портов."
    if   [[ "$a" == ok ]]; then verdict OK "MDM-сервер → APNs: api.push.apple.com:443 (HTTP/2) доступен" "$why"
    elif [[ "$b" == ok ]]; then verdict WARN "MDM-сервер → APNs: доступен только порт 2197" "$why"
    else verdict FAIL "MDM-сервер → APNs: api.push.apple.com недоступен (443 и 2197) — сервер не отправит push" "$why"; count FAIL; fi
    id=$(res_get identity.apple.com 443)
    [[ "$id" == ok ]] && verdict OK "Портал APNs-сертификата: identity.apple.com доступен" \
                      || verdict FAIL "Портал APNs-сертификата: identity.apple.com недоступен — не выпустить/продлить APNs-сертификат"
  fi
  if (( CERT_FAIL )); then verdict FAIL "Проверка сертификатов (OCSP/CRL): недоступно хостов — $CERT_FAIL"
  else verdict OK "Проверка сертификатов (OCSP/CRL): критичные хосты доступны"; fi
fi
short_list() { # первые 4 элемента + «и ещё N»
  local n=0 out="" x extra
  for x in $1; do ((n++)); (( n <= 4 )) && out="$out $x"; done
  (( n > 4 )) && out="$out … и ещё $((n-4))"
  printf '%s' "$out"
}
if [[ -n "$SSLI_LIST" ]]; then
  verdict FAIL "SSL-inspection похоже включён:$(short_list "$SSLI_LIST") — Apple обрывает такие соединения; исключите эти хосты из инспекции"; count FAIL
elif [[ -n "$ISSUER_LIST" ]]; then
  verdict WARN "Издатель сертификата не Apple/DigiCert:$(short_list "$ISSUER_LIST") — проверьте вручную (openssl s_client -connect хост:443)"
else
  verdict OK "SSL-inspection на проверенных хостах не замечен" "У всех хостов с TLS издатель сертификата — Apple или DigiCert."
fi
if [[ "$OUTSIDE_LIST" != "|" ]]; then
  n=$(tr -cd '|' <<<"$OUTSIDE_LIST" | awk '{print length($0)-1}')
  verdict INFO "Хостов вне 17.0.0.0/8 (CDN): $n — при allow-list по IP их придётся разрешать отдельно, надёжнее фильтровать по имени"; count INFO
fi

echo "${D}────────────────────────────────────────────────────────────────────${N}"
print_totals
if   (( FAIL_CNT )); then echo " ${R}${BD}Есть блокирующие проблемы для Apple MDM.${N}"; echo; exit 2
elif (( WARN_CNT )); then echo " ${Y}${BD}Есть замечания — проверьте перечисленные хосты.${N}"; echo; exit 1
else echo " ${G}${BD}Сетевое окружение соответствует требованиям Apple.${N}"; echo; fi
