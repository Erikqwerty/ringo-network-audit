# shellcheck shell=bash
# Адреса проверки отзыва (OCSP / CRL) из сертификата открываются: устройства Apple их проверяют.
# Видно только с этого компьютера; любой HTTP-ответ = адрес доступен (OCSP на GET отвечает 4xx).
# Итог: OK — все доступны; WARN — ни один; INFO — часть. Нет адресов в сертификате — строки нет.
[[ "$HOST" == https://* ]] || return 0
leaf="$FPD/leaf.pem"
[[ -s "$leaf" ]] || return 0
txt=$(openssl x509 -in "$leaf" -noout -text 2>/dev/null) || return 0
ok=0; bad=0; badl=""

urls=$( { sed -nE 's/.*OCSP - URI:(http[^[:space:],]+).*/OCSP \1/p' <<<"$txt"
          awk '/CRL Distribution Points/{f=1;next} f&&/URI:/{sub(/.*URI:/,""); print "CRL " $0; next} f&&!/Full Name|^ *$/{f=0}' <<<"$txt"; } | sort -u)
if [[ -n "$urls" ]]; then
  det_new "Адреса проверки отзыва (OCSP / CRL)"; det_sec "Адреса из сертификата и их доступность"
  det_text "Любой HTTP-ответ означает, что адрес доступен (OCSP на GET обычно отвечает 4xx)."
  while read -r kind u; do
    [[ -n "$u" ]] || continue
    c=$(curl -s -m 8 -r 0-2047 -o /dev/null -w '%{http_code}' "$u" 2>/dev/null)
    det_cmd curl -s -m 8 -r 0-2047 -o /dev/null -w '%{http_code}' "$u"; det_kv "$kind" "HTTP ${c:-000}$([[ "${c:-000}" == 000 ]] && echo ' — нет ответа')"
    if [[ "${c:-000}" != 000 ]]; then ((ok++)); else ((bad++)); badl="$badl $kind ${u#http://}"; fi
  done <<<"$urls"
  if (( bad == 0 )); then
    printf "   %s адреса проверки отзыва доступны %s(%d: %s)%s\n" "$(badge OK)" "$D" "$ok" "$(awk '{print $1}' <<<"$urls" | sort | uniq -c | awk '{printf "%s%s×%s", (NR>1?", ":""), $2, $1}')" "$N"; count OK
  elif (( ok == 0 )); then
    printf "   %s адреса проверки отзыва недоступны:%s%s\n" "$(badge WARN)" "$badl" "$N"; count WARN "OCSP/CRL сертификата недоступны"
    printf "          %s↳ если и у устройств так, проверка отзыва затянется или сорвётся; откройте эти адреса для клиентов%s\n" "$D" "$N"
  else
    printf "   %s часть адресов отзыва недоступна:%s %s(доступно %d из %d)%s\n" "$(badge INFO)" "$badl" "$D" "$ok" "$((ok+bad))" "$N"; count INFO
  fi
  det_ref
fi
