# shellcheck shell=bash
# Срок действия сертификата сервера (по $FPD/leaf.pem из проверки цепочки).
# -checkend есть и в OpenSSL, и в LibreSSL — без разбора дат.
# Итог: OK — больше 30 дней; WARN — меньше 30 дней; FAIL — истёк. Истёкший и заглушку уже отметила цепочка.
[[ "$HOST" == https://* ]] || return 0
leaf="$FPD/leaf.pem"
[[ -s "$leaf" ]] || return 0
openssl x509 -in "$leaf" -noout >/dev/null 2>&1 || return 0   # сертификат читается
end=$(openssl x509 -in "$leaf" -noout -enddate 2>/dev/null | sed 's/^notAfter=//')

det_new "Срок действия сертификата"; det_sec "Сертификат сервера"
det_cmd openssl x509 -in leaf.pem -noout -subject -issuer -dates
det_text "$(openssl x509 -in "$leaf" -noout -subject -issuer -dates 2>/dev/null)"
det_text "Порог предупреждения — 30 дней (openssl x509 -checkend)."
if [[ "$CH_RES" =~ ^(expired|placeholder)$ ]]; then :   # уже FAIL в проверке цепочки (у заглушки — её срок)
elif ! openssl x509 -in "$leaf" -noout -checkend 0 >/dev/null 2>&1; then
  printf "   %s сертификат истёк %s(%s)%s\n" "$(badge FAIL)" "$D" "$end" "$N"; count FAIL "сертификат сервера истёк"
elif ! openssl x509 -in "$leaf" -noout -checkend $((30*86400)) >/dev/null 2>&1; then
  printf "   %s сертификат истекает меньше чем через 30 дней %s(%s)%s\n" "$(badge WARN)" "$D" "$end" "$N"; count WARN "сертификат истекает < 30 дней"
else
  printf "   %s срок действия сертификата %s(до %s)%s\n" "$(badge OK)" "$D" "$end" "$N"; count OK
fi
det_ref
