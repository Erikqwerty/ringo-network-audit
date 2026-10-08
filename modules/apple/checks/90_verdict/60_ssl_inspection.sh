# shellcheck shell=bash
# SSL-inspection: Apple обрывает такие соединения. Итог: FAIL — издатель похож на прокси/файрвол;
# WARN — издатель не Apple/DigiCert; OK — не замечен.

if [[ -n "$SSLI_LIST" ]]; then
  verdict FAIL "SSL-inspection похоже включён:$(short_list "$SSLI_LIST") — Apple обрывает такие соединения; исключите эти хосты из инспекции"; count FAIL
elif [[ -n "$ISSUER_LIST" ]]; then
  verdict WARN "Издатель сертификата не Apple/DigiCert:$(short_list "$ISSUER_LIST") — проверьте вручную (openssl s_client -connect хост:443)"
else
  verdict OK "SSL-inspection на проверенных хостах не замечен" "У всех хостов с TLS издатель сертификата — Apple или DigiCert."
fi
