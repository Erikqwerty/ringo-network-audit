# shellcheck shell=bash
# Проверка сертификатов (OCSP/CRL): критичные хосты группы доступны. Итог: OK или FAIL.
(( NO_BUILTIN == 0 )) || return 0

if (( CERT_FAIL )); then verdict FAIL "Проверка сертификатов (OCSP/CRL): недоступно хостов — $CERT_FAIL"
else verdict OK "Проверка сертификатов (OCSP/CRL): критичные хосты доступны"; fi
