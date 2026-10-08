# shellcheck shell=bash
# Портал APNs-сертификата: identity.apple.com — без него не выпустить/продлить APNs-сертификат. Итог: OK или FAIL.
(( NO_BUILTIN == 0 )) || return 0
[[ "$ROLE" != "client" ]] || return 0

id=$(res_get identity.apple.com 443)
[[ "$id" == ok ]] && verdict OK "Портал APNs-сертификата: identity.apple.com доступен" \
                  || verdict FAIL "Портал APNs-сертификата: identity.apple.com недоступен — не выпустить/продлить APNs-сертификат"
