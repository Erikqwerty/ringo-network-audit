# shellcheck shell=bash
# Активация устройства: albert.apple.com (сертификаты активации/identity). Итог: OK или FAIL.
(( NO_BUILTIN == 0 )) || return 0
[[ "$ROLE" != "server" ]] || return 0

al=$(res_get albert.apple.com 443)
[[ "$al" == ok ]] && verdict OK "Активация: albert.apple.com доступен (сертификаты активации/identity)" "albert.apple.com:443 — доступен" \
                  || verdict FAIL "Активация: albert.apple.com недоступен — устройство не активируется" "albert.apple.com:443 — недоступен (подробности — в строке хоста выше)"
