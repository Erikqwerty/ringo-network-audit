# shellcheck shell=bash
# MDM-сервер → APNs: api.push.apple.com по HTTP/2 на 443 или 2197. Итог: OK — 443; WARN — только 2197; FAIL — ни один.
(( NO_BUILTIN == 0 )) || return 0
[[ "$ROLE" != "client" ]] || return 0

a=$(res_get api.push.apple.com 443); b=$(res_get api.push.apple.com 2197)
why="api.push.apple.com:443 — $(st_of api.push.apple.com 443)"$'\n'"api.push.apple.com:2197 — $(st_of api.push.apple.com 2197)"$'\n'"MDM-сервер отправляет push через HTTP/2 (ALPN h2) на один из этих портов."
if   [[ "$a" == ok ]]; then verdict OK "MDM-сервер → APNs: api.push.apple.com:443 (HTTP/2) доступен" "$why"
elif [[ "$b" == ok ]]; then verdict WARN "MDM-сервер → APNs: доступен только порт 2197" "$why"
else verdict FAIL "MDM-сервер → APNs: api.push.apple.com недоступен (443 и 2197) — сервер не отправит push" "$why"; count FAIL; fi
