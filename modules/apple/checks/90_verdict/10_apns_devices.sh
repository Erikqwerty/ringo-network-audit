# shellcheck shell=bash
# Push на устройства: APNs по 5223, запасной канал — 443. Итог: OK — 5223; WARN — только 443; FAIL — ни один.
(( NO_BUILTIN == 0 )) || return 0
[[ "$ROLE" != "server" ]] || return 0

a=$(res_get courier.push.apple.com 5223); b=$(res_get courier.push.apple.com 443)
why="courier.push.apple.com:5223 — $(st_of courier.push.apple.com 5223)"$'\n'"courier.push.apple.com:443 — $(st_of courier.push.apple.com 443)"$'\n'"Устройство держит постоянное соединение с APNs; 443 — запасной канал, если 5223 закрыт."
if   [[ "$a" == ok ]]; then verdict OK "Push на устройства: APNs доступен по 5223" "$why"
elif [[ "$b" == ok ]]; then verdict WARN "Push на устройства: 5223 закрыт, работает только запасной канал 443" "$why"
else verdict FAIL "Push на устройства: APNs недоступен (5223 и 443) — устройства не получат MDM-команды" "$why"; count FAIL; fi
