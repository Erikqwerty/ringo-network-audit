# shellcheck shell=bash
# Прокси пропускает Upgrade: websocket (нужны HTTP/1.1 и заголовки Upgrade/Connection до бэкенда).
# Итог: OK — 101 Switching Protocols; FAIL — любой другой код.

prog "   %s…%s" "$D" "$N"
wscode=$(curl -s -k -m 5 --http1.1 -o /dev/null -w '%{http_code}' \
  -H "Connection: Upgrade" -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  "$HOST/socket.io/?EIO=${EIO:-4}&transport=websocket" 2>/dev/null)
det_new "socket.io: websocket upgrade"
det_kv "Что проверяется" "прокси пропускает Upgrade: websocket (нужны HTTP/1.1 и заголовки Upgrade/Connection до бэкенда)"
det_cmd curl -sk -m 5 --http1.1 -o /dev/null -w '%{http_code}' -H "Connection: Upgrade" -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" "$HOST/socket.io/?EIO=${EIO:-4}&transport=websocket"
det_kv "Код ответа" "${wscode:-000}$([[ "$wscode" == 101 ]] && echo " — Switching Protocols, соединение переключено")"
clear_line
if [[ "$wscode" == "101" ]]; then
  printf "   %s websocket upgrade %s(101 Switching Protocols)%s\n" "$(badge OK)" "$D" "$N"; count OK
else
  printf "   %s websocket upgrade не прошёл %s(код %s; проверьте Upgrade/Connection и HTTP/1.1 на прокси)%s\n" "$(badge FAIL)" "$D" "${wscode:-000}" "$N"; count FAIL "socket.io: websocket upgrade не прошёл"
fi
det_ref
