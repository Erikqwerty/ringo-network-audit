# shellcheck shell=bash
# Проверка: socket.io (websocket агента). Выполняется по порядку из modules/ringo/run.sh (source, общие переменные).

# ---------- socket.io ----------
echo
echo " ${BD}${B}▸ socket.io (websocket-соединение агента)${N}"
prog "   %s…%s" "$D" "$N"
# EIO=4 (socket.io v3+) отвечает «0{...}», EIO=3 (v2) — «<длина>:0{...}»
EIO=""
det_new "socket.io: polling-handshake"
det_kv "Что проверяется" "агент Ringo открывает сессию socket.io через прокси; ответ «0{…sid…}» — сессия выдана"
for e in 4 3; do
  sio=$(curl -s -k -m 10 "$HOST/socket.io/?EIO=$e&transport=polling" 2>/dev/null | head -c 80 | tr -d '\r\n')
  det_sec "Попытка EIO=$e"; det_cmd curl -sk -m 10 "$HOST/socket.io/?EIO=$e&transport=polling"; det_text "${sio:-(пустой ответ)}"
  if [[ "$sio" =~ ^([0-9]+:)?0\{ ]]; then EIO=$e; break; fi
done
clear_line
if [[ -n "$EIO" ]]; then
  printf "   %s polling-handshake EIO=%s %s(%s…)%s\n" "$(badge OK)" "$EIO" "$D" "${sio:0:40}" "$N"; count OK
else
  printf "   %s polling-handshake не прошёл %s(ответ: %s)%s\n" "$(badge FAIL)" "$D" "${sio:0:50}" "$N"; count FAIL "socket.io: polling-handshake не прошёл"
fi
det_ref

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
