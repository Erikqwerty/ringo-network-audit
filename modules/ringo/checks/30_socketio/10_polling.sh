# shellcheck shell=bash
# Агент открывает сессию socket.io через прокси (polling-handshake). Пробуем EIO=4 (socket.io v3+), затем EIO=3.
# Итог: OK — сессия выдана; FAIL — нет. Задаёт EIO для проверки websocket.

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
