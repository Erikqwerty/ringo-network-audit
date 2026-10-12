# shellcheck shell=bash
# Раздел: итог удержания websocket агента (запущено в 00_header/65_ws_hold.sh).
[[ -n "${WS_PID:-}" ]] || return 0

echo
echo " ${BD}${B}▸ socket.io: удержание соединения (${WS_HOLD} с)${N}"
