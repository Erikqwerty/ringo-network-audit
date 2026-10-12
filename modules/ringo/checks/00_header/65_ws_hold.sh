# shellcheck shell=bash
# Удержание websocket (--ws-hold N): агент держит соединение постоянно, а прокси или балансировщик
# может рвать его по таймауту — тогда агент «то онлайн, то оффлайн». Клиент lib/ws_hold.py держит
# websocket N секунд в фоне, параллельно со всеми проверками; итог — в разделе 75_ws_hold.
# Задаёт: WS_PID — фоновый процесс, WS_LOG — его события, WS_T0 — когда запущен.
WS_PID=""
(( WS_HOLD > 0 )) && [[ "$HOST" == https://* && -n "${SRV_IP:-}" ]] || return 0

WS_PY="$(safe_python)"; WS_LOG="$FPD/ws_hold.txt"; WS_T0=$SECONDS
if [[ -z "$WS_PY" ]]; then
  printf " Websocket: %sудержание не проверяется — нужен python3%s\n" "$D" "$N"
  return 0
fi
"$WS_PY" "$MOD_DIR/lib/ws_hold.py" "$HN" "$SRV_IP" "$SRV_PORT" auto "$WS_HOLD" >"$WS_LOG" 2>&1 &
WS_PID=$!
printf " Websocket: удержание %d с в фоне %s(итог — в конце проверки)%s\n" "$WS_HOLD" "$D" "$N"
