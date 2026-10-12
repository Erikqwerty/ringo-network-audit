# shellcheck shell=bash
# Итог удержания websocket: дожидается фонового lib/ws_hold.py и разбирает его сессии.
# Без авторизации агента socket.io сам закрывает соединение через ~45 с (connectTimeout) — это норма,
# клиент переподключается. Плохо, когда соединение рвётся раньше и не сервером: TCP закрыт без
# close-кадра, сброс (RST), данные перестали идти — это таймаут прокси, балансировщика или DPI.
# Итог: OK — разрывов по пути нет; WARN — соединение рвётся по пути, ping сервера не доходят,
#       удержать не удалось; INFO — сервер сразу закрывает неавторизованное соединение (не измерить).
[[ -n "${WS_PID:-}" ]] || return 0

while kill -0 "$WS_PID" 2>/dev/null; do
  (( SECONDS - WS_T0 > WS_HOLD + 30 )) && { kill "$WS_PID" 2>/dev/null; break; }   # клиент завис
  prog "\r\033[K   %sудержание websocket: ещё %d с…%s" "$D" "$(( WS_HOLD - (SECONDS - WS_T0) > 0 ? WS_HOLD - (SECONDS - WS_T0) : 0 ))" "$N"
  sleep 1
done
clear_line
WS_PID=""

# сессии: «end N причина секунд ping», ошибка пространства «/» — «ns N error текст»
ws_n=0; ws_bad=0; ws_bad_txt=""; ws_lifes=""; ws_auth=0; ws_short_auth=0; ws_nopings=0; ws_fail=0; ws_iv=25
while read -r ev n a b c; do
  case "$ev" in
    open) ws_iv="${b:-25}" ;;
    ns)   [[ "$a" == error ]] && ws_auth=1 ;;
    end)
      ((ws_n++))
      case "$a" in
        done) ;;
        fail:*) ((ws_fail++)); ws_bad_txt="${ws_bad_txt:-не подключились (${a#fail:})}" ;;
        close:*|disconnect)
          # сервер закрыл: после отказа в авторизации это ожидаемо, если прожило до connectTimeout
          if (( b < 40 )); then
            if (( ws_auth && b <= 5 )); then ((ws_short_auth++))
            else ((ws_bad++)); ws_lifes="$ws_lifes $b"; ws_bad_txt="${ws_bad_txt:-закрыто через $b с (${a})}"; fi
          fi ;;
        eof)    ((ws_bad++)); ws_lifes="$ws_lifes $b"; ws_bad_txt="${ws_bad_txt:-TCP закрыт без close-кадра через $b с}" ;;
        rst)    ((ws_bad++)); ws_lifes="$ws_lifes $b"; ws_bad_txt="${ws_bad_txt:-сброс (RST) через $b с}" ;;
        silent) ((ws_bad++)); ws_lifes="$ws_lifes $b"; ws_bad_txt="${ws_bad_txt:-данные перестали идти через $b с}" ;;
      esac
      # прожило дольше интервала ping, а ни одного ping не прошло — прокси буферизует поток
      [[ "$a" != fail:* ]] && (( b > ws_iv + 10 && c == 0 )) && ((ws_nopings++)) ;;
  esac
done <"$WS_LOG"

det_new "socket.io: удержание соединения"
det_kv "Как проверяется" "websocket агента держится $WS_HOLD с: клиент отвечает на ping сервера, подключается к «/», после разрыва переподключается"
det_cmdline "python3 modules/ringo/lib/ws_hold.py $HN $SRV_IP $SRV_PORT auto $WS_HOLD"
det_kv "Сессий" "$ws_n"
det_sec "События"; det_file "$WS_LOG" 4000
det_text "Без авторизации агента socket.io закрывает соединение сам примерно через 45 с — это норма." \
         "Разрыв раньше и без close-кадра от сервера (eof, rst, silent) — таймаут прокси, балансировщика или DPI."
ws_min=$(tr ' ' '\n' <<<"$ws_lifes" | grep . | sort -n | head -1)
if (( ws_n == 0 )); then
  printf "   %s удержание websocket не получилось — клиент не запустился\n" "$(badge WARN)"; count WARN "удержание websocket не проверено"
elif (( ws_fail == ws_n )); then
  printf "   %s websocket не открылся ни разу: %s%s\n" "$(badge WARN)" "$ws_bad_txt" "$N"; count WARN "удержание websocket: соединение не открылось"
elif (( ws_bad )); then
  printf "   %s websocket рвётся по пути: %s; разрывов %d из %d сессий%s\n" "$(badge WARN)" "$ws_bad_txt" "$ws_bad" "$ws_n" "$N"
  count WARN "websocket агента рвётся через ${ws_min:-?} с — таймаут прокси или балансировщика"
  printf "          %s↳ агент будет «то онлайн, то оффлайн»; на nginx: proxy_read_timeout и proxy_send_timeout больше 60 с%s\n" "$D" "$N"
elif (( ws_short_auth == ws_n )); then
  printf "   %s сервер сразу закрывает неавторизованное соединение — удержание без токена агента не измерить\n" "$(badge INFO)"; count INFO
elif (( ws_nopings )); then
  printf "   %s websocket держится, но ping сервера не доходят до клиента — прокси буферизует поток%s\n" "$(badge WARN)" "$N"
  count WARN "ping socket.io не доходят — прокси буферизует websocket"
else
  printf "   %s websocket держится %d с без разрывов по пути %s(сессий: %d%s)%s\n" "$(badge OK)" "$WS_HOLD" "$D" "$ws_n" \
    "$( ((ws_auth)) && echo '; сервер закрывает неавторизованное соединение через ~45 с — норма')" "$N"; count OK
fi
det_ref
