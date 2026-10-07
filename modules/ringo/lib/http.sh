# shellcheck shell=bash
# HTTP-пробы: probe/probe_retry, разбор ответа приложения, сохранение ответов.
# Подключается через source из modules/ringo/run.sh; сам не запускается.

# ---------- запрос: "<code> <size> <ms> <сигнатура>", тело ответа — в $TMP ----------
PROBE_HDR=()   # доп. заголовки для следующего probe (например, User-Agent)
probe() { # путь [метод] [content-type] [файл тела]
  local path="$1" m="${2:-GET}" ct="${3:-}" body="${4:-/dev/null}" out rc code size t tc ta stage stub="-" args=()
  [[ "$m" != "GET" ]] && args=(-X "$m" -H "Content-Type: ${ct:-application/octet-stream}" --data-binary "@$body")
  (( ${#PROBE_HDR[@]} )) && args+=("${PROBE_HDR[@]}")
  : >"$TMP"
  # команда для подробностей отчёта — в виде, который можно повторить руками
  printf '%s\n' "$m" ${args[@]+"${args[@]}"} >"$TMP.args"; printf '%s\n' "$HOST$path" >>"$TMP.args"
  out=$(curl -s -v -k -m 10 ${args[@]+"${args[@]}"} -o "$TMP" -w '%{http_code} %{size_download} %{time_total} %{time_connect} %{time_appconnect} %{time_starttransfer}' "$HOST$path" 2>"$TMP.v"); rc=$?
  read -r code size t tc ta tf <<<"${out:-000 0 0 0 0 0}"
  # время до первого байта — отдельно от загрузки (probe работает в подоболочке, поэтому через файл)
  awk -v x="${tf:-0}" 'BEGIN{printf "%d", x*1000}' >"$TMP.t"
  if [[ "$code" == "000" ]]; then
    # при таймауте curl обнуляет time_connect, поэтому этап берём из -v: «Connected to» — TCP есть,
    # «Server hello» / сертификат — TLS прошёл
    stage=tcp
    grep -q '^\* Connected to' "$TMP.v" 2>/dev/null && stage=tls
    { grep -qiE 'Server hello|Server certificate|SSL connection using' "$TMP.v" 2>/dev/null \
      || awk -v x="$ta" 'BEGIN{exit !(x>0)}'; } && stage=http
    stub="curl-rc$rc:$stage"
  elif [[ "$m" == "GET" && "$code" == "200" && "$path" =~ ^/(mdm/|api/|agent/manifest) ]] && head -c 200 "$TMP" | grep -qi '<!doctype html\|<html'; then
    stub="spa-html"
  elif [[ "$code" == "503" ]] && grep -qi "No server is available" "$TMP" 2>/dev/null; then
    stub="haproxy-503"
  elif [[ "$code" == "503" && "$size" == "107" ]]; then
    stub="haproxy-503?"
  elif [[ "$code" =~ ^(403|406|429|451|501|999)$ ]] && grep -Eqi "$BLOCK_RE" "$TMP" 2>/dev/null; then
    stub="waf-block"
  elif [[ "$code" != "200" ]] && grep -q '"statusCode"' "$TMP" 2>/dev/null; then
    stub="app"   # JSON-ошибка NestJS — ответ самого приложения Ringo
  elif grep -qi "<center>nginx" "$TMP" 2>/dev/null; then
    stub="nginx"
  fi
  printf '%s %s %s %s' "$code" "$size" "$(awk -v t="$t" 'BEGIN{printf "%d", t*1000}')" "$stub"
}
# текст ошибки из JSON NestJS ({"message":"…"} или {"message":["…"]}) последнего ответа
app_msg() {
  LC_ALL=C tr -d '\0' <"$TMP" 2>/dev/null | head -c 4000 \
    | sed -nE 's/.*"message" *: *\[? *"(([^"\\]|\\.)*)".*/\1/p' | head -1 | cut -c1-140
}
# «Cannot PUT /agent/checkin» — у NestJS это «маршрута нет», а не ответ обработчика
route_missing() { [[ "$(app_msg)" =~ ^Cannot\ (GET|PUT|POST|PATCH|DELETE)\  ]]; }
ttfb() { cat "$TMP.t" 2>/dev/null || echo 0; }

# сохранение последнего ответа в папку аудита (--out): заголовки из curl -v и тело (до 64 КБ)
RESP_N=0
save_resp() { # метка (метод путь), код
  [[ -n "$RESP_DIR" ]] || return 0
  local f; ((RESP_N++))
  f="$RESP_DIR/$(printf '%02d' "$RESP_N")_$(printf '%s' "$1" | LC_ALL=C tr -c 'A-Za-z0-9._-' '_' | cut -c1-60).txt"
  {
    printf '# %s → %s\n' "$1" "$2"
    sed -nE 's/^< //p' "$TMP.v" 2>/dev/null | tr -d '\r'
    echo
    if (( $(wc -c <"$TMP" 2>/dev/null || echo 0) > 65536 )); then
      printf '[тело %s байт — не сохранено]\n' "$(wc -c <"$TMP" | tr -d ' ')"
    else cat "$TMP" 2>/dev/null; fi
  } >"$f"
}

# что обозначает сигнатура ответа — для подробностей
stub_desc() {
  case "$1" in
    app)          echo "JSON-ошибка NestJS — ответило само приложение Ringo" ;;
    nginx)        echo "стандартная страница ошибки nginx — ответил прокси, не приложение" ;;
    waf-block)    echo "страница блокировки WAF" ;;
    spa-html)     echo "HTML веб-интерфейса (SPA) вместо ответа API" ;;
    haproxy-503*) echo "заглушка HAProxy: нет живого бэкенда" ;;
    curl-rc*)     echo "ответа нет: $(net_hint $(stub_rc "$1"))" ;;
    -)            echo "обычный ответ — признаков ошибки прокси, WAF или приложения нет" ;;
    *)            echo "не опознана" ;;
  esac
}
# подробности последней пробы: запрос, ответ, тело, разбор (вызывать до следующей пробы)
det_probe() { # [подпись раздела запроса] [файл отправленного тела]
  [[ -n "$DET" ]] || return 0
  local m url args=() i=0 l code tf
  while IFS= read -r l; do args+=("$l"); done <"$TMP.args"
  m="${args[0]}"; url="${args[${#args[@]}-1]}"
  det_sec "${1:-Запрос}"
  if (( ${#args[@]} > 2 )); then det_cmd curl -sk -m 10 "${args[@]:1:${#args[@]}-2}" "$url"
  else det_cmd curl -sk -m 10 "$url"; fi
  sed -nE 's/^> //p' "$TMP.v" 2>/dev/null | LC_ALL=C tr -d '\r' | grep . >>"$DET"
  if [[ -n "${2:-}" && -f "$2" ]]; then det_sec "Отправленное тело"; det_file "$2" 3000; fi
  code=$(sed -nE 's/^< HTTP\/[0-9.]+ ([0-9]{3}).*/\1/p' "$TMP.v" 2>/dev/null | tail -1)
  det_sec "Ответ"
  if [[ -z "$code" ]]; then
    det_kv "Результат" "ответа нет"
    det_text "Ход соединения (curl -v):"
    grep -E '^\* ' "$TMP.v" 2>/dev/null | LC_ALL=C tr -d '\r' | grep -viE 'ALPN|^\* +(Trying|CAfile|CApath)' | head -25 >>"$DET"
  else
    sed -nE 's/^< //p' "$TMP.v" 2>/dev/null | LC_ALL=C tr -d '\r' | grep . >>"$DET"
    det_sec "Тело ответа"; det_file "$TMP" 5000
  fi
  return 0
}
det_probe_verdict() { # сигнатура [первый байт мс] [всего мс]
  [[ -n "$DET" ]] || return 0
  det_sec "Разбор"
  det_kv "Сигнатура ответа" "$1 — $(stub_desc "$1")"
  [[ -n "${2:-}" ]] && det_kv "Время" "первый байт ${2} мс, всего ${3:-?} мс"
  [[ "$1" == app && -n "$(app_msg)" ]] && det_kv "Сообщение приложения" "$(app_msg)"
  [[ "$1" == app ]] && det_resp_meaning
  return 0
}

# ожидаем ли ответ приложения: по таблице известных ответов и по описанию кода в схеме (вызывать до следующей пробы)
det_resp_meaning() {
  [[ -n "$DET" ]] || return 0
  local m url path code e
  m=$(head -1 "$TMP.args" 2>/dev/null); url=$(tail -1 "$TMP.args" 2>/dev/null)
  path="${url#"$HOST"}"; path="${path%%\?*}"
  code=$(sed -nE 's/^< HTTP\/[0-9.]+ ([0-9]{3}).*/\1/p' "$TMP.v" 2>/dev/null | tail -1)
  e="$(resp_explain "$m $path" "$code" "$(app_msg)")"
  if [[ -n "$e" ]]; then det_kv "Что значит ответ" "$e"
  else det_kv "Что значит ответ" "код $code для $m $path не описан ни в схеме API, ни в schemas/known_responses.tsv"; fi
  return 0
}

# probe с одним повтором при отсутствии ответа: CODE SIZE MS STUB, FIRST — сигнатура неудачной 1-й попытки
probe_retry() {
  FIRST=""
  read -r CODE SIZE MS STUB <<<"$(probe "$@")"
  if [[ "$CODE" == "000" ]]; then
    FIRST="$STUB"
    read -r CODE SIZE MS STUB <<<"$(probe "$@")"
    [[ "$CODE" == "000" ]] && FIRST=""
  fi
}
