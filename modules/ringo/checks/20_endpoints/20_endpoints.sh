# shellcheck shell=bash
# Каждый эндпоинт Ringo доходит через прокси до приложения. Запрос — как у настоящего клиента, с пустым телом:
# ответ приложения (JSON NestJS) на него — норма. Вердикт зависит от того, публичный ли путь (см. endpoint_verdict).
# Итог по строке: OK / INFO / WARN / FAIL с причиной; медленный первый байт (> SLOW_MS дважды) — WARN.
# Задаёт: ROWS (для --compare), N_PROBED/N_503, SEEN_HAPROXY/SEEN_NGINX (для раздела «Веб-сервер»).

# вердикт по ответу последней пробы: читает method path public code size stub msg missing, задаёт status и verdict
endpoint_verdict() {
  if (( missing )); then
    # NestJS «Cannot PUT …»: запрос дошёл до приложения, но такого маршрута в нём нет
    status="WARN"
    if [[ -n "$API_OPS" ]]; then verdict="маршрут есть в схеме ($API_SRC), но приложение его не знает — запрос ушёл не в тот бэкенд?"
    else verdict="маршрута нет в приложении — другая версия Ringo?"; fi
  elif [[ "$path" == /api/v1/documentation-json ]]; then
    if [[ "$code" == "200" ]] && head -c 200 "$TMP" | grep -q '"openapi"\|"swagger"'; then
      [[ "$INTERNAL" == "1" ]] && status="INFO" || status="WARN"
      verdict="Swagger JSON отдаётся без авторизации — полная карта API"
    elif [[ "$code" =~ ^(401|403|404|444)$ ]]; then verdict="Swagger JSON закрыт ($code)"
    else status="INFO"; verdict="ответ $code"; fi
  elif [[ "$path" == *operation=GetCACaps ]]; then
    caps=$(LC_ALL=C tr -d '\0\r' <"$TMP" | tr '\n' ' ' | head -c 80)
    if [[ "$code" == "200" && "$caps" == *PKIOperation* ]]; then verdict="SCEP отвечает: $caps"
    elif [[ "$code" == "000" ]]; then status="FAIL"; verdict="$(net_hint $(stub_rc "$stub")) (2 попытки)"
    elif [[ "$path" == /scep-proxy* && "$stub" == app ]] && grep -Eqi 'не включ|not enabled|disabled|выключ' <<<"$msg"; then
      status="INFO"; verdict="SCEP Proxy выключен в настройках Ringo — проверка неприменима"; msg=""
    elif [[ "$stub" == app ]]; then status="FAIL"; verdict="приложение отвечает $code без списка возможностей SCEP"
    else status="FAIL"; verdict="ответ $code без списка возможностей SCEP — прокси или SCEP не работает"; fi
  elif [[ "$public" == "1" || "$INTERNAL" == "1" ]]; then
    case "$code" in
      000) status="FAIL"; verdict="$(net_hint $(stub_rc "$stub")) (2 попытки)" ;;
      502|503|504)
        status="FAIL"
        if [[ "$stub" == haproxy* ]]; then verdict="прокси не нашёл живой бэкенд (заглушка HAProxy)"
        else verdict="ошибка прокси/бэкенда"; fi ;;
      403)
        if [[ "$public" == "1" && "$stub" == "waf-block" ]]; then status="WARN"; verdict="заблокировано WAF (страница блокировки)"
        elif [[ "$stub" == "app" ]]; then verdict="ответ приложения Ringo (запрещено)"
        elif [[ "$public" == "1" ]]; then status="WARN"; verdict="403 на публичном пути — вероятно, ACL на прокси"
        elif [[ "$stub" == "nginx" ]]; then
          # режим «изнутри»: веб-интерфейс должен открываться, а его закрыл nginx — нас нет в allow-списке
          status="WARN"; verdict="закрыт на nginx и из этой подсети — IP ${MY_IP:-?} не в allow-списке?"
          [[ "$MY_IP" == */* ]] && verdict="закрыт на nginx и из этой подсети — выход VPN меняется (${MY_IP}), allow-список по IP не сработает"
        else status="WARN"; verdict="403 не от приложения — доступ из этой подсети закрыт на прокси"; fi ;;
      401) verdict="ответ приложения (нужна авторизация)" ;;
      200|204|301|302|307|308)
        if [[ "$stub" == "spa-html" ]]; then status="INFO"; verdict="GET отдаёт HTML веб-интерфейса (SPA), а не API"
        else verdict="доступен"; fi ;;
      400|404|405|415|422)
        if [[ "$stub" == "app" ]]; then verdict="ответ приложения Ringo ($code на пустой запрос — норма)"
        elif [[ "$stub" == "nginx" ]]; then status="WARN"; verdict="$code от nginx — запрос не дошёл до Ringo"
        elif [[ "$code" == "404" ]] && same_as_nf "$code" "$size"; then status="WARN"; verdict="404 как на несуществующем пути — проверьте маршрут на прокси"
        elif [[ "$code" =~ ^(404|405)$ && "$method" != "GET" ]]; then status="WARN"; verdict="$code — маршрут или метод $method не принимается"
        else verdict="дошёл до бэкенда ($code)"; fi ;;
      *) status="WARN"; verdict="неожиданный код" ;;
    esac
  else
    # не входит в список обязательных публичных; ограничение подсетью — рекомендация.
    # 401 — это ответ приложения (запрос прошёл прокси), а не закрытие на прокси
    case "$code" in
      403|444) verdict="закрыт снаружи (рекомендация соблюдена)" ;;
      000)
        # закрытие по пути делает прокси (403/444); таймаут на L7-пути — сбой сети, а не ACL
        if [[ "$stub" == curl-rc52* ]]; then verdict="закрыт снаружи (соединение закрыто без ответа — nginx 444?)"
        else status="INFO"; verdict="не определить: $(net_hint $(stub_rc "$stub")) (2 попытки)"; fi ;;
      503) if [[ "$stub" == haproxy* ]]; then verdict="закрыт снаружи (заглушка HAProxy)"
           else status="INFO"; verdict="503 — закрыт или бэкенд недоступен"; fi ;;
      404)
        if [[ "$stub" == "app" ]]; then status="WARN"; verdict="открыт снаружи: 404 от приложения"
        elif [[ "$stub" == "nginx" ]] || same_as_nf "$code" "$size"; then verdict="закрыт снаружи (404 прокси)"
        else status="INFO"; verdict="404 — не ясно, ответ прокси или приложения"; fi ;;
      401) status="WARN"; verdict="открыт снаружи: API отвечает 401 (запрос дошёл до приложения)" ;;
      200|204|301|302|307|308) status="INFO"; verdict="открыт снаружи" ;;
      502|504) status="WARN"; verdict="ошибка прокси/бэкенда" ;;
      *) status="INFO"; verdict="ответ $code" ;;
    esac
  fi
}

ROWS=()   # «МЕТОД путь|код|размер» — для сравнения с прошлым аудитом
N_PROBED=0; N_503=0   # сколько эндпоинтов отправлено и сколько ответили 503 — для общего диагноза
SLOW_MS=1000
CUR_GROUP=""
N_TOTAL=${#ENDPOINTS[@]}; i=0
for row in "${ENDPOINTS[@]}"; do
  IFS='|' read -r method path ctype group public note <<<"$row"
  ((i++))
  if [[ "$group" != "$CUR_GROUP" ]]; then
    echo " ${BD}${B}▸ $group${N}"
    CUR_GROUP="$group"
  fi
  op="$method ${path%%\?*}"

  # в схеме API этой версии маршрута нет — проверять нечего (например, /agent/checkin в Ringo 2.x)
  if [[ -n "$API_OPS" ]] && api_known "$op" && ! api_has "$op"; then
    printf "   %s %-4s %-28s %s—%s  %sнет в API Ringo %s (схема: %s) — не проверяется%s\n" \
      "$(badge INFO)" "$method" "$path" "$BD" "$N" "$D" "${RINGO_VER:-${RINGO_FAM:-?}.x}" "$API_SRC" "$N"
    det_new "$method $path"; det_sec "Почему не проверялось"
    det_kv "Версия Ringo" "${RINGO_VER:-${RINGO_FAM:-?}.x} ($VER_HOW)"; det_kv "Схема API" "$API_SRC"
    det_text "Операции «${op}» в этой схеме нет — запрос не отправлялся."
    det_ref
    count INFO; ROWS+=("$op|—|—"); continue
  fi

  prog "   %s(%d/%d)%s %-4s %-28s %s…%s" "$D" "$i" "$N_TOTAL" "$N" "$method" "$path" "$D" "$N"
  # нет ответа — повторяем один раз: отличаем нестабильный канал (ТСПУ / VPN) от стабильного отказа
  probe_retry "$path" "$method" "$ctype"
  code="$CODE"; size="$SIZE"; ms="$MS"; stub="$STUB"; first="$FIRST"; tf=$(ttfb)
  msg=""; [[ "$stub" == app ]] && msg="$(app_msg)"
  missing=0; [[ "$stub" == app ]] && route_missing && missing=1
  save_resp "$method $path" "$code"
  det_new "$method $path — $note"; det_probe
  [[ "$method" != "GET" ]] && cp "$TMP" "$FPD/post$i.b" 2>/dev/null   # для поиска страниц блокировки WAF
  clear_line

  status="OK"; verdict=""; label="$method $path"
  [[ "$group" == "SCEP Proxy" ]] && label="$label (опционально)"
  endpoint_verdict
  if [[ -n "$first" ]]; then
    ((FLAKY_CNT++))
    [[ "$status" == "FAIL" ]] || status="WARN"
    verdict="$verdict; 1-я попытка: $(net_hint $(stub_rc "$first"))"
  fi
  det_probe_verdict "$stub" "$tf" "$ms"
  # медленный ответ: по времени до первого байта (большой /agent/bundle сам по себе грузится долго).
  # Один повтор — чтобы не путать разовую задержку (холодный кэш, переподключение) с постоянной.
  slow=""
  if [[ "$code" != 000 ]] && (( tf > SLOW_MS )); then
    read -r _ _ _ _ <<<"$(probe "$path" "$method" "$ctype")"; tf2=$(ttfb)
    if (( tf2 > SLOW_MS )); then
      slow="первый байт через $tf и $tf2 мс (порог $SLOW_MS)"; det_kv "Медленный ответ" "$slow"
      [[ "$status" == OK || "$status" == INFO ]] && status="WARN"
    else slow="1-й ответ медленный ($tf мс), повтор — $tf2 мс"; det_kv "Повтор" "$slow"; fi
  fi
  count "$status" "$label${verdict:+ — $verdict}"
  [[ "$stub" == haproxy* ]] && SEEN_HAPROXY=1
  [[ "$stub" == "nginx" ]] && SEEN_NGINX=1
  ROWS+=("$op|$code|$size")
  ((N_PROBED++)); [[ "$code" == 503 ]] && ((N_503++))

  printf "   %s %-4s %-28s %s%3s%s  %s%6sB %4sms%s  %s%s%s\n" \
    "$(badge "$status")" "$method" "$path" "$BD" "$code" "$N" "$D" "$size" "$ms" "$N" "$D" "$verdict" "$N"
  det_ref
  [[ -n "$slow" ]] && printf "          %s↳ %s%s\n" "$D" "$slow" "$N"
  [[ -n "$msg" && "$status" != OK ]] && printf "          %s↳ ответ приложения: %s%s\n" "$D" "$msg" "$N"
  [[ "$stub" =~ ^(haproxy|waf-block|nginx) ]] && printf "          %s↳ сигнатура ответа: %s%s\n" "$D" "$stub" "$N"
  if [[ "$stub" == "waf-block" ]]; then
    sid=$(grep -Eoi 'support id: *[0-9a-z-]+' "$TMP" 2>/dev/null | head -1)
    printf "          %s↳ %sпустое тело могло сработать как аномалия; сверьте по логам WAF и добавьте исключение для пути%s\n" "$D" "${sid:+$sid; }" "$N"
  fi
done
