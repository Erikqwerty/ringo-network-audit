# shellcheck shell=bash
# Проверка: реальные тела запросов устройств. Выполняется по порядку из modules/ringo/run.sh (source, общие переменные).

# ---------- реальные тела запросов устройств через WAF ----------
# На настоящих телах WAF чаще всего даёт ложные срабатывания: plist (DOCTYPE, XML), бинарный PKCS7,
# JSON агента. Значения заведомо невалидные — приложение отвечает 4xx и ничего не создаёт.
cat >"$FPD/body_checkin.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>MessageType</key>
	<string>RingoAuditProbe</string>
	<key>UDID</key>
	<string>00000000-0000000000AUDIT</string>
</dict>
</plist>
PLIST
sed 's/MessageType/Status/' "$FPD/body_checkin.plist" >"$FPD/body_connect.plist"
printf '{"request_type":"RingoAuditProbe","device_udid":"00000000-AUDIT"}' >"$FPD/body_agent.json"
{ printf '\x30\x82\x01\x00\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02'; head -c 241 /dev/urandom; } >"$FPD/body_pkcs7.der"
# варианты для поиска причины блокировки
grep -v '^<!DOCTYPE' "$FPD/body_checkin.plist" >"$FPD/body_checkin_nodtd.plist"
grep -v '^<!DOCTYPE' "$FPD/body_connect.plist" >"$FPD/body_connect_nodtd.plist"

# заблокирован ли ответ последней пробы до приложения
body_blocked() { # код сигнатура
  [[ "$2" != app ]] && [[ "$2" == waf-block || "$1" =~ ^(000|403|406|418|429|451|501|999)$ ]]
}
# итог одной контрольной пробы человеческими словами (вызывать сразу после пробы — читает $TMP)
ctl_desc() { # код сигнатура
  if [[ "$2" == app ]]; then
    local m; m="$(app_msg)"
    echo "дошёл до Ringo ($1${m:+: «${m}»})"
  else
    echo "заблокирован: $(blocker_of "$2") ($1)"
  fi
}
# контрольные пробы: что именно в запросе вызывает блок -> BODY_CTRL (ход проверки), BODY_WHY (вывод),
# BODY_SURE=1 — блок наверняка ломает настоящие устройства (по пути или по DOCTYPE, который они шлют всегда)
body_controls() { # метод путь content-type файл
  local m="$1" p="$2" ct="$3" f="$4" c st r="" why=""
  BODY_SURE=0
  read -r c _ _ st <<<"$(probe "$p" "$m" "$ct")"
  det_probe "Контроль 1: тот же запрос с пустым телом"; [[ "$st" == app ]] && det_resp_meaning
  r="пустое тело — $(ctl_desc "$c" "$st")"
  if body_blocked "$c" "$st"; then
    why="блок по пути или методу — содержимое ни при чём (правило location / ACL)"; BODY_SURE=1
  else
    read -r c _ _ st <<<"$(probe "$p" "$m" application/octet-stream "$f")"
    det_probe "Контроль 2: то же тело с Content-Type application/octet-stream"; [[ "$st" == app ]] && det_resp_meaning
    r="$r; Content-Type octet-stream — $(ctl_desc "$c" "$st")"
    if ! body_blocked "$c" "$st"; then why="блок по Content-Type «${ct}» (у ModSecurity типично CRS 920420 — тип не в allowed_request_content_type)"; BODY_SURE=1
    elif [[ "$f" == *.plist ]]; then
      read -r c _ _ st <<<"$(probe "$p" "$m" "$ct" "${f%.plist}_nodtd.plist")"
      det_probe "Контроль 3: plist без строки DOCTYPE" "${f%.plist}_nodtd.plist"; [[ "$st" == app ]] && det_resp_meaning
      r="$r; без DOCTYPE — $(ctl_desc "$c" "$st")"
      if ! body_blocked "$c" "$st"; then
        why="блок по DOCTYPE в plist (правила XXE / внешних сущностей). Настоящие устройства Apple шлют plist с DOCTYPE всегда — их запросы будут блокироваться"
        BODY_SURE=1
        # тот же DOCTYPE на соседнем пути: проходит — правило привязано к этому пути
        if [[ "$p" != /mdm/connect ]]; then
          read -r c _ _ st <<<"$(probe /mdm/connect PUT application/x-apple-aspen-mdm "$FPD/body_connect.plist")"
          det_probe "Контроль 4: plist с тем же DOCTYPE на PUT /mdm/connect" "$FPD/body_connect.plist"; [[ "$st" == app ]] && det_resp_meaning
          r="$r; тот же DOCTYPE на /mdm/connect — $(ctl_desc "$c" "$st")"
          body_blocked "$c" "$st" || why="$why; на /mdm/connect тот же DOCTYPE проходит — правило привязано к $p"
        fi
      else why="блок по содержимому тела (ключи/значения plist) — нужен id правила из лога"; fi
    else why="блок по содержимому тела — нужен id правила из лога"; fi
  fi
  BODY_CTRL="$r"; BODY_WHY="$why"
  det_sec "Вывод по контрольным пробам"
  det_text "Ответ приложения Ringo (JSON с statusCode) — значит, запрос прошёл прокси и WAF. 4xx от приложения" \
           "на тестовые данные — норма: например, 403 «Отсутствует устройство с udid …» для несуществующего UDID."
  det_kv "Ход проверки" "$r"; det_kv "Вывод" "$why"
}

echo
echo " ${BD}${B}▸ Реальные тела запросов устройств (ложные срабатывания WAF)${N}"
BODY_CASES=(
  "PUT|/mdm/checkin|application/x-apple-aspen-mdm-checkin|body_checkin.plist|check-in, plist"
  "PUT|/mdm/connect|application/x-apple-aspen-mdm|body_connect.plist|connect, plist"
  "PUT|/agent/checkin|application/json|body_agent.json|check-in агента, JSON"
  "POST|/mdm/enroll/profile|application/pkcs7-signature|body_pkcs7.der|OTA-профиль, бинарный PKCS7"
)
k=0
for c in "${BODY_CASES[@]}"; do
  IFS='|' read -r bm bpath bct bfile bname <<<"$c"; ((k++))
  if [[ -n "$API_OPS" ]] && ! api_has "$bm $bpath"; then
    printf "   %s %-4s %-20s %s  —%s  %s%s — нет в API Ringo %s, не проверяется%s\n" "$(badge INFO)" "$bm" "$bpath" "$BD" "$N" "$D" "$bname" "${RINGO_VER:-${RINGO_FAM:-?}.x}" "$N"
    det_new "$bm $bpath — $bname"; det_sec "Почему не проверялось"
    det_text "Операции «$bm ${bpath}» нет в схеме API этой версии ($API_SRC) — запрос не отправлялся."; det_ref
    count INFO; ROWS+=("тело $bm $bpath|—|"); continue
  fi
  prog "   %s(%d/%d)%s %-4s %-20s %s…%s" "$D" "$k" "${#BODY_CASES[@]}" "$N" "$bm" "$bpath" "$D" "$N"
  probe_retry "$bpath" "$bm" "$bct" "$FPD/$bfile"
  cp "$TMP" "$FPD/post_body_$k.b" 2>/dev/null
  save_resp "body $bm $bpath" "$CODE"
  det_new "$bm $bpath — $bname"
  det_kv "Что проверяется" "настоящее по форме тело запроса устройства (значения заведомо невалидны) доходит до приложения, а не блокируется WAF"
  det_probe "Запрос как от устройства" "$FPD/$bfile"; det_probe_verdict "$STUB"
  bmsg=""; [[ "$STUB" == app ]] && bmsg="$(app_msg)"
  status="OK"; BODY_CTRL=""; BODY_WHY=""; BODY_SURE=0
  if [[ "$STUB" == "app" ]] && route_missing; then
    status="WARN"; verdict="тело дошло до приложения, но маршрута в нём нет («${bmsg}»)"
  elif [[ "$STUB" == "app" ]]; then
    verdict="тело дошло до приложения ($CODE от Ringo)"
  elif [[ "$STUB" == "waf-block" || ( "$CODE" =~ ^(403|406|418|429|451|501|999)$ ) ]]; then
    status="WARN"; verdict="тело блокируется до приложения: $(blocker_of "$STUB") — устройства могут не регистрироваться"
    body_controls "$bm" "$bpath" "$bct" "$FPD/$bfile"
    (( BODY_SURE )) && { status="FAIL"; verdict="тело блокируется до приложения: $(blocker_of "$STUB") — запросы устройств не дойдут до Ringo"; }
  elif [[ "$CODE" == "000" ]]; then
    # контроль: тот же путь с пустым телом
    read -r cc _ _ _ <<<"$(probe "$bpath" "$bm" "$bct")"
    det_probe "Контроль: тот же запрос с пустым телом"
    if [[ "$cc" != "000" ]]; then status="WARN"; verdict="сброс только на содержимом тела (inline WAF / IPS), пустое тело → $cc"
    else status="FAIL"; verdict="$(net_hint $(stub_rc "$STUB")) (2 попытки)"; fi
  elif [[ "$CODE" =~ ^5 ]]; then
    status="FAIL"; verdict="ошибка прокси/бэкенда ($CODE)"
  else
    status="INFO"; verdict="ответ $CODE не от приложения — проверьте вручную"
  fi
  if [[ -n "$FIRST" ]]; then ((FLAKY_CNT++)); [[ "$status" == "FAIL" ]] || status="WARN"; verdict="$verdict; ответ со 2-й попытки"; fi
  clear_line
  count "$status" "тело $bm $bpath — ${BODY_WHY:-$verdict}"
  ROWS+=("тело $bm $bpath|$CODE|")
  printf "   %s %-4s %-20s %s%3s%s  %s%s — %s%s\n" "$(badge "$status")" "$bm" "$bpath" "$BD" "$CODE" "$N" "$D" "$bname" "$verdict" "$N"
  det_ref
  if [[ -n "$BODY_WHY" ]]; then
    printf "          %s↳ контроль: %s%s\n" "$D" "$BODY_CTRL" "$N"
    printf "          %s↳ вывод: %s%s\n" "$D" "$BODY_WHY" "$N"
  fi
done
