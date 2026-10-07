#!/usr/bin/env bash
# tests/run.sh — быстрые проверки без сети: синтаксис всех скриптов и юнит-тесты функций.
# Запуск: ./tests/run.sh   (код возврата 0 — всё прошло)
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIX="$ROOT/tests/fixtures"
PASS=0; FAILS=0
ok()   { ((PASS++)); printf '  ok   %s\n' "$1"; }
bad()  { ((FAILS++)); printf '  FAIL %s\n' "$1"; }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }   # описание, условие

echo "▸ синтаксис (bash -n)"
while IFS= read -r f; do
  if bash -n "$f" 2>/dev/null; then ((PASS++)); else bad "bash -n ${f#$ROOT/}"; bash -n "$f"; fi
done < <(find "$ROOT" -name '*.sh' -not -path '*/results/*')
echo "  проверено файлов: $PASS"
# bash 3.2 склеивает байты UTF-8 с именем переменной, если «»/кириллица идут вплотную к ней → unbound variable.
bad_vars=$(find "$ROOT" -name '*.sh' -not -path '*/results/*' -exec env LC_ALL=C grep -nE '\$[A-Za-z_][A-Za-z0-9_]*[^ -~]' {} + 2>/dev/null)
if [[ -z "$bad_vars" ]]; then ok "переменные перед кириллицей — в \${…}"; else bad "переменные перед кириллицей без \${…}:"; echo "$bad_vars"; fi
if command -v shellcheck >/dev/null 2>&1; then
  echo "▸ shellcheck (ошибки)"
  find "$ROOT" -name '*.sh' -not -path '*/results/*' -print0 | xargs -0 shellcheck -S error -x && ok "shellcheck" || bad "shellcheck"
fi

echo "▸ lib/ui.sh"
(
  . "$ROOT/lib/ui.sh"
  count OK; count WARN "w1"; count FAIL "f1"; count FAIL
  [[ "$OK_CNT $WARN_CNT $FAIL_CNT ${#FAIL_LIST[@]} ${WARN_LIST[0]}" == "1 1 2 1 w1" ]]
) && ok "count: счётчики и подписи" || bad "count: счётчики и подписи"

echo "▸ lib/util.sh: числа не зависят от локали"
if locale -a 2>/dev/null | grep -qi '^ru_RU.UTF-8$'; then
  r=$(LC_ALL=ru_RU.UTF-8 bash -c '. "$1/lib/util.sh"; echo "1 14:36:23.421668" | awk "{split(\$2,a,\":\"); printf \"%.1f\", a[3]*1000}"' _ "$ROOT")
  check "ru_RU: awk читает и печатает дробные с точкой (RTT из pcap)" '[[ "$r" == 23421.7 ]]'
else
  echo "  —    локали ru_RU.UTF-8 нет в системе, проверка пропущена"
fi

echo "▸ modules/ringo/lib (без сети)"
(
  . "$ROOT/lib/util.sh"
  for f in "$ROOT"/modules/ringo/lib/*.sh; do . "$f"; done
  # схемы — урезанные фикстуры: настоящие swagger Ringo в репозиторий не кладём (копятся в schemas/ сами)
  SCHEMA_DIR="$FIX/schemas"
  TMP="$FIX/nest_route_missing.json"
  check "app_msg: message-строка" '[[ "$(app_msg)" == "Cannot PUT /agent/checkin" ]]'
  check "route_missing: «Cannot PUT» — маршрута нет" 'route_missing'
  TMP="$FIX/nest_validation.json"
  check "app_msg: message-массив" '[[ "$(app_msg)" == Request_type* ]]'
  check "route_missing: ошибка валидации — маршрут есть" '! route_missing'
  check "name_ok: точное имя и wildcard на один уровень" 'name_ok a.example.com "*.example.com" && name_ok example.com "example.com" && ! name_ok a.b.example.com "*.example.com" && ! name_ok example.com "*.example.com"'
  check "заглушки прокси распознаются" 'grep -Eqi "$PLACEHOLDER_RE" <<<"letsencrypt-nginx-proxy-companion" && grep -Eqi "$PLACEHOLDER_RE" <<<"TRAEFIK DEFAULT CERT" && ! grep -Eqi "$PLACEHOLDER_RE" <<<"mdm.example.com"'
  check "net_hint: таймаут на TLS" '[[ "$(net_hint 28 tls)" == *ServerHello* ]]'
  check "stub_rc: разбор сигнатуры" '[[ "$(stub_rc curl-rc28:tls)" == "28 tls" ]]'
  check "local_swagger: 3.x" '[[ "$(basename "$(local_swagger 3)")" == swagger_3.x.json ]]'
  check "local_swagger: 2.x" '[[ "$(basename "$(local_swagger 2)")" == swagger_2.4.4.json ]]'
  check "swagger_label" '[[ "$(swagger_label x/swagger_2.4.4.json)" == 2.4.4 ]]'
  OPS3="$(swagger_ops "$SCHEMA_DIR/swagger_3.x.json")"; OPS2="$(swagger_ops "$SCHEMA_DIR/swagger_2.4.4.json")"
  check "swagger_ops: 3.x содержит PUT /agent/checkin" 'grep -qFx "PUT /agent/checkin" <<<"$OPS3"'
  check "swagger_ops: 2.4.4 без PUT /agent/checkin" '! grep -qFx "PUT /agent/checkin" <<<"$OPS2"'
  check "swagger_ops: оба метода /scep" '[[ $(grep -c " /scep$" <<<"$OPS3") == 2 ]]'
  API_OPS="$OPS2"
  check "api_has / api_known" 'api_has "PUT /mdm/checkin" && ! api_has "PUT /agent/connect" && ! api_known "GET /api/v1/documentation-json"'
  API_RESP="$(swagger_responses "$SCHEMA_DIR/swagger_3.x.json")"
  SCHEMA_DIR="$ROOT/schemas"   # known_responses.tsv — настоящая, она в репозитории
  check "resp_explain: известный ответ (403 на check-in — устройство не найдено)" \
    '[[ "$(resp_explain "PUT /mdm/checkin" 403 "Отсутствует устройство с udid x")" == "известный ответ Ringo: устройство"* ]]'
  check "resp_explain: общее правило * 401" '[[ "$(resp_explain "GET /api/v1/x" 401 "Ошибка авторизации")" == *авторизация* ]]'
  check "resp_explain: из схемы 3.x (200 на check-in)" '[[ "$(resp_explain "PUT /mdm/checkin" 200 "")" == "описан в схеме API: MDM check-in"* ]]'
  check "resp_explain: неизвестный код — пусто" '[[ -z "$(resp_explain "PUT /mdm/checkin" 418 "")" ]]'
  # снимки схем: выбор, совпадение, сохранение новой (во временной папке)
  SCHEMA_DIR="$(mktemp -d)"; cp "$FIX"/schemas/*.json "$SCHEMA_DIR/"
  cp "$FIX/schemas/swagger_2.4.4.json" "$SCHEMA_DIR/swagger_2.x_20260101_deadbeef.json"
  check "local_swagger: точная версия важнее авто-снимка" '[[ "$(basename "$(local_swagger 2)")" == swagger_2.4.4.json ]]'
  check "schema_match: точная версия важнее авто-снимка" '[[ "$(basename "$(schema_match <<<"$OPS2")")" == swagger_2.4.4.json ]]'
  check "schema_match: новой схемы среди снимков нет" '[[ -z "$(schema_match <<<"$OPS3"$'"'"'\nGET /new/route'"'"')" ]]'
  SAVE_SCHEMA=1; HN=mdm.example.com; RINGO_FAM=3; RINGO_VER=""
  save_schema "$FIX/schemas/swagger_3.x.json"
  check "save_schema: без версии — swagger_3.x_<дата>_<хеш>.json" '[[ "$(basename "$SCHEMA_SAVED")" =~ ^swagger_3\.x_[0-9]{8}_[0-9a-f]{8}\.json$ ]]'
  RINGO_VER=3.2.0; save_schema "$FIX/schemas/swagger_3.x.json"
  check "save_schema: с версией — swagger_3.2.0.json, и она главная в семействе" '[[ "$(basename "$SCHEMA_SAVED")" == swagger_3.2.0.json && "$(local_swagger 3)" == "$SCHEMA_SAVED" ]]'
  HN=components; save_schema "$FIX/schemas/swagger_3.x.json"
  check "save_schema: схему с именем сервера внутри не сохраняет" '[[ -z "$SCHEMA_SAVED" && "$SCHEMA_NOTE" == *"имя сервера"* ]]'
  rm -rf "$SCHEMA_DIR"
  exit "$FAILS"
); r=$?; FAILS=$((FAILS + r))

echo "▸ lib/detail.sh + отчёт: подробности проверки"
(
  OUT="$(mktemp -d)"; trap 'rm -rf "$OUT"' EXIT
  . "$ROOT/lib/ui.sh"; . "$ROOT/lib/util.sh"; . "$ROOT/lib/detail.sh"; . "$ROOT/report/build.sh"
  TTY_OUT=0; detail_init "$OUT" ringo
  printf '{"message":"Cannot PUT /x"}' >"$OUT/body.json"
  det_new "PUT /x — <проба>"; det_kv "Что проверяется" "маршрут"; det_sec "Запрос"
  det_cmd curl -sk -H "Content-Type: application/json" "https://h/x?a=1&b=2"
  det_text "HTTP/2 404" "server: nginx"; det_sec "Тело ответа"; det_file "$OUT/body.json"
  { echo; echo "T"; hr; echo " Хост: h"; hr; echo " ▸ Раздел"; printf '   [WARN] PUT  /x  404  42B  10ms  маршрута нет\n'; det_ref; } >"$OUT/ringo.txt"
  html=$(render_module "$OUT/ringo.txt" m1)
  grep -q '↳ подробнее: details/ringo/001.txt' "$OUT/ringo.txt" &&
  grep -q "^\$ curl -sk -H 'Content-Type: application/json' 'https://h/x?a=1&b=2'$" "$OUT/details/ringo/001.txt" &&
  grep -q '<template class="det" data-title="PUT /x — &lt;проба&gt;">' <<<"$html" &&
  grep -q '<div class="dcmd"><code>curl' <<<"$html" &&
  grep -q '<span class="hk">server</span>: nginx' <<<"$html" &&
  grep -q '<dt>Что проверяется</dt><dd>маршрут</dd>' <<<"$html" &&
  ! grep -q 'class="note">подробнее' <<<"$html"
) && ok "файл подробностей, экранирование команды, <template> в строке отчёта" || bad "подробности проверки"

echo "▸ report/build.sh (отчёт из фикстуры)"
(
  OUT="$(mktemp -d)"; trap 'rm -rf "$OUT"' EXIT
  . "$ROOT/lib/ui.sh"; . "$ROOT/lib/util.sh"; . "$ROOT/report/build.sh"
  LOGDIR="$OUT"; REPORT="$OUT/report.html"; RUN_DATE=now; RUN_T0=$SECONDS; RINGO_URL=https://mdm.example.com
  DO_MON=0; ORIG_ARGS=""
  RESULTS=("Ringo MDM: эндпоинты|$FIX/ringo_sample.txt|1|33 3 4 0|")
  build_report >/dev/null
  rows=$(grep -o 'class="row ' "$REPORT" | wc -l | tr -d ' ')
  lines=$(grep -cE '^ *\[( OK |INFO|WARN|FAIL)\]' "$FIX/ringo_sample.txt")
  [[ -s "$REPORT" && "$rows" == "$lines" ]] && grep -q '</html>' "$REPORT" && grep -q -- '--accent' "$REPORT"
) && ok "каждая строка проверки → строка отчёта, стили встроены" || bad "build_report"

echo
echo "Пройдено: $PASS, ошибок: $FAILS"
exit $(( FAILS > 0 ))
