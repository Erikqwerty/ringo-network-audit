# shellcheck shell=bash
# Схема API (swagger) и определение версии Ringo.
# Подключается через source из modules/ringo/run.sh; сам не запускается.

# ---------- схема API (swagger) и версия Ringo ----------
# «МЕТОД путь» по строке на операцию. python3 → jq → grep (grep видит только первый метод пути).
swagger_ops() {
  local f="$1" py
  py="$(safe_python)"
  if [[ -n "$py" ]]; then
    "$py" - "$f" 2>/dev/null <<'PY' && return
import json, sys
for p, v in json.load(open(sys.argv[1])).get("paths", {}).items():
    for m in v:
        if m in ("get", "put", "post", "patch", "delete"):
            print(m.upper(), p)
PY
  fi
  if command -v jq >/dev/null 2>&1; then
    jq -r '.paths | to_entries[] | .key as $p | .value | keys[] | select(test("^(get|put|post|patch|delete)$")) | ascii_upcase + " " + $p' "$f" 2>/dev/null && return
  fi
  grep -oE '"/[^"]*" *: *\{ *"(get|put|post|patch|delete)"' "$f" 2>/dev/null \
    | sed -E 's/^"([^"]*)" *: *\{ *"([a-z]+)"/\2 \1/' | awk '{print toupper($1), $2}'
}
# описанные в схеме ответы: «МЕТОД путь<TAB>код<TAB>описание» (в 2.4.4 почти пусто — см. known_responses.tsv)
swagger_responses() {
  local f="$1" py; py="$(safe_python)"
  [[ -f "$f" && -n "$py" ]] || return 0
  "$py" - "$f" 2>/dev/null <<'PY'
import json, sys
for p, v in json.load(open(sys.argv[1])).get("paths", {}).items():
    for m, op in v.items():
        if m in ("get", "put", "post", "patch", "delete"):
            for code, r in (op.get("responses") or {}).items():
                d = " ".join(((r or {}).get("description") or "").split())
                if d: print(f"{m.upper()} {p}\t{code}\t{d}")
PY
}
# что значит ответ приложения: сначала таблица известных ответов (schemas/known_responses.tsv),
# затем описание кода в схеме. Печатает «источник: пояснение» или ничего.
resp_explain() { # «МЕТОД /путь» код message
  local op="$1" code="$2" msg="$3" o c frag mean
  if [[ -f "$SCHEMA_DIR/known_responses.tsv" ]]; then
    while IFS=$'\t' read -r o c frag mean; do
      [[ -z "$o" || "$o" == \#* ]] && continue
      [[ "$o" == "*" || "$o" == "$op" ]] && [[ "$c" == "$code" ]] && [[ -z "$frag" || "$msg" == *"$frag"* ]] || continue
      echo "известный ответ Ringo: $mean"; return 0
    done <"$SCHEMA_DIR/known_responses.tsv"
  fi
  mean=$(awk -F'\t' -v o="$op" -v c="$code" '$1 == o && $2 == c {print $3; exit}' <<<"${API_RESP:-}")
  [[ -n "$mean" ]] && echo "описан в схеме API: $mean"
  return 0
}

API_OPS=""   # операции текущей схемы; пусто — схемы нет, фильтрации нет
API_FILE=""; API_RESP=""
api_has() { [[ -z "$API_OPS" ]] || grep -qFx "$1" <<<"$API_OPS"; }   # "МЕТОД /путь" без query
# маршруты, которых в swagger нет никогда (socket.io, статика UI)
api_known() { [[ "$1" =~ ^[A-Z]+\ /(agent|mdm|enroll|scep|api)(/|$) && "$1" != *documentation-json ]]; }   # swagger себя не описывает
# операции устройств (не /api/v1 — тех слишком много и они для администратора)
device_ops() { grep -E '^[A-Z]+ /(agent|mdm|enroll|scep)' | sort -u; }

swagger_label() { # путь к локальной схеме -> версия по имени файла
  local b; b="$(basename "$1" .json)"
  case "$b" in swagger) echo "3.x" ;; swagger_*) echo "${b#swagger_}" ;; *) echo "$b" ;; esac
}
# снимок с точной версией в имени: swagger_3.2.0.json (а не swagger_3.x.json или swagger_3.x_<дата>_<хеш>.json)
is_versioned() { [[ "$(basename "$1")" =~ ^swagger_[0-9]+(\.[0-9]+)+\.json$ ]]; }
local_swagger() { # семейство 2|3 -> лучший снимок семейства: свежая точная версия, иначе 3.x, иначе свежий авто-снимок
  local fam="$1" f
  f=$(ls "$SCHEMA_DIR"/swagger_"$fam".*.json 2>/dev/null | while read -r x; do is_versioned "$x" && echo "$x"; done | sort -V | tail -1)
  [[ -z "$f" && -f "$SCHEMA_DIR/swagger_$fam.x.json" ]] && f="$SCHEMA_DIR/swagger_$fam.x.json"
  [[ -z "$f" ]] && f=$(ls "$SCHEMA_DIR"/swagger_"$fam".x_*.json 2>/dev/null | sort | tail -1)
  echo "$f"
}
ops_hash() { cksum | awk '{printf "%08x", $1}'; }   # stdin: отсортированные операции
# снимок с тем же набором операций, что у схемы сервера (точные версии — в приоритете). stdin: операции
schema_match() {
  local want f hit=""
  want="$(sort -u)"
  for f in "$SCHEMA_DIR"/swagger_*.json; do
    [[ -f "$f" ]] || continue
    [[ "$(swagger_ops "$f" | sort -u)" == "$want" ]] || continue
    if is_versioned "$f"; then echo "$f"; return 0; fi
    [[ -z "$hit" ]] && hit="$f"
  done
  [[ -n "$hit" ]] && echo "$hit"
  return 0
}
# новая схема с сервера -> schemas/: с точной версией — swagger_<версия>.json, без — swagger_<сем>.x_<дата>_<хеш>.json.
# Результат: SCHEMA_SAVED (путь) или SCHEMA_NOTE (почему не сохранена)
save_schema() { # файл схемы
  local src="$1" h name
  SCHEMA_SAVED=""; SCHEMA_NOTE=""
  (( SAVE_SCHEMA )) || { SCHEMA_NOTE="новая, не сохранена (--no-save-schema)"; return 0; }
  # схема генерируется из кода и одинакова для всех установок; имя сервера в ней — признак чужих данных
  if grep -qiF "$HN" "$src" 2>/dev/null; then SCHEMA_NOTE="новая, не сохранена: в ней встречается имя сервера"; return 0; fi
  h="$(swagger_ops "$src" | sort -u | ops_hash)"
  if [[ "$RINGO_VER" =~ ^[0-9]+(\.[0-9]+)+$ ]]; then
    name="swagger_$RINGO_VER.json"; [[ -e "$SCHEMA_DIR/$name" ]] && name="swagger_${RINGO_VER}_$h.json"
  else
    name="swagger_${RINGO_FAM:-0}.x_$(date +%Y%m%d)_$h.json"
  fi
  if cp "$src" "$SCHEMA_DIR/$name" 2>/dev/null; then SCHEMA_SAVED="$SCHEMA_DIR/$name"
  else SCHEMA_NOTE="новая, не сохранена: нет записи в $SCHEMA_DIR"; fi
  return 0
}

# RINGO_FAM=3|2|"" — семейство версий; RINGO_VER — точная версия (с --token или по совпадению схемы);
# VER_HOW — как определено; API_SRC — откуда схема; API_SAME / API_DIFF — сравнение со снимками;
# SCHEMA_SAVED / SCHEMA_NOTE — сохранена ли новая схема сервера в schemas/
detect_ringo() {
  local code stub fam_probe="" live="$FPD/swagger_live.json" lf match
  RINGO_FAM=""; RINGO_VER=""; VER_HOW=""; API_SRC="нет"; API_DIFF=""; API_SAME=""; LIVE_SWAGGER=0
  SCHEMA_SAVED=""; SCHEMA_NOTE=""

  # 1. отпечаток по маршруту: PUT /agent/checkin появился в 3.x, в 2.4.4 его нет
  read -r code _ _ stub <<<"$(probe "/agent/checkin" PUT application/json)"
  if [[ "$stub" == app ]]; then
    if route_missing; then fam_probe=2; else fam_probe=3; fi
  else
    read -r code _ _ stub <<<"$(probe "/api/v1/auth/session-expired" POST application/json)"
    if [[ "$stub" == app ]]; then route_missing && fam_probe=2 || fam_probe=3; fi
  fi

  # 2. схема с сервера
  code=$(curl -sk -m 20 -o "$live" -w '%{http_code}' "$HOST/api/v1/documentation-json" 2>/dev/null)
  if [[ "$code" == 200 ]] && head -c 300 "$live" | grep -q '"openapi"\|"swagger"'; then
    LIVE_SWAGGER=1
    [[ -n "$OUT_DIR" ]] && cp "$live" "$OUT_DIR/swagger_server.json" 2>/dev/null
  fi

  if [[ -n "$SWAGGER_FILE" ]]; then
    API_OPS="$(swagger_ops "$SWAGGER_FILE")"; API_SRC="$(basename "$SWAGGER_FILE") (--swagger)"; API_FILE="$SWAGGER_FILE"
  elif (( LIVE_SWAGGER )); then
    API_OPS="$(swagger_ops "$live")"; API_SRC="с сервера"; API_FILE="$live"
  fi
  if [[ -n "$API_OPS" ]]; then
    grep -qFx "PUT /agent/checkin" <<<"$API_OPS" && RINGO_FAM=3 || RINGO_FAM=2
    VER_HOW="по схеме API"
  elif [[ -n "$fam_probe" ]]; then
    RINGO_FAM="$fam_probe"; VER_HOW="по маршрутам приложения"
  fi

  # 3. точная версия — только с токеном (метод требует авторизации)
  if [[ -n "$API_TOKEN" ]]; then
    RINGO_VER=$(curl -sk -m 10 -H "Authorization: Bearer $API_TOKEN" "$HOST/api/v1/version" 2>/dev/null \
                | sed -nE 's/.*"version" *: *"([^"]+)".*/\1/p')
    [[ -n "$RINGO_VER" ]] && VER_HOW="по /api/v1/version"
  fi

  # 4. схема сервера против снимков: совпала — знаем снимок (и версию, если она в имени); новая — сохраняем
  if (( LIVE_SWAGGER )) && [[ -z "$SWAGGER_FILE" ]]; then
    match="$(schema_match <<<"$API_OPS")"
    if [[ -n "$match" ]]; then
      API_SAME="совпадает со схемой $(swagger_label "$match")"
      [[ -z "$RINGO_VER" ]] && is_versioned "$match" && { RINGO_VER="$(swagger_label "$match")"; VER_HOW="по совпадению схемы со снимком"; }
    else
      save_schema "$live"
    fi
  fi

  # 5. снимок семейства: основная схема, если с сервера не получили; иначе — с чем сравнить новую
  lf=""; [[ -n "$RINGO_FAM" ]] && lf="$(local_swagger "$RINGO_FAM")"
  [[ -n "$SCHEMA_SAVED" && "$lf" == "$SCHEMA_SAVED" ]] && lf=""   # с собой не сравниваем
  if [[ -z "$API_OPS" && -n "$lf" ]]; then
    API_OPS="$(swagger_ops "$lf")"; API_SRC="локальная $(basename "$lf")"; API_FILE="$lf"
  elif (( LIVE_SWAGGER )) && [[ -z "$SWAGGER_FILE" && -z "$API_SAME" && -n "$lf" ]]; then
    local a b plus minus
    a="$(device_ops <<<"$API_OPS")"; b="$(swagger_ops "$lf" | device_ops)"
    plus=$(comm -23 <(echo "$a") <(echo "$b") | paste -sd, - | sed 's/,/, /g')
    minus=$(comm -13 <(echo "$a") <(echo "$b") | paste -sd, - | sed 's/,/, /g')
    if [[ -n "$plus$minus" ]]; then API_DIFF="против $(basename "$lf"):${plus:+ новые: $plus;}${minus:+ нет: $minus}"
    else API_DIFF="против $(basename "$lf"): маршруты устройств те же, отличия — в API администратора"; fi
  fi
  API_RESP="$(swagger_responses "$API_FILE")"
  [[ -n "$fam_probe" && -n "$RINGO_FAM" && "$fam_probe" != "$RINGO_FAM" ]] && \
    VER_HOW="$VER_HOW; маршруты приложения говорят о $fam_probe.x — схема не от этого бэкенда?"
  return 0
}
