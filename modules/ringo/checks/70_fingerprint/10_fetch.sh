# shellcheck shell=bash
# Ответы для анализа: /, /enroll и несуществующий путь (заголовки и тела — в $FPD).
# Задаёт: RAWH — заголовки как есть, ALLH / ALLB — заголовки и тела в нижнем регистре, hver — версия HTTP.

fp_fetch() { # $1 = путь+query, $2 = метка -> печатает http-код
  local c
  c=$(curl -sk -m 10 -D "$FPD/$2.h" -o "$FPD/$2.b" -w '%{http_code}' "$HOST$1" 2>/dev/null)
  printf '%s' "${c:-000}"   # при ошибке curl сам печатает 000 — не дублировать
}

prog "   %s…%s" "$D" "$N"
fp_fetch "/" root >/dev/null
fp_fetch "/enroll" enroll >/dev/null
fp_fetch "/__ringo_probe_$RANDOM$RANDOM" nf >/dev/null
hver=$(curl -sk -m 10 -o /dev/null -w '%{http_version}' "$HOST/" 2>/dev/null)

clear_line

RAWH=$(cat "$FPD"/*.h 2>/dev/null | tr -d '\r')
ALLH=$(tr 'A-Z' 'a-z' <<<"$RAWH")
ALLB=$(cat "$FPD"/*.b 2>/dev/null | head -c 40000 | tr -d '\0' | tr 'A-Z' 'a-z')
