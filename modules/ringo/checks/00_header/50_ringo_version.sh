# shellcheck shell=bash
# Версия Ringo и схема API (detect_ringo в lib/api.sh). От схемы зависит, какие эндпоинты проверять:
# маршрутов, которых нет в этой версии, проверки не трогают. Новая схема сервера сохраняется в schemas/.
# Задаёт: RINGO_FAM, RINGO_VER, VER_HOW, API_OPS, API_SRC и др. (см. detect_ringo).

prog " %sопределение версии Ringo и схемы API…%s" "$D" "$N"
detect_ringo
clear_line
if [[ -n "$RINGO_FAM" ]]; then
  printf " Ringo:  %s%s%s %s(%s)%s\n" "$BD" "${RINGO_VER:-${RINGO_FAM}.x}" "$N" "$D" "$VER_HOW" "$N"
else
  printf " Ringo:  %sверсия не определена%s\n" "$D" "$N"
fi
if [[ -n "$API_OPS" ]]; then
  printf " API:    схема %s %s(операций: %d%s)%s\n" "$API_SRC" "$D" "$(grep -c . <<<"$API_OPS")" "${API_SAME:+; $API_SAME}" "$N"
else
  printf " API:    %sсхемы нет — эндпоинты проверяются по встроенному списку без учёта версии%s\n" "$D" "$N"
fi
[[ -n "$API_DIFF" ]] && printf " Отличия: маршруты устройств %s\n" "$API_DIFF"
if [[ -n "$SCHEMA_SAVED" ]]; then
  printf " Снимок: новая схема сохранена в schemas/%s%s%s\n" "$BD" "$(basename "$SCHEMA_SAVED")" "$N"
  is_versioned "$SCHEMA_SAVED" || \
    printf "          %sверсия неизвестна — когда узнаете, переименуйте в swagger_<версия>.json (или запустите с RINGO_TOKEN)%s\n" "$D" "$N"
elif [[ -n "$SCHEMA_NOTE" ]]; then
  printf " Снимок: схема %s\n" "$SCHEMA_NOTE"
fi
