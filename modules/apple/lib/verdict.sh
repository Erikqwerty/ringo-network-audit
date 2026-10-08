# shellcheck shell=bash
# Строки вердикта по сценариям (checks/90_verdict/).
# Подключается через source из modules/apple/run.sh; сам не запускается.

# вердикт СТАТУС текст [на чём основан] — основание уходит в подробности отчёта
verdict() {
  det_new "Вердикт"; det_text "$2"; [[ -n "${3:-}" ]] && { det_sec "На чём основан"; det_text "$3"; }
  printf "   %s %s\n" "$(badge "$1")" "$2"; det_ref
}
st_of() { [[ "$(res_get "$1" "$2")" == ok ]] && echo "доступен" || echo "недоступен"; }
short_list() { # первые 4 элемента + «и ещё N»
  local n=0 out="" x extra
  for x in $1; do ((n++)); (( n <= 4 )) && out="$out $x"; done
  (( n > 4 )) && out="$out … и ещё $((n-4))"
  printf '%s' "$out"
}
