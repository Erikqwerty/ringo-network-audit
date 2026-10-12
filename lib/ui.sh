# shellcheck shell=bash
# Оформление вывода и счётчики результатов — общие для всех модулей.
# Подключается через source; сам не запускается.
#
# Формат строк — контракт с report/build.sh (HTML-отчёт разбирает текстовый вывод):
#   «[ OK ] …» / «[INFO] …» / «[WARN] …» / «[FAIL] …» — строка проверки
#   « ▸ Раздел»                — заголовок раздела
#   «          ↳ …» (≥6 пробелов) — пояснение к строке выше, «   ↳ …» — к разделу
#   «   • ключ: значение»      — сведения
#   « Итого:  N OK   N INFO   N WARN   N FAIL» — итог модуля (по нему мастер считает сводку)

# Вывод в терминал? AUDIT_TTY=1 выставляет audit.sh: он пишет лог через tee, поэтому модуль
# видит канал, а не терминал, но пользователь смотрит на экран — цвета и прогресс нужны.
TTY_OUT=0; [[ -t 1 || "${AUDIT_TTY:-0}" == 1 ]] && TTY_OUT=1
if (( TTY_OUT )); then
  G=$'\e[32m'; R=$'\e[31m'; Y=$'\e[33m'; B=$'\e[34m'; C=$'\e[36m'; D=$'\e[2m'; BD=$'\e[1m'; N=$'\e[0m'
else
  G=; R=; Y=; B=; C=; D=; BD=; N=
fi

OK_CNT=0; INFO_CNT=0; WARN_CNT=0; FAIL_CNT=0
FAIL_LIST=(); WARN_LIST=()

badge() {
  case "$1" in
    OK)   printf '%s[ OK ]%s' "$G" "$N" ;;
    INFO) printf '%s[INFO]%s' "$C" "$N" ;;
    WARN) printf '%s[WARN]%s' "$Y" "$N" ;;
    FAIL) printf '%s[FAIL]%s' "$R" "$N" ;;
  esac
}
# что делать при WARN/FAIL: первое правило lib/remedies.tsv, чьё регулярное выражение совпало с подписью
REMEDY_FILE="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}/lib/remedies.tsv"
remedy_of() { # подпись -> действие или ничего
  local re fix
  [[ -n "${1:-}" && -f "$REMEDY_FILE" ]] || return 0
  while IFS=$'\t' read -r re fix; do
    [[ -z "$re" || "$re" == \#* || -z "$fix" ]] && continue
    if [[ "$1" =~ $re ]]; then printf '%s' "$fix"; return 0; fi
  done <"$REMEDY_FILE"
}
# действие — первой строкой в подробности открытой проверки (DET из lib/detail.sh), чтобы его было видно сразу
det_remedy() { # подпись
  local fix; [[ -n "${DET:-}" && -f "${DET:-}" ]] || return 0
  fix="$(remedy_of "$1")"; [[ -n "$fix" ]] || return 0
  grep -q '^= Что делать: ' "$DET" && return 0
  { head -1 "$DET"; printf '= Что делать: %s\n' "$fix"; tail -n +2 "$DET"; } >"$DET.r" && mv "$DET.r" "$DET"
}
# count СТАТУС [подпись для итога] — подписанные WARN/FAIL перечисляются в конце модуля
count() {
  case "$1" in
    OK) ((OK_CNT++));; INFO) ((INFO_CNT++));;
    WARN) ((WARN_CNT++)); [[ -n "${2:-}" ]] && { WARN_LIST+=("$2"); det_remedy "$2"; };;
    FAIL) ((FAIL_CNT++)); [[ -n "${2:-}" ]] && { FAIL_LIST+=("$2"); det_remedy "$2"; };;
  esac
  return 0
}
clear_line() { (( TTY_OUT )) && printf '\r\033[K'; return 0; }
prog() { (( TTY_OUT )) && printf "$@"; return 0; }   # строки прогресса — только в терминал
hr() { echo "${D}────────────────────────────────────────────────────────────────${N}"; }
section() { echo " ${BD}${B}▸ $*${N}"; }
# строка итога — её формат разбирают audit.sh (summary_of) и report/build.sh
print_totals() {
  printf " Итого:  %s%d OK%s   %s%d INFO%s   %s%d WARN%s   %s%d FAIL%s\n" \
    "$G" "$OK_CNT" "$N" "$C" "$INFO_CNT" "$N" "$Y" "$WARN_CNT" "$N" "$R" "$FAIL_CNT" "$N"
}
