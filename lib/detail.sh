# shellcheck shell=bash
# Подробности проверок для HTML-отчёта: какие команды выполнялись, что ответил сервер, как разобрано.
# Подключается через source; сам не запускается. Без папки аудита (--out) все функции — пустышки.
#
# Порядок у строки проверки:
#   det_new "Заголовок"          — начать подробности
#   det_sec / det_cmd / det_kv / det_text / det_file — наполнить
#   printf "…строка [ OK ] …\n"  — напечатать строку проверки
#   det_ref                      — привязать подробности к только что напечатанной строке
#
# Формат файла (его разбирает report/build.sh):
#   «# заголовок»  «## раздел»  «$ команда»  «= ключ: значение»  остальное — вывод как есть
#
# Ссылка на файл в терминале не видна: печатается как OSC-последовательность ESC]7777;путь BEL,
# которую терминалы игнорируют, а audit.sh превращает в строку лога «↳ подробнее: путь».
# Без терминала (вывод в файл) ссылка печатается сразу обычной строкой.

DETAIL_DIR=""; DETAIL_REL=""; DETAIL_N=0; DET=""

detail_init() { # папка аудита, имя модуля
  [[ -n "${1:-}" ]] || return 0
  DETAIL_DIR="$1/details/$2"; DETAIL_REL="details/$2"
  mkdir -p "$DETAIL_DIR" 2>/dev/null || DETAIL_DIR=""
  return 0
}
det_new() { # заголовок
  DET=""
  [[ -n "$DETAIL_DIR" ]] || return 0
  ((DETAIL_N++))
  DET="$DETAIL_DIR/$(printf '%03d' "$DETAIL_N").txt"
  printf '# %s\n' "$1" >"$DET"
}
det_sec()  { [[ -n "$DET" ]] && printf '## %s\n' "$1" >>"$DET"; return 0; }
det_kv()   { [[ -n "$DET" ]] && printf '= %s: %s\n' "$1" "$2" >>"$DET"; return 0; }
det_text() { [[ -n "$DET" ]] && printf '%s\n' "$@" >>"$DET"; return 0; }
# команда как её можно повторить в терминале: аргументы экранируются, пути временных файлов скрыты
det_cmd() {
  [[ -n "$DET" ]] || return 0
  local a s="" t="${FPD:-/nonexistent}/"
  for a in "$@"; do
    a="${a//$t/}"
    if [[ "$a" =~ ^[A-Za-z0-9_./:=@%+,-]+$ ]]; then s="$s $a"; else s="$s '${a//\'/\'\\\'\'}'"; fi
  done
  printf '$%s\n' "$s" >>"$DET"
}
det_cmdline() { [[ -n "$DET" ]] && printf '$ %s\n' "$1" >>"$DET"; return 0; }
# содержимое файла: текст — до N байт, двоичное — одной строкой о размере
det_file() { # файл [макс. байт]
  [[ -n "$DET" && -f "$1" ]] || return 0
  local max="${2:-6000}" sz
  sz=$(wc -c <"$1" | tr -d ' ')
  if (( sz == 0 )); then printf '(пусто)\n' >>"$DET"; return 0; fi
  if head -c 2048 "$1" | perl -0777 -ne 'exit((tr/\x00-\x08\x0e-\x1f//) > 4 ? 0 : 1)'; then
    printf '(двоичные данные, %s байт)\n' "$sz" >>"$DET"; return 0
  fi
  # обрезка по байтам может разрезать символ UTF-8 — неполный хвост отбрасывает iconv -c
  { head -c "$max" "$1" | LC_ALL=C tr -d '\r' | { iconv -c -f UTF-8 -t UTF-8 2>/dev/null || cat; }; echo; } \
    | LC_ALL=C sed -e '$!b' -e '/^$/d' >>"$DET"
  (( sz > max )) && printf '… (ещё %d байт не показано)\n' "$((sz - max))" >>"$DET"
  return 0
}
det_ref() {
  [[ -n "$DET" ]] || return 0
  local rel; rel="$DETAIL_REL/$(basename "$DET")"
  if (( TTY_OUT )); then printf '\033]7777;%s\007' "$rel"
  else printf '          ↳ подробнее: %s\n' "$rel"; fi
  DET=""
}
