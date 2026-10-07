# shellcheck shell=bash
# Запуск модулей из audit.sh: вывод в терминал и лог, сводка в results.txt.
# Подключается через source; сам не запускается.

# RESULTS: «модуль|лог|код возврата|OK INFO WARN FAIL|параметры» (заполняется модулями или из --rebuild)
summary_of() { sed -nE 's/.*Итого: *([0-9]+) OK *([0-9]+) INFO *([0-9]+) WARN *([0-9]+) FAIL.*/\1 \2 \3 \4/p' "$1" | tail -1; }

run_module() { # название, лог, скрипт, аргументы...
  local name="$1" log="$2"; shift 2
  local script="$1"; shift
  echo "${B}${BD}════ $name ════${N}"
  # вывод модуля — и в терминал, и в лог. Модуль видит канал tee, а не терминал, поэтому
  # сообщаем ему через AUDIT_TTY, что пользователь смотрит на экран: цвета и строки прогресса остаются.
  local tty=0; [[ -t 1 ]] && tty=1
  AUDIT_TTY=$tty /usr/bin/env bash "$script" "$@" 2>&1 | tee "$log.raw"
  local rc=${PIPESTATUS[0]}
  # в лог — чистый текст: ссылки на подробности (OSC 7777, в терминале невидимы) — отдельной строкой,
  # без ANSI-цветов, а от строк с прогрессом (…\r\e[K) остаётся итог после последнего \r
  perl -pe 's/\e\]7777;([^\a]*)\a/          ↳ подробнее: $1\n/g; s/\e\[[0-9;]*[A-Za-z]//g; s/[^\n]*\r//g' \
    "$log.raw" >"$log" && rm -f "$log.raw"
  RESULTS+=("$name|$log|$rc|$(summary_of "$log")|$*")
  printf '%s\n' "${RESULTS[${#RESULTS[@]}-1]}" >>"$LOGDIR/results.txt"
  echo
}

run_ringo() {
  local args=("$RINGO_URL")
  (( R_INTERNAL ))  && args+=(--internal)
  (( R_SCEPPROXY )) && args+=(--scep-proxy)
  (( R_WAF ))       || args+=(--no-waf-probe)
  (( R_DPI ))       && args+=(--dpi)
  [[ -n "$R_CAPTURE" ]] && args+=(--capture "$R_CAPTURE" --pcap "$LOGDIR/ringo_capture.pcap")
  [[ -n "$R_COMPARE" ]] && args+=(--compare "$R_COMPARE")
  args+=(--out "$LOGDIR")   # ответы сервера и swagger — в папку запуска
  run_module "Ringo MDM: эндпоинты" "$LOGDIR/ringo.txt" "$ROOT/modules/ringo/run.sh" "${args[@]}"
}

run_apple() {
  local args=(--role "$A_ROLE" --timeout "$A_TIMEOUT" --out "$LOGDIR") x
  for x in $A_EXTRA; do args+=("$x"); done
  run_module "Apple MDM: сетевое окружение" "$LOGDIR/apple.txt" "$ROOT/modules/apple/run.sh" "${args[@]}"
}
