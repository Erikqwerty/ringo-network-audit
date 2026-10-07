#!/usr/bin/env bash
# audit.sh — сетевой аудит Ringo MDM: одна точка входа для всех модулей
#   modules/ringo   — эндпоинты Ringo за reverse proxy, TLS и цепочка, WAF, DPI/ТСПУ, версия и схема API
#   modules/apple   — сетевое окружение Apple MDM: APNs, активация, ADE, OCSP/CRL, NTP
#   modules/monitor — мониторинг «как mtr»: параллельная постоянная проверка адресов/эндпоинтов
# Результат — папка results/<домен>_<дата>_<время>/: report.html, ringo.txt, apple.txt, monitor/, responses/, *.pcap.
#
# Запуск без аргументов — интерактивное меню. Без вопросов:
#   ./audit.sh --full https://mdm.example.com [--internal] [--capture IFACE] [--duration S]
#                      полный аудит: Ringo со всеми проверками + Apple (все хосты, обе роли) + мониторинг (60 с)
#   ./audit.sh --ringo https://mdm.example.com [--internal] [--scep-proxy] [--no-waf-probe] [--dpi] [--capture IFACE]
#                      [--compare results/<домен>_<дата>_<время>]   (сравнить с прошлым аудитом, например эталонного сервера)
#     точная версия Ringo: RINGO_TOKEN=<JWT> ./audit.sh --ringo …  (токен не попадает в логи и отчёт)
#   ./audit.sh --apple [--role server|client|both] [--timeout N] [--apple-extra "--updates --apps"]
#   ./audit.sh --monitor [--target URL|host:port|ping:host]... [--interval S] [--count N | --duration S]
#   Модули сочетаются: --ringo URL --apple --monitor
#   Общие: --report путь/файл.html (логи — в ту же папку)  --no-open  --menu (меню вместе с флагами)  -h|--help
#   Пересобрать отчёт из логов прошлого запуска (без повторных проверок): --rebuild results/<домен>_<дата>_<время>
#
# Цели мониторинга:
#   https://host/путь   — HTTP(S): код, TCP/TLS/первый байт/итог, этап обрыва
#   host:port           — TCP-подключение (время установления)
#   ping:host           — ICMP (может быть закрыт файрволом — это не ошибка сервиса)
# Если цели не заданы, берутся ключевые эндпоинты Ringo (при --ringo) и хосты Apple (APNs, активация).
#
# Коды возврата: 0 — всё ок, 1 — есть WARN, 2 — есть FAIL (по худшему модулю).
# Совместимо с bash 3.2 (macOS).

set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ORIG_ARGS="$*"
FULL_MON_SECONDS=60   # мониторинг в полном аудите, если не задан --duration/--count

# ---------- параметры ----------
DO_RINGO=0; DO_APPLE=0; DO_MON=0; FULL=0
RINGO_URL=""; R_INTERNAL=0; R_SCEPPROXY=0; R_WAF=1; R_DPI=0; R_CAPTURE=""; R_COMPARE=""
A_ROLE="both"; A_TIMEOUT=4; A_EXTRA=""
M_TARGETS=(); M_INTERVAL=2; M_COUNT=0; M_DURATION=0; M_TIMEOUT=5
REPORT=""; OPEN_REPORT=1; INTERACTIVE=1; FORCE_MENU=0; REBUILD=""; RUN_DUR=""

usage() { sed -n '2,29p' "$0" | sed 's/^# \{0,1\}//'; }

while [[ $# -gt 0 ]]; do
  INTERACTIVE=0
  case "$1" in
    --full)         FULL=1; [[ "${2:-}" =~ ^https?:// ]] && { RINGO_URL="$2"; shift; } ;;
    --ringo)        DO_RINGO=1; RINGO_URL="${2:-}"; shift ;;
    --internal)     R_INTERNAL=1 ;;
    --scep-proxy)   R_SCEPPROXY=1 ;;
    --no-waf-probe) R_WAF=0 ;;
    --dpi)          R_DPI=1 ;;
    --capture)      R_CAPTURE="${2:-}"; shift ;;
    --compare)      R_COMPARE="${2:-}"; shift ;;
    --apple)        DO_APPLE=1 ;;
    --role)         A_ROLE="${2:-both}"; shift ;;
    --timeout)      A_TIMEOUT="${2:-4}"; shift ;;
    --apple-extra)  A_EXTRA="${2:-}"; shift ;;
    --monitor)      DO_MON=1 ;;
    --target)       M_TARGETS+=("${2:-}"); shift ;;
    --interval)     M_INTERVAL="${2:-2}"; shift ;;
    --count)        M_COUNT="${2:-0}"; shift ;;
    --duration)     M_DURATION="${2:-0}"; shift ;;
    --probe-timeout) M_TIMEOUT="${2:-5}"; shift ;;
    --report)       REPORT="${2:-}"; shift ;;
    --no-open)      OPEN_REPORT=0 ;;
    --menu)         FORCE_MENU=1 ;;
    --rebuild)      REBUILD="${2:-}"; shift ;;
    -h|--help)      usage; exit 0 ;;
    *) echo "Неизвестный параметр: $1"; usage; exit 1 ;;
  esac
  shift
done

(( FORCE_MENU )) && INTERACTIVE=1

# полный аудит: все модули и все проверки, которые не требуют прав и ввода
apply_full() {
  [[ -n "$RINGO_URL" ]] && DO_RINGO=1
  R_SCEPPROXY=1; R_DPI=1; R_WAF=1
  DO_APPLE=1; A_ROLE=both
  [[ " $A_EXTRA " == *" --all "* ]] || A_EXTRA="$A_EXTRA --all"
  DO_MON=1
  (( M_DURATION == 0 && M_COUNT == 0 )) && M_DURATION=$FULL_MON_SECONDS
  return 0
}
(( FULL )) && apply_full

# shellcheck source=lib/ui.sh
. "$ROOT/lib/ui.sh"
# shellcheck source=lib/util.sh
. "$ROOT/lib/util.sh"
. "$ROOT/lib/menu.sh"
. "$ROOT/lib/runner.sh"
. "$ROOT/report/build.sh"

# --rebuild: только пересобрать report.html из сохранённых логов прошлого запуска
RESULTS=()
if [[ -n "$REBUILD" ]]; then
  [[ -f "$REBUILD/run.txt" ]] || { echo "--rebuild: в $REBUILD нет run.txt (это не папка запуска мастера)"; exit 1; }
  INTERACTIVE=0; LOGDIR="$(cd "$REBUILD" && pwd)"; REPORT="$LOGDIR/report.html"; RUN_T0=$SECONDS
  # shellcheck disable=SC1090
  . "$LOGDIR/run.txt"
  if [[ -f "$LOGDIR/results.txt" ]]; then
    while IFS='|' read -r name log rest; do
      [[ -z "$name" ]] && continue
      [[ -f "$log" ]] || log="$LOGDIR/$(basename "$log")"      # папку могли перенести
      RESULTS+=("$name|$log|$rest")
    done <"$LOGDIR/results.txt"
  fi
  if [[ -f "$LOGDIR/monitor/targets.txt" ]]; then
    DO_MON=1; MON_DIR="$LOGDIR/monitor"; MON_T=()
    while IFS= read -r x; do [[ -n "$x" ]] && MON_T+=("$x"); done <"$MON_DIR/targets.txt"
    [[ -f "$MON_DIR/meta.txt" ]] && . "$MON_DIR/meta.txt"
  fi
fi

(( INTERACTIVE )) && interactive_menu
(( FULL )) && [[ -z "$RINGO_URL" ]] && echo "${Y}Полный аудит без URL Ringo: только Apple и мониторинг.${N}"

if [[ -z "$REBUILD" ]] && (( !DO_RINGO && !DO_APPLE && !DO_MON )); then
  echo "Ничего не выбрано. Запустите без аргументов для меню или см. --help"; exit 1
fi
if (( DO_RINGO )) && [[ ! "$RINGO_URL" =~ ^https?:// ]]; then
  echo "--ringo: нужен URL вида https://host"; exit 1
fi
case "$A_ROLE" in server|client|both) ;; *) echo "--role: server|client|both"; exit 1 ;; esac

STAMP="$(date +%Y%m%d_%H%M%S)"
[[ -n "$REBUILD" ]] || { RUN_T0=$SECONDS; RUN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"; }
# всё про один запуск — в одной папке: report.html рядом с ringo.txt, apple.txt, monitor/, *.pcap
if [[ -n "$REBUILD" ]]; then :
elif [[ -n "$REPORT" ]]; then
  [[ "$REPORT" == */* ]] || REPORT="$PWD/$REPORT"
  LOGDIR="$(dirname "$REPORT")"
else
  # папка — по домену, чтобы аудиты разных серверов было видно сразу: results/<домен>_<дата>_<время>
  LOGDIR="$ROOT/results/$( [[ -n "$RINGO_URL" ]] && host_of "$RINGO_URL" || echo apple )_$STAMP"
  REPORT="$LOGDIR/report.html"
fi
mkdir -p "$LOGDIR" || { echo "Не удалось создать $LOGDIR"; exit 1; }

(( DO_RINGO )) && run_ringo
(( DO_APPLE )) && run_apple
# мониторинг: модуль сам проверяет DO_MON/REBUILD и рисует таблицу до Ctrl-C или --count/--duration
. "$ROOT/modules/monitor/monitor.sh"

[[ -n "$REBUILD" ]] || printf 'RUN_DATE=%q\nRUN_DUR=%q\nORIG_ARGS=%q\nRINGO_URL=%q\n' "$RUN_DATE" "$((SECONDS - RUN_T0))" "$ORIG_ARGS" "$RINGO_URL" >"$LOGDIR/run.txt"
build_report; RC=$?
echo "${BD}Отчёт:${N} $REPORT"
echo "${D}Папка: $LOGDIR${N}"
if (( OPEN_REPORT )) && [[ -t 1 ]]; then
  if have open; then open "$REPORT" 2>/dev/null; elif have xdg-open; then xdg-open "$REPORT" >/dev/null 2>&1; fi
fi
exit "$RC"
