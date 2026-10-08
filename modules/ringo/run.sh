#!/usr/bin/env bash
# modules/ringo/run.sh — проверка Ringo MDM за reverse proxy
# Сверка с https://docs.ringomdm.ru/installation/infrastructure/reverse-proxy
#
# Использование (обычно запускается из ../../audit.sh, но можно и напрямую):
#   run.sh https://mdm.example.com                 # снаружи
#   run.sh https://mdm.example.com --internal      # из подсети, где разрешён веб-интерфейс
#   run.sh https://mdm.example.com --scep-proxy    # + /scep-proxy
#   run.sh https://mdm.example.com --no-waf-probe  # не слать тестовые строки с сигнатурами атак
#   run.sh https://mdm.example.com --dpi           # вмешательство на пути (DPI / ТСПУ)
#   run.sh https://mdm.example.com --capture [if]  # захват tcpdump во время проверки (нужен sudo)
#   run.sh https://mdm.example.com --pcap файл     # разбор готового .pcap
#   run.sh https://mdm.example.com --out папка     # сохранить ответы сервера и swagger
#   run.sh https://mdm.example.com --compare папка # сравнить с прошлым аудитом (папка или ringo.txt)
#   run.sh https://mdm.example.com --token JWT     # точная версия Ringo (/api/v1/version); или RINGO_TOKEN
#   run.sh https://mdm.example.com --swagger файл  # своя схема API вместо скачанной/локальной
#   run.sh https://mdm.example.com --no-save-schema # не сохранять новую схему сервера в schemas/
#
# Схема API: сначала скачивается с сервера (/api/v1/documentation-json). Если она закрыта —
# берётся schemas/swagger_<версия>.json по версии, определённой по маршрутам. Эндпоинты,
# которых нет в схеме этой версии, не проверяются. Схема сервера, которой ещё нет среди снимков,
# сохраняется в schemas/ (с токеном — как swagger_<версия>.json) — так копятся снимки версий.
#
# Проверки WAF и DPI неинвазивны: тестовые строки идут в query/теле с заведомо
# невалидными данными, приложение ничего не создаёт. Запускать только по своей инфраструктуре.
#
# Устройство: lib/*.sh — общие функции, checks/NN_раздел/NN_проверка.sh — по файлу на проверку, по порядку.
# Коды возврата: 0 — всё ок, 1 — есть WARN, 2 — есть FAIL. Совместимо с bash 3.2 (macOS).

set -u

MOD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$MOD_DIR/../.." && pwd)"
SCHEMA_DIR="$ROOT/schemas"

usage() { sed -n '2,29p' "$0" | sed 's/^# \{0,1\}//'; }

HOST="${1:-}"
[[ "$HOST" == -* ]] && HOST=""
INTERNAL=0; CHECK_SCEP_PROXY=0; WAF_PROBE=1; DPI_PROBE=0; CAPTURE=0; CAP_IFACE=""; PCAP_FILE=""
OUT_DIR=""; COMPARE=""; API_TOKEN="${RINGO_TOKEN:-}"; SWAGGER_FILE=""; SAVE_SCHEMA=1
shift || true
while [[ $# -gt 0 ]]; do
  case "$1" in
    --internal)     INTERNAL=1 ;;
    --scep-proxy)   CHECK_SCEP_PROXY=1 ;;
    --no-waf-probe) WAF_PROBE=0 ;;
    --dpi)          DPI_PROBE=1 ;;
    --capture)      CAPTURE=1; DPI_PROBE=1
                    [[ "${2:-}" == --* || -z "${2:-}" ]] || { CAP_IFACE="$2"; shift; } ;;
    --pcap)         PCAP_FILE="${2:-}"; shift ;;
    --out)          OUT_DIR="${2:-}"; shift ;;
    --compare)      COMPARE="${2:-}"; shift ;;
    --token)        API_TOKEN="${2:-}"; shift ;;
    --swagger)      SWAGGER_FILE="${2:-}"; shift ;;
    --no-save-schema) SAVE_SCHEMA=0 ;;
    -h|--help)      usage; exit 0 ;;
    *) echo "Неизвестный параметр: $1"; usage; exit 1 ;;
  esac
  shift
done

if [[ -z "$HOST" ]]; then usage; exit 1; fi
HOST="${HOST%/}"
[[ -d "$COMPARE" ]] && COMPARE="$COMPARE/ringo.txt"
if [[ -n "$COMPARE" && ! -f "$COMPARE" ]]; then echo "--compare: нет файла $COMPARE"; exit 1; fi
RESP_DIR=""
if [[ -n "$OUT_DIR" ]]; then
  RESP_DIR="$OUT_DIR/responses"; mkdir -p "$RESP_DIR" 2>/dev/null || RESP_DIR=""
fi

# shellcheck source=../../lib/ui.sh
. "$ROOT/lib/ui.sh"
# shellcheck source=../../lib/util.sh
. "$ROOT/lib/util.sh"
# shellcheck source=../../lib/detail.sh
. "$ROOT/lib/detail.sh"
for f in "$MOD_DIR"/lib/*.sh; do . "$f"; done
detail_init "$OUT_DIR" ringo

# общее состояние проверок
FLAKY_CNT=0
SEEN_HAPROXY=0; SEEN_NGINX=0
TMP="$(mktemp)"; FPD="$(mktemp -d)"
trap 'stop_capture; rm -f "$TMP" "$TMP".*; rm -rf "$FPD"' EXIT
# признаки страницы блокировки WAF (в нижнем регистре)
BLOCK_RE='support id|incident id|ray id|request rejected|requested url was rejected|access to resource was blocked|access blocked|attention required|request blocked|web application firewall'

# проверки: разделы и файлы внутри — по порядку номеров; файл без нужных условий сам делает return
for f in "$MOD_DIR"/checks/[0-9][0-9]_*/[0-9][0-9]_*.sh; do . "$f"; done
