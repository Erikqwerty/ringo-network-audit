#!/usr/bin/env bash
# modules/apple/run.sh — проверка сетевого окружения для Apple MDM (APNs, активация, OCSP, NTP)
#
# Списки хостов и портов: Apple «Use Apple products on enterprise networks»
# (https://support.apple.com/101555, ред. 07.08.2026) и Apple Platform Deployment (APNs).
#
# Запускать:
#   • на MDM-сервере            — исходящие: APNs (HTTP/2), портал APNs-сертификата, ADE/Apple Business, VPP
#   • на Mac / в сети устройств — APNs 5223/443, активация (albert.apple.com), профили, OCSP/CRL, NTP
#
# Использование (обычно из ../../audit.sh):
#   run.sh [--role server|client|both] [--timeout N] [--updates] [--accounts] [--apps] [--all]
#          [--add host:port[:tls]] [--no-builtin] [--out папка аудита — подробности проверок для отчёта]
#
# Устройство: lib/*.sh — функции и список целей, checks/NN_раздел/NN_проверка.sh — по файлу на проверку.
# Коды возврата: 0 — всё ок, 1 — есть WARN, 2 — есть FAIL. Совместимо с bash 3.2 (macOS).

set -u

MOD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$MOD_DIR/../.." && pwd)"

usage() { sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; }

ROLE="both"; TMO=4; NO_BUILTIN=0; G_UPD=0; G_ACC=0; G_APPS=0
ADD=(); OUT_DIR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --role)      ROLE="${2:-both}"; shift ;;
    --timeout)   TMO="${2:-4}"; shift ;;
    --updates)   G_UPD=1 ;;
    --accounts)  G_ACC=1 ;;
    --apps)      G_APPS=1 ;;
    --all)       G_UPD=1; G_ACC=1; G_APPS=1 ;;
    --add)       ADD+=("${2:-}"); shift ;;
    --no-builtin) NO_BUILTIN=1 ;;
    --out)       OUT_DIR="${2:-}"; shift ;;
    -h|--help)   usage; exit 0 ;;
    *) echo "Неизвестный параметр: $1"; usage; exit 1 ;;
  esac
  shift
done
case "$ROLE" in server|client|both) ;; *) echo "--role: server|client|both"; exit 1 ;; esac

# shellcheck source=../../lib/ui.sh
. "$ROOT/lib/ui.sh"
# shellcheck source=../../lib/util.sh
. "$ROOT/lib/util.sh"
# shellcheck source=../../lib/detail.sh
. "$ROOT/lib/detail.sh"
detail_init "$OUT_DIR" apple
. "$MOD_DIR/lib/net.sh"
. "$MOD_DIR/lib/check.sh"
. "$MOD_DIR/lib/verdict.sh"
. "$MOD_DIR/lib/targets.sh"   # строит TARGETS/SEL по флагам выше
# проверки: разделы и файлы внутри — по порядку номеров; файл без нужных условий сам делает return
for f in "$MOD_DIR"/checks/[0-9][0-9]_*/[0-9][0-9]_*.sh; do . "$f"; done
