#!/usr/bin/env bash
# tools/bundle.sh — собрать аудит в один файл для запуска у клиента: dist/ringo-audit.sh
# Клиенту не нужно клонировать репозиторий: копирует файл, запускает, присылает архив с результатом.
#
#   ./tools/bundle.sh                 # dist/ringo-audit.sh — без снимков swagger
#   ./tools/bundle.sh --with-schemas  # со снимками schemas/swagger_*.json (они не публикуются — решайте сами)
#   ./tools/bundle.sh -o путь.sh      # другой путь
#
# У клиента:
#   bash ringo-audit.sh                                   # меню
#   bash ringo-audit.sh --full https://mdm.example.com    # полный аудит
# Результат — папка ringo-audit_<домен>_<дата>_<время>/ и рядом .tar.gz: его и пришлите.
# Нужны те же bash, curl, openssl, perl (см. README). Совместимо с bash 3.2 (macOS).
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/dist/ringo-audit.sh"; SCHEMAS=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --with-schemas) SCHEMAS=1 ;;
    -o)             OUT="${2:-}"; shift ;;
    -h|--help)      sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Неизвестный параметр: $1"; exit 1 ;;
  esac
  shift
done
mkdir -p "$(dirname "$OUT")" || exit 1

# что входит: всё, что нужно для запуска; результаты, тесты и снимки swagger — нет
ex=(--exclude '__pycache__' --exclude '.DS_Store' --exclude '*.pyc')
(( SCHEMAS )) || ex+=(--exclude 'swagger_*.json')
ver="$(git -C "$ROOT" describe --always --dirty 2>/dev/null || echo "?")"
payload="$(mktemp)"; trap 'rm -f "$payload"' EXIT
COPYFILE_DISABLE=1 tar -czf "$payload" -C "$ROOT" "${ex[@]}" audit.sh lib modules report schemas README.md LICENSE || exit 1

{
  cat <<EOF
#!/usr/bin/env bash
# ringo-audit.sh — сетевой аудит Ringo MDM одним файлом (версия $ver, собрано $(date '+%Y-%m-%d'))
#
#   bash ringo-audit.sh                                  # меню с вопросами
#   bash ringo-audit.sh --full https://mdm.example.com   # проверить всё сразу (2–3 минуты)
#   bash ringo-audit.sh --help                           # все параметры
#
# Результат — папка ringo-audit_<домен>_<дата>_<время>/ в текущей папке и рядом архив .tar.gz:
# пришлите архив. Скрипты распаковываются во временную папку и удаляются после запуска.
# Проверки ничего не меняют на сервере. Запускайте только на серверах, которые вам разрешили проверять.
EOF
  cat <<'EOF'
set -u
SELF="$0"
D="$(mktemp -d "${TMPDIR:-/tmp}/ringo-audit.XXXXXX")" || exit 1
trap 'rm -rf "$D"' EXIT
# архив — после строки __ARCHIVE__; base64 разбирает perl (есть везде, в отличие от одинаковых флагов base64)
sed -n '/^__ARCHIVE__$/,$p' "$SELF" | tail -n +2 | perl -MMIME::Base64 -ne 'print decode_base64($_)' | tar -xzf - -C "$D" \
  || { echo "Не удалось распаковать скрипты аудита"; exit 1; }
AUDIT_RESULTS="$PWD" AUDIT_PREFIX="ringo-audit_" bash "$D/audit.sh" --archive "$@"
exit $?
__ARCHIVE__
EOF
  perl -MMIME::Base64 -e 'local $/; print encode_base64(<STDIN>)' <"$payload"
} >"$OUT"
chmod +x "$OUT"
echo "Готово: $OUT ($(( $(wc -c <"$OUT") / 1024 )) КБ, версия $ver$( ((SCHEMAS)) && echo ', со снимками swagger'))"
