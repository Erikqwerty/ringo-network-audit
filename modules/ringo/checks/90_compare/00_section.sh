# shellcheck shell=bash
# Раздел: сравнение с прошлым аудитом (--compare, лучше — эталонного сервера). Разбирается его ringo.txt.
[[ -n "$COMPARE" ]] || return 0

echo
C_HOST=$(sed -nE 's/^ *Хост: *//p' "$COMPARE" | head -1)
C_DATE=$(sed -nE 's/^ *Дата: *//p' "$COMPARE" | head -1)
echo " ${BD}${B}▸ Сравнение с ${C_HOST:-прошлым аудитом} (${C_DATE:-?})${N}"
