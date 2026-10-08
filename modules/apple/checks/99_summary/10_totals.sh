# shellcheck shell=bash
# Счётчики и код возврата модуля: 0 — всё ок, 1 — есть WARN, 2 — есть FAIL.

echo "${D}────────────────────────────────────────────────────────────────────${N}"
print_totals
if   (( FAIL_CNT )); then echo " ${R}${BD}Есть блокирующие проблемы для Apple MDM.${N}"; echo; exit 2
elif (( WARN_CNT )); then echo " ${Y}${BD}Есть замечания — проверьте перечисленные хосты.${N}"; echo; exit 1
else echo " ${G}${BD}Сетевое окружение соответствует требованиям Apple.${N}"; echo; fi
