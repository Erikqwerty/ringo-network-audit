# shellcheck shell=bash
# Время (UDP 123): расхождение часов больше минуты ломает проверку TLS-сертификатов и подписей MDM.
# Итог: OK — ответ есть, сдвиг ≤ 60 с; WARN — нет ответа или сдвиг > 60 с; INFO — нет python3 и sntp.
(( NO_BUILTIN == 0 )) || return 0

echo; echo " ${BD}${B}▸ Время (UDP 123): расхождение часов ломает TLS и подписи${N}"
for h in time.apple.com time-macos.apple.com; do
  prog "   %s…%s" "$D" "$N"
  off=$(ntp_offset "$h"); rc=$?
  clear_line
  det_new "NTP: $h"; det_kv "Как проверяется" "запрос NTP на UDP 123 и сравнение времени сервера с часами этого компьютера"
  det_cmdline "python3: socket UDP → $h:123, пакет 0x1b + 47 нулей, время из ответа (transmit timestamp); без python3 — sntp $h"
  det_kv "Результат" "$( ((rc == 0)) && echo "сдвиг часов ${off} с" || echo "нет ответа (rc=$rc)")"
  det_text "Расхождение больше минуты ломает проверку TLS-сертификатов и подписей MDM."
  if (( rc == 9 )); then
    printf "   %s %-38s %s%s%s\n" "$(badge INFO)" "UDP 123 $h" "$D" "не проверено: нужен python3 или sntp" "$N"; count INFO; det_ref
  elif (( rc != 0 )) || [[ -z "$off" ]]; then
    printf "   %s %-38s %s%s%s\n" "$(badge WARN)" "UDP 123 $h" "$D" "нет ответа NTP (UDP 123 закрыт?)" "$N"; count WARN "NTP: нет ответа от $h (UDP 123)"; det_ref
  else
    abs=$(awk -v x="$off" 'BEGIN{print (x<0?-x:x)}')
    if awk -v a="$abs" 'BEGIN{exit !(a>60)}'; then
      printf "   %s %-38s %s%s%s\n" "$(badge WARN)" "UDP 123 $h" "$D" "часы расходятся с Apple на ${off} с (>60 с)" "$N"; count WARN "часы расходятся с $h на ${off} с"; det_ref
    else
      printf "   %s %-38s %s%s%s\n" "$(badge OK)" "UDP 123 $h" "$D" "ответ получен, сдвиг часов ${off} с" "$N"; count OK; det_ref
    fi
  fi
done
