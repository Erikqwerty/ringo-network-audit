# shellcheck shell=bash
# Время (UDP 123): расхождение часов больше минуты ломает проверку TLS-сертификатов и подписей MDM.
# Итог: OK — ответ есть, сдвиг ≤ 60 с; WARN — нет ответа или сдвиг > 60 с; INFO — нет python3 и sntp.
(( NO_BUILTIN == 0 )) || return 0

echo; echo " ${BD}${B}▸ Время (UDP 123): расхождение часов ломает TLS и подписи${N}"
for h in time.apple.com time-macos.apple.com; do
  prog "   %s…%s" "$D" "$N"
  off=""
  if have python3; then
    off=$(python3 - "$h" <<'PY' 2>/dev/null
import socket,struct,sys,time
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(3)
try:
    s.sendto(b'\x1b'+47*b'\0',(sys.argv[1],123)); t0=time.time(); d,_=s.recvfrom(512); t1=time.time()
    srv=struct.unpack('!12I',d[:48])[10]-2208988800
    print("%.2f"%(srv-(t0+t1)/2)); sys.exit(0)
except Exception: sys.exit(1)
PY
)
    rc=$?
  elif have sntp; then
    off=$($TOUT ${TOUT:+6} sntp -t 3 "$h" 2>/dev/null | awk 'NR==1{print $1}'); [[ -n "$off" ]] && rc=0 || rc=1
  else rc=9; fi
  clear_line
  det_new "NTP: $h"; det_kv "Как проверяется" "запрос NTP на UDP 123 и сравнение времени сервера с часами этого компьютера"
  det_cmdline "python3: socket UDP → $h:123, пакет 0x1b + 47 нулей, время из ответа (transmit timestamp)"
  det_kv "Результат" "$( ((rc == 0)) && echo "сдвиг часов ${off} с" || echo "нет ответа (rc=$rc)")"
  det_text "Расхождение больше минуты ломает проверку TLS-сертификатов и подписей MDM."
  if (( rc == 9 )); then
    printf "   %s %-38s %s%s%s\n" "$(badge INFO)" "UDP 123 $h" "$D" "не проверено: нужен python3 или sntp" "$N"; count INFO; det_ref
  elif (( rc != 0 )) || [[ -z "$off" ]]; then
    printf "   %s %-38s %s%s%s\n" "$(badge WARN)" "UDP 123 $h" "$D" "нет ответа NTP (UDP 123 закрыт?)" "$N"; count WARN; det_ref
  else
    abs=$(awk -v x="$off" 'BEGIN{print (x<0?-x:x)}')
    if awk -v a="$abs" 'BEGIN{exit !(a>60)}'; then
      printf "   %s %-38s %s%s%s\n" "$(badge WARN)" "UDP 123 $h" "$D" "часы расходятся с Apple на ${off} с (>60 с)" "$N"; count WARN; det_ref
    else
      printf "   %s %-38s %s%s%s\n" "$(badge OK)" "UDP 123 $h" "$D" "ответ получен, сдвиг часов ${off} с" "$N"; count OK; det_ref
    fi
  fi
done
