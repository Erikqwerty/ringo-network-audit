# shellcheck shell=bash
# Часы: этого компьютера (по NTP) и сервера (по заголовку Date его ответа).
# Сбитые часы здесь искажают проверки сертификатов в отчёте. Сбитые часы сервера ломают устройства:
# SCEP выдаёт сертификаты «из будущего» или уже истёкшие, токены регистрации не проходят по времени.
# Date ставит фронтовой прокси (nginx) — обычно это та же машина, что и Ringo, но не всегда.
# Итог: этот компьютер — OK ≤ 60 с, WARN > 60 с, INFO — NTP недоступен;
#       сервер — OK ≤ 60 с, WARN до 5 мин, FAIL > 5 мин, INFO — нет Date или не с чем сравнить.

# HTTP-дата («Thu, 08 Oct 2026 11:54:35 GMT») -> секунды Unix
http_epoch() {
  perl -MTime::Local=timegm -ne '
    my %m = (Jan=>0,Feb=>1,Mar=>2,Apr=>3,May=>4,Jun=>5,Jul=>6,Aug=>7,Sep=>8,Oct=>9,Nov=>10,Dec=>11);
    print timegm($6, $5, $4, $1, $m{$2}, $3) if /(\d{1,2}) (\w{3}) (\d{4}) (\d\d):(\d\d):(\d\d)/' <<<"$1"
}
abs_gt() { awk -v x="$1" -v l="$2" 'BEGIN{exit !((x<0?-x:x) > l)}'; }

prog "   %sчасы…%s" "$D" "$N"
NTP_SRV=""; NTP_OFF=""
for h in time.apple.com pool.ntp.org; do
  NTP_OFF=$(ntp_offset "$h") && { NTP_SRV="$h"; break; }
  NTP_OFF=""
done
# Date сервера и наше время в середине запроса (у Date точность 1 с)
t0=$(now_ms)
srv_date=$(curl -skI -m 8 "$HOST/" 2>/dev/null | sed -nE 's/^[Dd]ate: *([^[:cntrl:]]*).*/\1/p' | head -1)
t1=$(now_ms)
srv_epoch=$(http_epoch "$srv_date")
clear_line

det_new "Часы этого компьютера"
det_kv "Как проверяется" "запрос NTP на UDP 123 (time.apple.com, затем pool.ntp.org) и сравнение с часами этого компьютера"
det_cmdline "python3: socket UDP → time.apple.com:123 (без python3 — sntp time.apple.com)"
det_kv "Местное время" "$(date '+%Y-%m-%d %H:%M:%S %Z')"
det_kv "Сдвиг" "${NTP_OFF:+${NTP_OFF} с по $NTP_SRV}"
det_text "Плюс — часы компьютера отстают, минус — спешат. Сдвиг больше минуты искажает проверки сертификатов в этом отчёте."
if [[ -z "$NTP_OFF" ]]; then
  printf "   %s часы этого компьютера: NTP недоступен (UDP 123 закрыт?) — сверить не с чем\n" "$(badge INFO)"; count INFO
elif abs_gt "$NTP_OFF" 60; then
  printf "   %s часы этого компьютера сбиты на %s с — проверки сертификатов в отчёте могут быть неверны%s\n" "$(badge WARN)" "$NTP_OFF" "$N"
  count WARN "часы этого компьютера сбиты на ${NTP_OFF} с"
else
  printf "   %s часы этого компьютера: сдвиг %s с %s(NTP %s)%s\n" "$(badge OK)" "$NTP_OFF" "$D" "$NTP_SRV" "$N"; count OK
fi
det_ref

det_new "Часы сервера"
det_kv "Как проверяется" "заголовок Date в ответе сервера сравнивается с точным временем (часы этого компьютера + поправка NTP)"
det_cmd curl -skI -m 8 "$HOST/"
det_kv "Date сервера" "${srv_date:-нет}"
if [[ -n "$srv_epoch" ]]; then
  # точное время = наше + поправка NTP; без NTP сравниваем с нашими часами как есть
  srv_skew=$(awk -v s="$srv_epoch" -v a="$t0" -v b="$t1" -v o="${NTP_OFF:-0}" 'BEGIN{printf "%+.0f", s - ((a+b)/2000 + o)}')
  det_kv "Местное время в момент ответа" "$(date -r $(( (t0 + t1) / 2000 )) '+%Y-%m-%d %H:%M:%S %Z' 2>/dev/null || date '+%Y-%m-%d %H:%M:%S %Z')"
  det_kv "Расхождение сервера" "$srv_skew с$( [[ -z "$NTP_OFF" ]] && echo ' (относительно часов этого компьютера — NTP недоступен)')"
fi
det_text "Date ставит фронтовой прокси (nginx). Если Ringo на другой машине, её часы проверяйте там: date -u."
det_text "Сбитые часы сервера: сертификаты SCEP «из будущего» или уже истёкшие, токены регистрации не проходят по времени."
if [[ -z "$srv_epoch" ]]; then
  printf "   %s часы сервера: нет заголовка Date — сверить не с чем\n" "$(badge INFO)"; count INFO
elif abs_gt "$srv_skew" 300; then
  printf "   %s часы сервера расходятся на %s с — устройства получат сертификаты с неверным сроком%s\n" "$(badge FAIL)" "$srv_skew" "$N"
  count FAIL "часы сервера расходятся на ${srv_skew} с"
elif abs_gt "$srv_skew" 60; then
  printf "   %s часы сервера расходятся на %s с%s\n" "$(badge WARN)" "$srv_skew" "$N"
  count WARN "часы сервера расходятся на ${srv_skew} с"
elif [[ -z "$NTP_OFF" ]]; then
  printf "   %s часы сервера: %s с от часов этого компьютера %s(NTP недоступен — точнее не сверить)%s\n" "$(badge INFO)" "$srv_skew" "$D" "$N"; count INFO
else
  printf "   %s часы сервера: расхождение %s с %s(по заголовку Date, точность 1 с)%s\n" "$(badge OK)" "$srv_skew" "$D" "$N"; count OK
fi
det_ref
