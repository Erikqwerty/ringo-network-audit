# shellcheck shell=bash
# Порт 80: запрос по http:// перенаправляется на https (в примере nginx из документации — 301).
# Итог: OK — редирект на https; INFO — порт закрыт или редиректа нет (рекомендация, не требование).
[[ "$HOST" == https://* ]] || return 0

hostname="${HOST#https://}"; hostname="${hostname%%/*}"; hostname="${hostname%%:*}"
prog "   %s…%s" "$D" "$N"
r80=$(curl -s -m 8 -o /dev/null -w '%{http_code} %{redirect_url}' "http://$hostname/" 2>/dev/null); rc80=$?
det_new "Порт 80"; det_kv "Что проверяется" "запрос по http:// перенаправляется на https (в примере документации — 301)"
det_cmd curl -s -m 8 -o /dev/null -w '%{http_code} %{redirect_url}' "http://$hostname/"
det_kv "Ответ" "${r80:-нет} (curl rc=$rc80)"
clear_line
r80="${r80:-000 }"; c80="${r80%% *}"; loc="${r80#* }"
if [[ "$c80" =~ ^30[1278]$ && "$loc" == https://* ]]; then
  printf "   %s порт 80: редирект на https %s(%s)%s\n" "$(badge OK)" "$D" "$c80" "$N"; count OK
elif [[ "$c80" == "000" ]]; then
  printf "   %s порт 80: %s %s(в примере документации — 301 на https)%s\n" "$(badge INFO)" "$(net_hint "$rc80")" "$D" "$N"; count INFO
else
  printf "   %s порт 80: код %s, редиректа на https нет %s(в примере документации — 301)%s\n" "$(badge INFO)" "$c80" "$D" "$N"; count INFO
fi
det_ref
