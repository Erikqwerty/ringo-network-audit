# shellcheck shell=bash
# Сертификат принимает обычный клиент — curl с хранилищем доверенных корней этого компьютера.
# Итог: OK — принят; WARN — не принят (причина обычно уже видна в проверке цепочки) или нет ответа.
[[ "$HOST" == https://* ]] || return 0

prog "   %s…%s" "$D" "$N"
cverr=$(curl -sS -m 10 -o /dev/null "$HOST/" 2>&1); rc=$?
det_new "Проверка сертификата клиентом (curl)"; det_sec "Проверка с хранилищем доверенных корней этого компьютера"
det_cmd curl -sS -m 10 -o /dev/null "$HOST/"; det_kv "Код возврата curl" "$rc$( ((rc == 0)) && echo " — сертификат принят")"
[[ -n "$cverr" ]] && det_text "$cverr"
clear_line
case "$rc" in
  0)  printf "   %s сертификат валиден и доверенный\n" "$(badge OK)"; count OK ;;
  60|51|58|83)
    if [[ "$CH_RES" =~ ^(incomplete\??|untrusted|self|expired|order|placeholder|name)$ ]]; then
      printf "   %s сертификат не прошёл проверку curl %s(rc=%d — причина в цепочке, см. выше)%s\n" "$(badge WARN)" "$D" "$rc" "$N"
    else
      printf "   %s сертификат не прошёл проверку %s(curl rc=%d: самоподписанный/просрочен/не та цепочка/имя)%s\n" "$(badge WARN)" "$D" "$rc" "$N"
    fi; count WARN ;;
  *)  printf "   %s не удалось проверить сертификат %s(%s)%s\n" "$(badge WARN)" "$D" "$(net_hint "$rc")" "$N"; count WARN "сертификат не проверен (нет ответа)" ;;
esac
det_ref
