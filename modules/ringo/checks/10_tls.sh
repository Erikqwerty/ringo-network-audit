# shellcheck shell=bash
# Проверка: TLS, цепочка и сертификат, порт 80. Выполняется по порядку из modules/ringo/run.sh (source, общие переменные).

# ---------- TLS и порт 80 ----------
echo " ${BD}${B}▸ TLS (требование документации: TLS 1.2 и TLS 1.3)${N}"
if [[ "$HOST" != https://* ]]; then
  printf "   %s схема не https — проверка пропущена\n" "$(badge WARN)"; count WARN "схема не https"
else
  for v in 1.2 1.3; do
    prog "   %s…%s" "$D" "$N"
    det_new "TLS $v"; det_kv "Что проверяется" "сервер принимает соединение по TLS $v (требование документации Ringo)"
    tls_check "$v"
    clear_line
    case "$TLS_RES" in
      ok)   printf "   %s TLS %s поддерживается %s(проверено через %s)%s\n" "$(badge OK)" "$v" "$D" "$TLS_VIA" "$N"; count OK ;;
      fail) printf "   %s TLS %s сервером не принят %s(%s %s)%s\n" "$(badge FAIL)" "$v" "$D" "$TLS_VIA" "$TLS_DETAIL" "$N"; count FAIL "TLS $v не принимается" ;;
      *)    printf "   %s TLS %s не удалось проверить %s(%s)%s\n" "$(badge WARN)" "$v" "$D" "$TLS_DETAIL" "$N"; count WARN "TLS $v не проверен" ;;
    esac
    det_ref
  done

  prog "   %s…%s" "$D" "$N"
  det_new "Цепочка сертификатов"
  chain_check
  clear_line
  case "$CH_RES" in
    ok)   printf "   %s цепочка сертификатов полная %s(отдано: %d)%s\n" "$(badge OK)" "$D" "$CH_N" "$N"; count OK ;;
    incomplete)
      printf "   %s неполная цепочка сертификатов: сервер отдаёт %d, нет промежуточного «%s»\n" "$(badge FAIL)" "$CH_N" "$CH_MISSING"; count FAIL "неполная цепочка сертификатов (нет «${CH_MISSING}»)"
      [[ -n "$CH_DETAIL" ]] && printf "          %s↳ %s%s\n" "$D" "$CH_DETAIL" "$N"
      printf "          %s↳ клиенты без догрузки по AIA (Android, Java, curl/openssl, агенты) не установят TLS%s\n" "$D" "$N"
      printf "          %s↳ в ssl_certificate nginx нужен fullchain: сертификат сервера, затем промежуточный%s\n" "$D" "$N"
      [[ -n "$CH_AIA" ]] && printf "          %s↳ промежуточный: %s%s\n" "$D" "$CH_AIA" "$N" ;;
    incomplete\?)
      printf "   %s вероятно, неполная цепочка: сервер отдаёт только свой сертификат, издатель «%s» не отдан и локально не найден\n" "$(badge WARN)" "$CH_MISSING"; count WARN "вероятно, неполная цепочка сертификатов"
      printf "          %s↳ %s%s\n" "$D" "$CH_DETAIL" "$N" ;;
    untrusted)
      printf "   %s цепочка полная %s(отдано: %d)%s, но корень «%s» не в доверенных этого компьютера\n" "$(badge WARN)" "$D" "$CH_N" "$N" "$CH_MISSING"; count WARN "корень «${CH_MISSING}» не доверен на этом компьютере"
      printf "          %s↳ на устройствах корень должен быть установлен (например, профилем MDM)%s\n" "$D" "$N" ;;
    order)   printf "   %s цепочка сертификатов в неверном порядке или с лишним сертификатом %s(%s)%s\n" "$(badge WARN)" "$D" "$CH_DETAIL" "$N"; count WARN "порядок цепочки сертификатов" ;;
    self)    printf "   %s сертификат самоподписанный\n" "$(badge WARN)"; count WARN "самоподписанный сертификат" ;;
    expired) printf "   %s %s\n" "$(badge FAIL)" "$CH_DETAIL"; count FAIL "истёкший сертификат в цепочке" ;;
    placeholder)
      printf "   %s сервер отдаёт сертификат-заглушку «%s» вместо сертификата %s\n" "$(badge FAIL)" "$CH_MISSING" "$HN"
      count FAIL "сертификат-заглушка прокси «${CH_MISSING}» вместо сертификата $HN"
      printf "          %s↳ %s%s\n" "$D" "$CH_DETAIL" "$N"
      printf "          %s↳ браузер покажет ошибку сертификата (на домене с HSTS её нельзя обойти), устройства и агенты не подключатся%s\n" "$D" "$N" ;;
    name)
      printf "   %s %s\n" "$(badge FAIL)" "$CH_DETAIL"; count FAIL "сертификат выдан не на $HN" ;;
    *)       printf "   %s цепочку сертификатов проверить не удалось %s(%s)%s\n" "$(badge WARN)" "$D" "$CH_DETAIL" "$N"; count WARN "цепочка сертификатов не проверена" ;;
  esac

  det_ref
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

  cert_extras   # не в $(…): счётчики count должны остаться в этой оболочке

  # порт 80 -> https (в примере nginx: 301 на https)
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
fi
echo
