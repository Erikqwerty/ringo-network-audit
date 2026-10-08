# shellcheck shell=bash
# Фильтрация по SNI: рукопожатие напрямую на IP сервера с настоящим SNI (5 раз) и со случайным (3 раза).
# Теряется/сбрасывается только ClientHello с вашим именем, а с чужим — нет → фильтр по SNI на пути.
# Итог: FAIL — фильтр по SNI; WARN — перехват SNI прокси/VPN, потери на TLS у обоих имён, SYN без ответа;
#       OK — признаков нет.
(( DPI_PROBE )) && [[ -n "${SRV_IP:-}" ]] || return 0

hs_series() { # sni, повторов -> HS_SUM "ok=N reject=N …", HS_FIRST_SUBJ, HS_MSR "мин–макс"
  local sni="$1" n="$2" j r lst="" mn="" mx=""
  HS_FIRST_SUBJ=""
  SNI_TXT="$SNI_TXT"$'\n'"## SNI $sni ($n попыток)"$'\n'"\$ curl -skv -m 8 --resolve $sni:$SRV_PORT:$SRV_IP https://$sni:$SRV_PORT/"
  for ((j=1; j<=n; j++)); do
    tls_hs "$sni"; lst="$lst $HS_RES"
    SNI_TXT="$SNI_TXT"$'\n'"= попытка $j: $HS_RES, $HS_MS мс${HS_SUBJ:+, сертификат: $HS_SUBJ}"
    [[ "$HS_RES" == ok && -z "$HS_FIRST_SUBJ" ]] && HS_FIRST_SUBJ="$HS_SUBJ"
    [[ -z "$mn" || "$HS_MS" -lt "$mn" ]] && mn=$HS_MS; [[ -z "$mx" || "$HS_MS" -gt "$mx" ]] && mx=$HS_MS
  done
  HS_SUM=$(tr ' ' '\n' <<<"$lst" | grep -v '^$' | sort | uniq -c | awk '{printf "%s%s=%s", (NR>1?" ":""), $2, $1}')
  HS_MSR="${mn}–${mx} мс"
}
# подробности одни на все строки вывода по SNI — копируются в каждую
SNI_TXT="= Как проверяется: рукопожатие напрямую на IP сервера с настоящим SNI и со случайным; теряется только своё имя — фильтр по SNI на пути"$'\n'"= Расшифровка: ok — рукопожатие прошло; reject — сервер отказал (норма для чужого имени); tls-drop — нет ответа на ClientHello; rst — сброс; tcp-drop — нет SYN-ACK"
sni_det() { det_new "DPI: фильтрация по SNI"; det_text "$SNI_TXT"; }
prog "   %s…%s" "$D" "$N"
hs_series "$HN" 5;  REAL_SUM="$HS_SUM"; REAL_MS="$HS_MSR"; REAL_SUBJ="$HS_FIRST_SUBJ"
CTRL_SNI="audit-$RANDOM$RANDOM.invalid"
hs_series "$CTRL_SNI" 3; CTRL_SUM="$HS_SUM"; CTRL_MS="$HS_MSR"; CTRL_SUBJ="$HS_FIRST_SUBJ"
clear_line
printf "   • SNI своего домена:  %s%s%s %s(%s, %s)%s\n" "$BD" "$REAL_SUM" "$N" "$D" "$HN" "$REAL_MS" "$N"
printf "   • SNI контрольный:    %s%s%s %s(случайное имя, %s)%s\n" "$BD" "$CTRL_SUM" "$N" "$D" "$CTRL_MS" "$N"
real_bad=$(grep -oE '(tls-drop|rst)=[0-9]+' <<<"$REAL_SUM" | awk -F= '{s+=$2} END{print s+0}')
ctrl_bad=$(grep -oE '(tls-drop|rst)=[0-9]+' <<<"$CTRL_SUM" | awk -F= '{s+=$2} END{print s+0}')
tcp_bad=$(grep -oE 'tcp-drop=[0-9]+' <<<"$REAL_SUM $CTRL_SUM" | awk -F= '{s+=$2} END{print s+0}')
if [[ -n "$CTRL_SUBJ" && -n "$REAL_SUBJ" && "$CTRL_SUBJ" != "$REAL_SUBJ" ]]; then
  sni_det
  printf "   %s на случайное имя пришёл другой сертификат (%s) — соединение по SNI перехватывает прокси/VPN%s\n" "$(badge WARN)" "$CTRL_SUBJ" "$N"; count WARN "SNI перехватывает прокси/VPN"
  det_ref
fi
if (( real_bad > 0 && ctrl_bad == 0 )); then
  sni_det
  printf "   %s ClientHello с именем %s теряется/сбрасывается (%d из 5), с контрольным именем — нет:%s\n" "$(badge FAIL)" "$HN" "$real_bad" "$N"
  printf "          %sфильтрация по SNI на пути (DPI / ТСПУ) — проверьте, не попал ли домен в реестр%s\n" "$D" "$N"; count FAIL "фильтрация по SNI на пути (DPI / ТСПУ)"
  det_ref
elif (( real_bad > 0 && ctrl_bad > 0 )); then
  sni_det
  printf "   %s потери на TLS и с вашим, и с контрольным именем — канал или сервер, а не фильтр по SNI%s\n" "$(badge WARN)" "$N"; count WARN "потери на TLS (канал или сервер)"
  det_ref
elif (( real_bad == 0 )) && [[ "$REAL_SUM" == *ok=* ]]; then
  sni_det
  printf "   %s признаков фильтрации по SNI нет\n" "$(badge OK)"; count OK
  det_ref
fi
if (( tcp_bad > 0 )); then
  sni_det
  printf "   %s SYN без ответа в %d попытк(ах) — потери до TLS: имя тут ни при чём (канал / файрвол / VPN)%s\n" "$(badge WARN)" "$tcp_bad" "$N"; count WARN "SYN без ответа"
  det_ref
fi
