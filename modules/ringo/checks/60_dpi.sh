# shellcheck shell=bash
# Проверка: вмешательство на пути (DPI / ТСПУ), только с --dpi. Выполняется по порядку из modules/ringo/run.sh (source, общие переменные).

# ---------- вмешательство на пути: DPI / ТСПУ (--dpi) ----------
if (( DPI_PROBE )) && [[ -n "${SRV_IP:-}" ]]; then
  echo
  echo " ${BD}${B}▸ Вмешательство на пути (DPI / ТСПУ) — ${SRV_IP}:${SRV_PORT}${N}"
  if (( LOCAL_TCP )); then
    det_new "TCP завершается локально"; det_kv "Время TCP-подключения" "$(awk -v x="$CONN_T" 'BEGIN{printf "%.1f", x*1000}') мс (без DNS)"
    det_text "Быстрее ~3 мс до внешнего адреса TCP не устанавливается физически: рукопожатие завершает" \
             "локальный VPN-клиент в режиме TUN, а до сервера соединение строит уже он сам."
    printf "   %s TCP завершается локально (VPN-клиент в режиме TUN) — всё ниже описывает VPN, а не путь%s\n" "$(badge WARN)" "$N"; count WARN "TCP завершается локально (VPN TUN)"
    det_ref
  fi

  # 1. Рукопожатие с настоящим SNI и с контрольным (случайным) на тот же IP.
  #    Теряется/сбрасывается только ClientHello с вашим именем, а с чужим — нет → фильтр по SNI на пути.
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

  # 2. «Заморозка» потока: ТСПУ обрывает передачу после ~16 КБ (данные перестают идти, соединение висит)
  for attempt in 1 2; do
    prog "   %s…%s" "$D" "$N"
    fz=$(curl -sk -m 40 --speed-time 8 --speed-limit 1 -o /dev/null -w '%{http_code} %{size_download}' "$HOST/agent/bundle" 2>/dev/null); frc=$?
    det_new "DPI: поток /agent/bundle, попытка $attempt"
    det_kv "Как проверяется" "большой ответ (~800 КБ) должен прийти целиком; ТСПУ «замораживает» поток после ~16 КБ — данные перестают идти, соединение висит"
    det_cmd curl -sk -m 40 --speed-time 8 --speed-limit 1 -o /dev/null -w '%{http_code} %{size_download}' "$HOST/agent/bundle"
    det_kv "Результат" "HTTP ${fz:-000 0} байт, curl rc=$frc$( ((frc == 28)) && echo ' (остановился: 8 с без данных или таймаут 40 с)')"
    read -r fcode fsize <<<"${fz:-000 0}"
    clear_line
    fkb=$(( ${fsize%.*} / 1024 ))
    if (( frc == 0 )) && [[ "$fcode" == "200" ]]; then
      printf "   %s поток /agent/bundle: %d КБ без остановки %s(попытка %d)%s\n" "$(badge OK)" "$fkb" "$D" "$attempt" "$N"; count OK; det_ref
    elif (( frc == 28 && ${fsize%.*} >= 8000 && ${fsize%.*} <= 40000 )); then
      printf "   %s поток встал на %d КБ и висит — характерно для «заморозки» ТСПУ (~16 КБ) %s(попытка %d)%s\n" "$(badge FAIL)" "$fkb" "$D" "$attempt" "$N"; count FAIL "«заморозка» потока /agent/bundle"; det_ref
    elif [[ "$fcode" != "200" && "$fcode" != "000" ]]; then
      printf "   %s /agent/bundle отвечает %s — тест потока пропущен\n" "$(badge INFO)" "$fcode"; det_ref; break
    else
      printf "   %s поток прервался на %d КБ: %s %s(попытка %d)%s\n" "$(badge WARN)" "$fkb" "$(net_hint "$frc")" "$D" "$attempt" "$N"; count WARN "поток /agent/bundle прервался"; det_ref
    fi
  done

  # 3. DNS: системный резолвер против DoH — подмена ответа или fake-ip локального прокси
  if [[ ! "$HN" =~ ^[0-9.]+$ ]]; then
    sys_ips=$( (dscacheutil -q host -a name "$HN" 2>/dev/null | awk '/^ip_address:/{print $2}'; getent ahostsv4 "$HN" 2>/dev/null | awk '{print $1}') \
               | grep -E '^[0-9]+(\.[0-9]+){3}$' | sort -u | paste -sd' ' -)
    doh_ips=$( (curl -s -m 8 -H 'accept: application/dns-json' "https://cloudflare-dns.com/dns-query?name=$HN&type=A";
                curl -s -m 8 "https://dns.google/resolve?name=$HN&type=A") 2>/dev/null \
               | grep -oE '"data": ?"[0-9.]+"' | grep -oE '[0-9]+(\.[0-9]+){3}' | sort -u | paste -sd' ' -)
    det_new "DPI: DNS — системный резолвер против DoH"
    det_kv "Как проверяется" "ответ системного DNS сравнивается с DNS-over-HTTPS (его не подменить на пути)"
    det_sec "Системный резолвер"; det_cmd dscacheutil -q host -a name "$HN"; det_text "${sys_ips:-(нет ответа)}"
    det_sec "DoH"; det_cmd curl -s -m 8 -H 'accept: application/dns-json' "https://cloudflare-dns.com/dns-query?name=$HN&type=A"
    det_cmd curl -s -m 8 "https://dns.google/resolve?name=$HN&type=A"; det_text "${doh_ips:-(нет ответа)}"
    common=""; for x in $sys_ips; do [[ " $doh_ips " == *" $x "* ]] && common="$x"; done
    if [[ "$sys_ips" =~ (^| )198\.1[89]\. ]]; then
      printf "   %s DNS: системный резолвер отдаёт %s (fake-ip, 198.18.0.0/15) — имена резолвит локальный прокси%s\n" "$(badge WARN)" "$sys_ips" "$N"; count WARN "DNS: fake-ip локального прокси"; det_ref
    elif [[ -z "$doh_ips" ]]; then
      printf "   %s DNS: DoH недоступен — сравнить не с чем (система: %s)\n" "$(badge INFO)" "${sys_ips:-—}"; det_ref
    elif [[ -n "$common" ]]; then
      printf "   %s DNS: системный ответ совпадает с DoH (%s)\n" "$(badge OK)" "$common"; count OK; det_ref
    else
      printf "   %s DNS: система %s, DoH %s — подмена DNS или split-horizon%s\n" "$(badge WARN)" "${sys_ips:-—}" "$doh_ips" "$N"; count WARN "DNS: подмена или split-horizon"; det_ref
    fi
  fi
fi
