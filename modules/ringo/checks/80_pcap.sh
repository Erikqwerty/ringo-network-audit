# shellcheck shell=bash
# Проверка: разбор захвата (--capture / --pcap). Выполняется по порядку из modules/ringo/run.sh (source, общие переменные).

# ---------- разбор захвата (--capture / --pcap) ----------
[[ -n "${CAP_PID:-}" ]] && sleep 2   # дать долететь FIN/RST последних соединений
stop_capture
if [[ -n "$PCAP_FILE" ]]; then
  echo
  echo " ${BD}${B}▸ Разбор захвата: ${PCAP_FILE}${N}"
  if [[ ! -s "$PCAP_FILE" ]]; then
    printf "   %s файл пуст или не найден\n" "$(badge WARN)"; count WARN
  elif [[ -z "${SRV_IP:-}" ]]; then
    printf "   %s IP сервера не определён — нечего фильтровать\n" "$(badge WARN)"; count WARN
  else
    read -r P_N P_NOS P_INJ P_RST P_FRZ P_RTT P_TTLS <<<"$(pcap_stats "$PCAP_FILE" "$SRV_IP")"
    pcap_det() {
      det_new "Разбор захвата"; det_cmd tcpdump -r "$PCAP_FILE" -nn -v "host $SRV_IP and tcp"
      det_kv "TCP-потоков" "$P_N"; det_kv "Без SYN-ACK" "$P_NOS"; det_kv "RST с чужим TTL (вставлены на пути)" "$P_INJ"
      det_kv "RST от сервера" "$P_RST"; det_kv "Встали на 8–40 КБ (пауза ≥5 с)" "$P_FRZ"
      det_kv "Мин. RTT рукопожатия" "${P_RTT} мс"; det_kv "TTL ответов сервера" "$P_TTLS"
      det_text "TTL 255 или RTT < 3 мс — пакеты «сервера» собирает локальный VPN-стек, а не сервер."
    }
    printf "   • TCP-потоков к %s: %s%s%s, TTL ответов сервера: %s, мин. RTT рукопожатия: %s мс\n" "$SRV_IP" "$BD" "${P_N:-0}" "$N" "${P_TTLS:--}" "${P_RTT:--}"
    if [[ "${P_N:-0}" == "0" ]]; then
      pcap_det
      printf "   %s пакетов к серверу нет — не тот интерфейс? (VPN мог переподключиться на другой utun)\n" "$(badge WARN)"; count WARN "захват: пакетов к серверу нет"
      det_ref
    else
      # TTL ровно 255 у «ответов сервера» — пакет не прошёл ни одного маршрутизатора, его собрал
      # локальный TUN-стек VPN; то же — SYN-ACK быстрее 3 мс. Тогда TTL/RST в захвате описывают VPN.
      PCAP_LOCAL=0
      # до частного адреса (сервер в локальной сети) RTT < 3 мс — норма, туннель по нему не определить
      SRV_PRIVATE=0; [[ "$SRV_IP" =~ ^(10\.|127\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.) ]] && SRV_PRIVATE=1
      if [[ ",$P_TTLS," == *,255,* ]] || { (( ! SRV_PRIVATE )) && [[ "$P_RTT" != "-" ]] && awk -v r="$P_RTT" 'BEGIN{exit !(r<3)}'; }; then
        PCAP_LOCAL=1
        pcap_det
        printf "   %s захват на туннеле: SYN-ACK через %s мс, TTL %s — пакеты «сервера» собирает локальный VPN-стек%s\n" "$(badge WARN)" "$P_RTT" "$P_TTLS" "$N"
        printf "          %sвыводы о RST/TTL/заморозке ниже описывают VPN, а не путь; захватывайте на физическом (en0)%s\n" "$D" "$N"
        count WARN "захват на туннеле — разбор pcap не отражает путь до сервера"
        det_ref
      fi
      if (( PCAP_LOCAL )); then
        printf "   • RST: %d, «вставленных» RST: %d, встали на 8–40 КБ: %d %s(на туннеле не показательно)%s\n" "${P_RST:-0}" "$P_INJ" "$P_FRZ" "$D" "$N"
      elif (( P_INJ > 0 )); then
        pcap_det
        printf "   %s RST с TTL, отличным от TTL сервера, в %d поток(ах) — сброс вставлен на пути (DPI / ТСПУ)\n" "$(badge FAIL)" "$P_INJ"; count FAIL "RST вставлен на пути (DPI / ТСПУ)"
        det_ref
      fi
      if (( P_NOS > 0 && ! PCAP_LOCAL )); then
        pcap_det
        printf "   %s %d из %d соединений без SYN-ACK — SYN теряются до TLS (канал / файрвол / VPN, не фильтр по имени)\n" "$(badge WARN)" "$P_NOS" "$P_N"; count WARN "SYN без SYN-ACK в захвате"
        det_ref
      fi
      if (( P_FRZ > 0 && ! PCAP_LOCAL )); then
        pcap_det
        printf "   %s %d поток(ов) встали на 8–40 КБ без FIN/RST — возможна «заморозка» ТСПУ\n" "$(badge WARN)" "$P_FRZ"; count WARN "«заморозка» потоков в захвате"
        det_ref
      fi
      (( P_RST > 0 && ! PCAP_LOCAL )) && printf "   • RST от самого сервера (TTL совпадает): %d — обычное закрытие, не вмешательство\n" "$P_RST"
      if (( PCAP_LOCAL )); then :
      elif (( P_INJ == 0 && P_NOS == 0 && P_FRZ == 0 )); then
        pcap_det
        printf "   %s признаков вмешательства в захвате нет\n" "$(badge OK)"; count OK
        det_ref
      fi
    fi
  fi
fi
