# shellcheck shell=bash
# Сводка захвата по TCP-потокам к серверу (pcap_stats в lib/capture.sh). Итог: WARN, если пакетов к серверу нет.
# Задаёт: P_N потоков, P_NOS без SYN-ACK, P_INJ с чужим RST, P_RST с RST сервера, P_FRZ вставших,
#         P_RTT мин. RTT рукопожатия, P_TTLS — TTL ответов; pcap_det — подробности для строк раздела.
[[ -n "$PCAP_FILE" && -s "$PCAP_FILE" && -n "${SRV_IP:-}" ]] || return 0

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
fi
