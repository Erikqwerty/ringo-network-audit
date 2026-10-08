# shellcheck shell=bash
# Захват на туннеле: TTL ровно 255 у «ответов сервера» или SYN-ACK быстрее 3 мс — пакеты собирает
# локальный VPN-стек, и выводы о RST/TTL/заморозке ниже описывают VPN. Итог: WARN. Задаёт PCAP_LOCAL.
[[ -n "$PCAP_FILE" && -s "$PCAP_FILE" && -n "${SRV_IP:-}" ]] || return 0
[[ "${P_N:-0}" != "0" ]] || return 0

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
