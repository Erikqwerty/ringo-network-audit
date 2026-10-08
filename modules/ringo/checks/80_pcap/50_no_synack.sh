# shellcheck shell=bash
# Соединения без SYN-ACK — SYN теряются до TLS (канал / файрвол / VPN, не фильтр по имени). Итог: WARN.
[[ -n "$PCAP_FILE" && -s "$PCAP_FILE" && -n "${SRV_IP:-}" ]] || return 0
[[ "${P_N:-0}" != "0" ]] || return 0

if (( P_NOS > 0 && ! PCAP_LOCAL )); then
  pcap_det
  printf "   %s %d из %d соединений без SYN-ACK — SYN теряются до TLS (канал / файрвол / VPN, не фильтр по имени)\n" "$(badge WARN)" "$P_NOS" "$P_N"; count WARN "SYN без SYN-ACK в захвате"
  det_ref
fi
