# shellcheck shell=bash
# Потоки встали на 8–40 КБ без FIN/RST и висели ≥ 5 с — возможна «заморозка» ТСПУ. Итог: WARN.
[[ -n "$PCAP_FILE" && -s "$PCAP_FILE" && -n "${SRV_IP:-}" ]] || return 0
[[ "${P_N:-0}" != "0" ]] || return 0

if (( P_FRZ > 0 && ! PCAP_LOCAL )); then
  pcap_det
  printf "   %s %d поток(ов) встали на 8–40 КБ без FIN/RST — возможна «заморозка» ТСПУ\n" "$(badge WARN)" "$P_FRZ"; count WARN "«заморозка» потоков в захвате"
  det_ref
fi
