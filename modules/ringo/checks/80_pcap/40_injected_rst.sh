# shellcheck shell=bash
# RST с TTL, отличным от TTL сервера, — сброс вставлен на пути (DPI / ТСПУ). Итог: FAIL.
# На туннеле не показательно — только справочная строка.
[[ -n "$PCAP_FILE" && -s "$PCAP_FILE" && -n "${SRV_IP:-}" ]] || return 0
[[ "${P_N:-0}" != "0" ]] || return 0

if (( PCAP_LOCAL )); then
  printf "   • RST: %d, «вставленных» RST: %d, встали на 8–40 КБ: %d %s(на туннеле не показательно)%s\n" "${P_RST:-0}" "$P_INJ" "$P_FRZ" "$D" "$N"
elif (( P_INJ > 0 )); then
  pcap_det
  printf "   %s RST с TTL, отличным от TTL сервера, в %d поток(ах) — сброс вставлен на пути (DPI / ТСПУ)\n" "$(badge FAIL)" "$P_INJ"; count FAIL "RST вставлен на пути (DPI / ТСПУ)"
  det_ref
fi
