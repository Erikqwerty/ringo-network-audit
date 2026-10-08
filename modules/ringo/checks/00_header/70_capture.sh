# shellcheck shell=bash
# Захват tcpdump на время всех проверок (--capture). Останавливается и разбирается в разделе 80_pcap.
# Последний файл шапки — закрывает её чертой.

if (( CAPTURE )) && [[ -n "${SRV_IP:-}" ]]; then
  CAP_IFACE="${CAP_IFACE:-${RIF:-any}}"
  PCAP_FILE="${PCAP_FILE:-./ringo_audit_$(date +%Y%m%d_%H%M%S).pcap}"
  start_capture "$CAP_IFACE" "$PCAP_FILE" "$SRV_IP" && printf " Захват: %s → %s\n" "$CAP_IFACE" "$PCAP_FILE"
fi
# конец шапки
echo "${D}────────────────────────────────────────────────────────────────${N}"
