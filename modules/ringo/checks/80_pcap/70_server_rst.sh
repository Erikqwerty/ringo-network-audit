# shellcheck shell=bash
# RST от самого сервера (TTL совпадает) — обычное закрытие, не вмешательство. Справка без вердикта.
[[ -n "$PCAP_FILE" && -s "$PCAP_FILE" && -n "${SRV_IP:-}" ]] || return 0
[[ "${P_N:-0}" != "0" ]] || return 0

(( P_RST > 0 && ! PCAP_LOCAL )) && printf "   • RST от самого сервера (TTL совпадает): %d — обычное закрытие, не вмешательство\n" "$P_RST"
