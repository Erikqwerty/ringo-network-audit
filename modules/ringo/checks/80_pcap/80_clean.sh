# shellcheck shell=bash
# Признаков вмешательства в захвате нет. Итог: OK (на туннеле не выносится).
[[ -n "$PCAP_FILE" && -s "$PCAP_FILE" && -n "${SRV_IP:-}" ]] || return 0
[[ "${P_N:-0}" != "0" ]] || return 0

if (( PCAP_LOCAL )); then :
elif (( P_INJ == 0 && P_NOS == 0 && P_FRZ == 0 )); then
  pcap_det
  printf "   %s признаков вмешательства в захвате нет\n" "$(badge OK)"; count OK
  det_ref
fi
