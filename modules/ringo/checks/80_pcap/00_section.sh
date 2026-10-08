# shellcheck shell=bash
# Раздел: разбор захвата (--capture — свой, --pcap — готовый файл). Сначала останавливаем свой захват.

[[ -n "${CAP_PID:-}" ]] && sleep 2   # дать долететь FIN/RST последних соединений
stop_capture
[[ -n "$PCAP_FILE" ]] || return 0
echo
echo " ${BD}${B}▸ Разбор захвата: ${PCAP_FILE}${N}"
