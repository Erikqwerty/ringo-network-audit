# shellcheck shell=bash
# Раздел: вмешательство на пути (DPI / ТСПУ). Только с --dpi (или --capture) и если известен IP сервера.
(( DPI_PROBE )) && [[ -n "${SRV_IP:-}" ]] || return 0

echo
echo " ${BD}${B}▸ Вмешательство на пути (DPI / ТСПУ) — ${SRV_IP}:${SRV_PORT}${N}"
