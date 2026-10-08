# shellcheck shell=bash
# «Заморозка» потока: ТСПУ обрывает передачу после ~16 КБ (данные перестают идти, соединение висит).
# Качаем /agent/bundle (~800 КБ) дважды. Итог по попытке: OK — пришёл целиком; FAIL — встал на 8–40 КБ;
# WARN — прервался иначе; INFO — /agent/bundle не отдаётся (тест пропущен).
(( DPI_PROBE )) && [[ -n "${SRV_IP:-}" ]] || return 0

for attempt in 1 2; do
  prog "   %s…%s" "$D" "$N"
  fz=$(curl -sk -m 40 --speed-time 8 --speed-limit 1 -o /dev/null -w '%{http_code} %{size_download}' "$HOST/agent/bundle" 2>/dev/null); frc=$?
  det_new "DPI: поток /agent/bundle, попытка $attempt"
  det_kv "Как проверяется" "большой ответ (~800 КБ) должен прийти целиком; ТСПУ «замораживает» поток после ~16 КБ — данные перестают идти, соединение висит"
  det_cmd curl -sk -m 40 --speed-time 8 --speed-limit 1 -o /dev/null -w '%{http_code} %{size_download}' "$HOST/agent/bundle"
  det_kv "Результат" "HTTP ${fz:-000 0} байт, curl rc=$frc$( ((frc == 28)) && echo ' (остановился: 8 с без данных или таймаут 40 с)')"
  read -r fcode fsize <<<"${fz:-000 0}"
  clear_line
  fkb=$(( ${fsize%.*} / 1024 ))
  if (( frc == 0 )) && [[ "$fcode" == "200" ]]; then
    printf "   %s поток /agent/bundle: %d КБ без остановки %s(попытка %d)%s\n" "$(badge OK)" "$fkb" "$D" "$attempt" "$N"; count OK; det_ref
  elif (( frc == 28 && ${fsize%.*} >= 8000 && ${fsize%.*} <= 40000 )); then
    printf "   %s поток встал на %d КБ и висит — характерно для «заморозки» ТСПУ (~16 КБ) %s(попытка %d)%s\n" "$(badge FAIL)" "$fkb" "$D" "$attempt" "$N"; count FAIL "«заморозка» потока /agent/bundle"; det_ref
  elif [[ "$fcode" != "200" && "$fcode" != "000" ]]; then
    printf "   %s /agent/bundle отвечает %s — тест потока пропущен\n" "$(badge INFO)" "$fcode"; det_ref; break
  else
    printf "   %s поток прервался на %d КБ: %s %s(попытка %d)%s\n" "$(badge WARN)" "$fkb" "$(net_hint "$frc")" "$D" "$attempt" "$N"; count WARN "поток /agent/bundle прервался"; det_ref
  fi
done
