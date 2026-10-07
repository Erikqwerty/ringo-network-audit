# shellcheck shell=bash
# Мониторинг «как mtr»: параллельные пробы целей, таблица в терминале.
# Подключается через source из audit.sh; сам не запускается.

# ---------- мониторинг (как mtr) ----------
MON_ROUNDS=${MON_ROUNDS:-0}; MON_STARTED=${MON_STARTED:-}; MON_ENDED=${MON_ENDED:-}
MON_DIR="${MON_DIR:-$LOGDIR/monitor}"
NC_G=(); [[ "$(uname -s)" == Darwin ]] && NC_G=(-G "$M_TIMEOUT")

# одна проба; пишет в $MON_DIR/t<idx>.log строку «раунд|время|статус|мс|подробности»
# статус: ok — ответ есть; err — ответ есть, но ошибка сервера (5xx); fail — ответа нет
mon_probe() {
  local i="$1" tg="$2" rnd="$3" st="ok" ms=0 det="" out rc code tc ta tf tt t0 h p stage
  case "$tg" in
    http://*|https://*)
      out=$(curl -skv -o /dev/null -m "$M_TIMEOUT" \
            -w '\nW %{http_code} %{time_connect} %{time_appconnect} %{time_starttransfer} %{time_total}\n' "$tg" 2>&1); rc=$?
      read -r _ code tc ta tf tt <<<"$(grep '^W ' <<<"$out" | tail -1)"
      ms=$(awk -v x="${tt:-0}" 'BEGIN{printf "%d", x*1000}')
      if [[ "${code:-000}" == "000" ]]; then
        st="fail"; stage="tcp"
        grep -q '^\* Connected to' <<<"$out" && stage="tls"
        grep -qiE 'Server hello|SSL connection using' <<<"$out" && stage="http"
        case "$rc:$stage" in
          6:*)    det="DNS не резолвится" ;;
          7:*)    det="TCP отклонён" ;;
          28:tcp) det="таймаут TCP (SYN без ответа)" ;;
          28:tls) det="таймаут TLS (нет ответа на ClientHello)" ;;
          28:*)   det="таймаут после TLS (нет HTTP-ответа)" ;;
          35:*)   det="обрыв TLS-рукопожатия" ;;
          52:*)   det="пустой ответ" ;;
          56:*)   det="сброс соединения (RST)" ;;
          *)      det="нет ответа (curl rc=$rc)" ;;
        esac
      else
        det="HTTP $code · TCP $(awk -v x="$tc" 'BEGIN{printf "%d", x*1000}') · TLS $(awk -v x="$ta" 'BEGIN{printf "%d", x*1000}') · 1-й байт $(awk -v x="$tf" 'BEGIN{printf "%d", x*1000}') мс"
        [[ "$code" =~ ^5 ]] && st="err"
      fi ;;
    ping:*)
      h="${tg#ping:}"
      if [[ "$(uname -s)" == Darwin ]]; then out=$(ping -n -c 1 -W $((M_TIMEOUT*1000)) "$h" 2>&1); rc=$?
      else out=$(ping -n -c 1 -W "$M_TIMEOUT" "$h" 2>&1); rc=$?; fi
      ms=$(sed -nE 's/.*time[=<]([0-9.]+) *ms.*/\1/p' <<<"$out" | head -1)
      if (( rc == 0 )) && [[ -n "$ms" ]]; then ms=${ms%.*}; det="ICMP ответ"
      else st="fail"; ms=0; det="ICMP без ответа (может быть закрыт файрволом)"; fi ;;
    *:*)
      h="${tg%:*}"; p="${tg##*:}"
      t0=$(now_ms)
      nc -z ${NC_G[@]+"${NC_G[@]}"} -w "$M_TIMEOUT" "$h" "$p" >/dev/null 2>&1; rc=$?
      ms=$(( $(now_ms) - t0 ))
      if (( rc == 0 )); then det="TCP открыт"
      elif (( ms >= M_TIMEOUT*1000 - 200 )); then st="fail"; det="таймаут TCP (SYN без ответа)"
      else st="fail"; det="TCP отклонён / DNS"; fi ;;
    *) st="fail"; det="неизвестный формат цели" ;;
  esac
  printf '%s|%s|%s|%s|%s\n' "$rnd" "$(date +%H:%M:%S)" "$st" "$ms" "$det" >>"$MON_DIR/t$i.log"
}

# статистика по логу цели: sent fail err loss% last avg best worst jitter | последний статус | детали | спарклайн
MON_STATS_AWK='
BEGIN { FS = "|"; split("▁ ▂ ▃ ▄ ▅ ▆ ▇ █", BAR, " ") }
{
  n++; st[n] = $3; v[n] = $4 + 0; det = $5; last_st = $3
  if ($3 == "fail") { f++ } else {
    if ($3 == "err") e++
    ok++; sum += $4; if (best == "" || $4 < best) best = $4; if ($4 > worst) worst = $4
    if (prev != "") { d = $4 - prev; jit += (d < 0 ? -d : d); jn++ }
    prev = $4; last = $4
  }
}
END {
  from = (n > W ? n - W + 1 : 1); mx = 0
  for (k = from; k <= n; k++) if (st[k] != "fail" && v[k] > mx) mx = v[k]
  sp = ""
  for (k = from; k <= n; k++) {
    if (st[k] == "fail") c = "×"
    else if (st[k] == "err") c = "!"
    else { lv = (mx > 0 ? int(v[k] / mx * 7.999) + 1 : 1); if (lv < 1) lv = 1; if (lv > 8) lv = 8; c = BAR[lv] }
    sp = sp c
  }
  printf "%d %d %d %.1f %s %s %s %s %s|%s|%s|%s\n", n, f + 0, e + 0, (n ? f * 100 / n : 0),
    (last_st == "fail" ? "-" : last), (ok ? int(sum / ok) : "-"), (best == "" ? "-" : best), (ok ? worst : "-"),
    (jn ? int(jit / jn) : "-"), last_st, det, sp
}'

mon_draw() { # таблица в стиле mtr
  local i tg line nums lst det sp n f e loss last avg best worst jit col
  (( ${#MON_T[@]} )) || return
  [[ -t 1 ]] && printf '\033[H\033[2J'
  printf "%s%sМониторинг%s — проб на цель ≥ %d · интервал %s с · таймаут %s с · %s · Ctrl-C — стоп и отчёт\n\n" \
    "$BD" "$B" "$N" "$MON_ROUNDS" "$M_INTERVAL" "$M_TIMEOUT" "$(date +%H:%M:%S)"
  printf "%s %-46s %5s %6s %6s %6s %6s %6s %6s  %s%s\n" "$BD" "Target" "Sent" "Loss%" "Last" "Avg" "Best" "Worst" "Jit" "History (ms)" "$N"
  for ((i=0; i<${#MON_T[@]}; i++)); do
    tg="${MON_T[$i]}"
    [[ -s "$MON_DIR/t$i.log" ]] || { printf " %-46s %s…%s\n" "${tg:0:46}" "$D" "$N"; continue; }
    line=$(awk -v W=40 "$MON_STATS_AWK" "$MON_DIR/t$i.log")
    IFS='|' read -r nums lst det sp <<<"$line"
    read -r n f e loss last avg best worst jit <<<"$nums"
    col="$G"; [[ "$loss" != "0.0" || "$e" != "0" ]] && col="$Y"; [[ "$lst" == "fail" ]] && col="$R"
    printf " %s%-46s%s %5s %s%6s%s %6s %6s %6s %6s %6s  %s\n" "$col" "${tg:0:46}" "$N" "$n" "$col" "$loss" "$N" \
      "$last" "$avg" "$best" "$worst" "$jit" "$sp"
    [[ "$lst" != "ok" ]] && printf "   %s↳ %s%s\n" "$D" "$det" "$N"
  done
  printf "\n %sгистограмма: ▁…█ — задержка относительно максимума окна, × — нет ответа, ! — ошибка 5xx%s\n" "$D" "$N"
}

if (( DO_MON )) && [[ -z "$REBUILD" ]]; then
  MON_T=(${M_TARGETS[@]+"${M_TARGETS[@]}"})
  if (( ${#MON_T[@]} == 0 )) || [[ -z "${MON_T[0]}" ]]; then
    MON_T=()
    if [[ -n "$RINGO_URL" ]]; then
      u="${RINGO_URL%/}"
      MON_T+=("$u/" "$u/scep?operation=GetCACaps" "$u/agent/manifest" "$u/socket.io/?EIO=4&transport=polling"
              "$(host_of "$u"):443" "ping:$(host_of "$u")")
    fi
    MON_T+=("courier.push.apple.com:5223" "api.push.apple.com:443" "albert.apple.com:443" "identity.apple.com:443")
  fi
  mkdir -p "$MON_DIR"; rm -f "$MON_DIR"/t*.log "$MON_DIR/stop"
  MON_STARTED="$(date '+%Y-%m-%d %H:%M:%S')"; MON_STOP=0; t_begin=$SECONDS

  # У каждой цели свой цикл (как в mtr): медленная или недоступная цель не задерживает остальные.
  # Фоновые процессы неинтерактивного bash игнорируют Ctrl-C — останавливаем их файлом-флагом.
  mon_worker() { # индекс, цель
    local k=0 t0 rest
    while [[ ! -f "$MON_DIR/stop" ]]; do
      ((k++)); t0=$(now_ms)
      mon_probe "$1" "$2" "$k"
      (( M_COUNT > 0 && k >= M_COUNT )) && break
      rest=$(awk -v i="$M_INTERVAL" -v el="$(( $(now_ms) - t0 ))" 'BEGIN{r=i-el/1000; printf "%.2f", (r>0?r:0)}')
      [[ -f "$MON_DIR/stop" ]] || sleep "$rest" 2>/dev/null
    done
  }
  min_sent() { # минимум проб среди целей — «раунд» для заголовка и --count
    local i c m=""
    for ((i=0; i<${#MON_T[@]}; i++)); do
      c=$(grep -c . "$MON_DIR/t$i.log" 2>/dev/null); c=${c:-0}
      [[ -z "$m" || "$c" -lt "$m" ]] && m=$c
    done
    echo "${m:-0}"
  }
  W_PIDS=()
  for ((i=0; i<${#MON_T[@]}; i++)); do mon_worker "$i" "${MON_T[$i]}" & W_PIDS+=($!); done

  trap 'MON_STOP=1' INT
  echo "${B}${BD}════ Мониторинг: ${#MON_T[@]} целей ════${N}"
  last_drawn=-1
  while (( ! MON_STOP )); do
    sleep "$M_INTERVAL" 2>/dev/null
    MON_ROUNDS=$(min_sent)
    if [[ -t 1 ]]; then mon_draw
    elif (( MON_ROUNDS != last_drawn )); then
      # без терминала — строка при каждом новом полном раунде: последний статус и задержка по целям
      printf "раунд %d %s:" "$MON_ROUNDS" "$(date +%H:%M:%S)"
      for ((i=0; i<${#MON_T[@]}; i++)); do printf " [%s]" "$(tail -1 "$MON_DIR/t$i.log" 2>/dev/null | cut -d'|' -f3,4)"; done; echo
    fi
    last_drawn=$MON_ROUNDS
    alive=0; for p in "${W_PIDS[@]}"; do kill -0 "$p" 2>/dev/null && alive=1; done
    (( alive )) || break                                   # все цели сделали --count проб
    (( M_DURATION > 0 && SECONDS - t_begin >= M_DURATION )) && break
  done
  : >"$MON_DIR/stop"
  trap - INT
  echo; echo "Останавливаю пробы (дождусь текущих, до ${M_TIMEOUT} с)…"
  wait "${W_PIDS[@]}" 2>/dev/null
  rm -f "$MON_DIR/stop"
  MON_ROUNDS=$(min_sent)
  MON_ENDED="$(date '+%Y-%m-%d %H:%M:%S')"
  printf '%s\n' "${MON_T[@]}" >"$MON_DIR/targets.txt"
  printf 'MON_STARTED=%q\nMON_ENDED=%q\nMON_ROUNDS=%q\nM_INTERVAL=%q\nM_TIMEOUT=%q\n' \
    "$MON_STARTED" "$MON_ENDED" "$MON_ROUNDS" "$M_INTERVAL" "$M_TIMEOUT" >"$MON_DIR/meta.txt"
  echo "Мониторинг остановлен: не меньше $MON_ROUNDS проб на цель."
fi
