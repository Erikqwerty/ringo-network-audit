# shellcheck shell=bash
# Проверка: реакция WAF на тестовые строки. Выполняется по порядку из modules/ringo/run.sh (source, общие переменные).

# ---------- WAF: реакция на типовые тестовые строки ----------
# По HTTPS содержимое запроса видит только тот, кто терминирует TLS (прокси / WAF сервера).
# Поэтому реакция именно на тестовую строку — признак защиты на стороне сервера, а не на пути (ТСПУ).
WAF_ACTIVE=""; WAF_HITS=0; WAF_TOTAL=0
blocker_of() { # сигнатура ответа -> кто заблокировал
  case "$1" in
    waf-block) echo "страница блокировки WAF" ;;
    app)       echo "само приложение Ringo" ;;
    nginx)     echo "nginx (правило / ModSecurity)" ;;
    curl-rc*)  echo "сброс соединения (inline WAF / IPS)" ;;
    *)         echo "не опознан" ;;
  esac
}
if (( WAF_PROBE )); then
  echo
  echo " ${BD}${B}▸ WAF: реакция на типовые тестовые строки${N}"
  probe_retry "/enroll?q=audit"
  B_CODE="$CODE"; B_STUB="$STUB"
  det_new "WAF: эталонный запрос"; det_probe "Эталон: безобидная строка"; det_probe_verdict "$STUB"
  case "$B_CODE" in
    000|401|403|429|502|503|504)
      WAF_ACTIVE="skip:эталонный запрос даёт $B_CODE — сравнение неинформативно"
      printf "   %s эталон /enroll?q=audit → %s — пробы пропущены\n" "$(badge INFO)" "$B_CODE"; det_ref ;;
    *)
      WAF_CASES=(
        "SQL-инъекция|/enroll?q=1%27%20OR%20%271%27%3D%271|"
        "XSS|/enroll?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E|"
        "обход каталогов|/enroll?q=..%2F..%2F..%2Fetc%2Fpasswd|"
        "User-Agent сканера|/enroll?q=audit|User-Agent: sqlmap/1.8"
      )
      k=0
      for c in "${WAF_CASES[@]}"; do
        IFS='|' read -r wname wpath whdr <<<"$c"; ((k++)); ((WAF_TOTAL++))
        prog "   %s(%d/%d)%s %s %s…%s" "$D" "$k" "${#WAF_CASES[@]}" "$N" "$wname" "$D" "$N"
        PROBE_HDR=(); [[ -n "$whdr" ]] && PROBE_HDR=(-H "$whdr")
        read -r wc _ _ wstub <<<"$(probe "$wpath")"
        PROBE_HDR=()
        det_new "WAF: $wname"
        det_kv "Как проверяется" "тот же путь, что у эталона, но с тестовой строкой; другой код (403/406/…) — реакция защиты на содержимое"
        det_kv "Эталон /enroll?q=audit" "$B_CODE ($B_STUB)"
        det_probe "Проба: $wname"; det_probe_verdict "$wstub"
        cp "$TMP" "$FPD/atk_$k.b" 2>/dev/null
        res="pass"; who=""
        if [[ "$wc" == "000" ]]; then
          # нет ответа на пробе — сразу повторяем эталон: если он проходит, реакция была на содержимое
          read -r bc _ _ _ <<<"$(probe "/enroll?q=audit")"
          if [[ "$bc" != "000" ]]; then res="hit"; who="$(blocker_of "$wstub")"; else res="flaky"; fi
        elif [[ "$wc" != "$B_CODE" && "$wc" =~ ^(403|406|418|429|444|451|501|503|999)$ ]]; then
          res="hit"; who="$(blocker_of "$wstub")"
        fi
        clear_line
        case "$res" in
          hit)   ((WAF_HITS++))
                 printf "   %s %s%3s%s  %s — %sзаблокировано: %s%s\n" "$(badge INFO)" "$BD" "$wc" "$N" "$wname" "$Y" "$who" "$N" ;;
          flaky) printf "   %s %s%3s%s  %s — %sнет ответа и на эталоне: канал нестабилен, не определить%s\n" "$(badge WARN)" "$BD" "$wc" "$N" "$wname" "$D" "$N"; count WARN "WAF-проба: канал нестабилен" ;;
          *)     printf "   %s %s%3s%s  %s — %sпропущено (как эталон, %s)%s\n" "$(badge INFO)" "$BD" "$wc" "$N" "$wname" "$D" "$B_CODE" "$N" ;;
        esac
        det_ref
      done
      if (( WAF_HITS )); then WAF_ACTIVE="hit:заблокировано $WAF_HITS из $WAF_TOTAL категорий"
      else WAF_ACTIVE="none:ни одна из $WAF_TOTAL категорий не заблокирована"; fi ;;
  esac
fi
