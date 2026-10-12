# shellcheck shell=bash
# Сравнение двух запусков (--diff A B): только то, что различается. Типичные пары: изнутри сети и снаружи,
# хост администратора и Wi-Fi устройств, до и после правки прокси, рабочий сервер и проблемный.
# Подключается через source из audit.sh. Пишет diff.html в папку B (или --report).
#
# Строки сопоставляются по заголовку подробностей проверки (details/…/NNN.txt): он не зависит от
# результата («Цепочка сертификатов», «PUT /mdm/checkin — …», «albert.apple.com:443»). Без подробностей —
# по тексту строки без чисел. Повторы одного заголовка нумеруются по порядку.

# лог модуля -> «раздел|ключ|статус|текст» по строке на проверку
# (порядок «хуже стало в B — выше»: сначала ухудшения, затем улучшения; строки, которых нет в одном из запусков, — нейтральные)
diff_rows() { # лог
  awk -v LD="$(dirname "$1")" '
    function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }
    function flush(   k) {
      if (st == "") return
      # эндпоинт — по «МЕТОД путь»: в разных версиях Ringo заголовок подробностей у него разный
      if (match(txt, /^(GET|PUT|POST|PATCH|DELETE|HEAD) +[^ ]+/)) { k = substr(txt, 1, RLENGTH); gsub(/ +/, " ", k) }
      else { k = (title != "" ? title : txt); if (title == "") gsub(/[0-9]+/, "#", k) }
      n[sec "|" k]++; if (n[sec "|" k] > 1) k = k " (" n[sec "|" k] ")"
      gsub(/\|/, "/", k); gsub(/\|/, "/", txt)
      print sec "|" k "|" st "|" txt
      st = ""; title = ""; txt = ""
    }
    { l = trim($0) }
    # раздел без адреса и длительности: «DPI — 1.2.3.4:443», «удержание (120 с)» у разных запусков совпадают
    index(l, "▸ ") == 1 { flush(); sec = substr(l, length("▸ ") + 1); sub(/ — [0-9a-fA-F.:]+$/, "", sec); sub(/ \([0-9]+ с\)$/, "", sec); next }
    l ~ /^Вердикт по ключевым/ { flush(); sec = l; next }
    match(l, /^\[( OK |INFO|WARN|FAIL)\]/) { flush(); st = trim(substr(l, 2, 4)); txt = trim(substr(l, 7)); gsub(/ +/, " ", txt); next }
    index(l, "↳ подробнее: ") == 1 && st != "" {
      f = LD "/" substr(l, length("↳ подробнее: ") + 1)
      if ((getline t < f) > 0 && t ~ /^# /) title = substr(t, 3); close(f)
      next
    }
    END { flush() }
  ' "$1"
}
# шапка модуля Ringo -> «ключ|значение» (Хост, Режим, IP, Ваш IP, Маршрут, Ringo…)
diff_meta() { # лог
  awk '/────/ { d++; next } d == 1 && match($0, /^ [^ :][^:]*: +/) { k = substr($0, 2, RLENGTH - 1); sub(/: +$/, "", k); v = substr($0, RLENGTH + 1); print k "|" v }' "$1"
}
diff_log_of() { # папка запуска, модуль -> путь к логу
  local f="$1/results.txt" name log
  [[ -f "$f" ]] || return 0
  while IFS='|' read -r name log _; do
    [[ "$name" == "$2" ]] || continue
    [[ -f "$log" ]] || log="$1/$(basename "$log")"
    [[ -f "$log" ]] && echo "$log"; return 0
  done <"$f"
}
diff_label() { # папка запуска -> короткая подпись (хост · режим · дата)
  local log host mode date
  log="$(diff_log_of "$1" "Ringo MDM: эндпоинты")"
  if [[ -n "$log" ]]; then
    host=$(sed -nE 's/^ *Хост: *//p' "$log" | head -1); mode=$(sed -nE 's/^ *Режим: *//p' "$log" | head -1)
  fi
  date=$( [[ -f "$1/run.txt" ]] && sed -nE "s/^RUN_DATE=//p" "$1/run.txt" | tr -d "\\\\'" )
  echo "${host:-$(basename "$1")}${mode:+ · $mode}${date:+ · $date}"
}

build_diff() { # папка A, папка B, файл html
  local A="$1" B="$2" OUT="$3" la lb name mods=() m ra rb sec key sa ta sb tb x cls same diffn total_diff=0
  local labA labB
  labA="$(diff_label "$A")"; labB="$(diff_label "$B")"
  # модули, которые есть хотя бы в одном запуске
  for x in "$A" "$B"; do
    [[ -f "$x/results.txt" ]] || continue
    while IFS='|' read -r name _; do [[ -n "$name" && " ${mods[*]:-} " != *" $name "* ]] && mods+=("$name"); done <"$x/results.txt"
  done
  sev() { case "$1" in FAIL) echo 3 ;; WARN) echo 2 ;; INFO) echo 1 ;; OK) echo 0 ;; *) echo -1 ;; esac; }
  cell() { # статус, текст
    if [[ -z "$1" ]]; then printf '<td class="dna">нет такой проверки</td>'
    else printf '<td><span class="pill %s">%s</span> %s</td>' "$(tr 'A-Z' 'a-z' <<<"$1")" "$1" "$(html_esc <<<"$2")"; fi
  }
  {
  cat <<'HTML'
<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>Сравнение аудитов</title>
<style>
HTML
  cat "$ROOT/report/style.css"
  cat <<'HTML'
</style>
</head>
<body>
<header class="bar"><div class="wrap"><div class="brand"><div class="logo" aria-hidden="true"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><path d="M3 12h4l3-8 4 16 3-8h4"/></svg></div><span>Сравнение аудитов</span></div></div></header>
<main class="wrap">
HTML
  printf '<section class="hero diffhero"><div><h1>Что различается</h1><ul class="facts dfacts"><li><span class="tag">A</span><b>%s</b></li><li><span class="tag">B</span><b>%s</b></li></ul>\n' \
    "$(html_esc <<<"$labA")" "$(html_esc <<<"$labB")"
  printf '<div class="cmd">A: %s<br>B: %s</div></div></section>\n' "$(html_esc <<<"$A")" "$(html_esc <<<"$B")"

  # шапка Ringo: адреса, режим, маршрут — часто причина различий именно здесь
  la="$(diff_log_of "$A" "Ringo MDM: эндпоинты")"; lb="$(diff_log_of "$B" "Ringo MDM: эндпоинты")"
  if [[ -n "$la" && -n "$lb" ]]; then
    printf '<article class="module"><header><h2>Условия запуска</h2></header><div class="mbody"><div class="tblwrap"><table class="dtbl dmeta"><thead><tr><th>Параметр</th><th>A</th><th>B</th></tr></thead><tbody>\n'
    { diff_meta "$la" | sed 's/^/A|/'; diff_meta "$lb" | sed 's/^/B|/'; } | awk -F'|' '
      { k = $2; v = $3; for (i = 4; i <= NF; i++) v = v "|" $i; if (!(k in seen)) { seen[k] = 1; ord[++n] = k } val[$1, k] = v }
      END { for (i = 1; i <= n; i++) { k = ord[i]; print k "|" val["A", k] "|" val["B", k] } }' |
    while IFS='|' read -r key ta tb; do
      [[ "$key" == Дата ]] && continue
      cls=""; [[ "$ta" != "$tb" ]] && cls=' class="chg"'
      printf '<tr%s><td>%s</td><td>%s</td><td>%s</td></tr>\n' "$cls" "$(html_esc <<<"$key")" "$(html_esc <<<"${ta:-—}")" "$(html_esc <<<"${tb:-—}")"
    done
    printf '</tbody></table></div></div></article>\n'
  fi

  for m in ${mods[@]+"${mods[@]}"}; do
    la="$(diff_log_of "$A" "$m")"; lb="$(diff_log_of "$B" "$m")"
    ra="$( [[ -n "$la" ]] && diff_rows "$la" | sed 's/^/A|/')"; rb="$( [[ -n "$lb" ]] && diff_rows "$lb" | sed 's/^/B|/')"
    # «раздел|ключ|статус A|текст A|статус B|текст B» в порядке первого появления
    local merged
    merged=$(printf '%s\n%s\n' "$ra" "$rb" | grep . | awk -F'|' '
      { k = $2 "|" $3; if (!(k in seen)) { seen[k] = 1; ord[++n] = k } st[$1, k] = $4; tx[$1, k] = $5 }
      END { for (i = 1; i <= n; i++) { k = ord[i]; print k "|" st["A", k] "|" tx["A", k] "|" st["B", k] "|" tx["B", k] } }')
    diffn=$(awk -F'|' '$3 != $5' <<<"$merged" | grep -c .)
    same=$(awk -F'|' '$3 == $5' <<<"$merged" | grep -c .)
    total_diff=$((total_diff + diffn))
    printf '<article class="module"><header><h2>%s</h2><span class="pill %s">%s</span></header><div class="mbody">\n' \
      "$(html_esc <<<"$m")" "$( ((diffn)) && echo warn || echo ok)" "$( ((diffn)) && echo "различий: $diffn" || echo "одинаково")"
    [[ -z "$la" ]] && printf '<p class="lead">В запуске A этого модуля нет.</p>\n'
    [[ -z "$lb" ]] && printf '<p class="lead">В запуске B этого модуля нет.</p>\n'
    if (( diffn )); then
      printf '<div class="tblwrap"><table class="dtbl"><thead><tr><th>Раздел</th><th>Проверка</th><th>A</th><th>B</th></tr></thead><tbody>\n'
      # хуже стало в B — выше
      while IFS='|' read -r sec key sa ta sb tb; do
        x=$(( $(sev "$sb") - $(sev "$sa") ))
        printf '%s|%s|%s|%s|%s|%s|%s\n' "$((10 - x))" "$sec" "$key" "$sa" "$ta" "$sb" "$tb"
      done < <(awk -F'|' '$3 != $5' <<<"$merged") | sort -t'|' -s -k1,1n |
      while IFS='|' read -r _ sec key sa ta sb tb; do
        cls="better"; (( $(sev "$sb") > $(sev "$sa") )) && cls="worse"; [[ -z "$sa" || -z "$sb" ]] && cls="only"
        printf '<tr class="%s"><td>%s</td><td>%s</td>%s%s</tr>\n' "$cls" "$(html_esc <<<"$sec")" "$(html_esc <<<"$key")" "$(cell "$sa" "$ta")" "$(cell "$sb" "$tb")"
      done
      printf '</tbody></table></div>\n'
    fi
    if (( same )); then
      printf '<details class="raw"><summary>Совпадает: %d</summary><div class="tblwrap"><table class="dtbl"><tbody>\n' "$same"
      awk -F'|' '$3 == $5' <<<"$merged" | while IFS='|' read -r sec key sa ta _ _; do
        printf '<tr><td>%s</td><td>%s</td>%s</tr>\n' "$(html_esc <<<"$sec")" "$(html_esc <<<"$key")" "$(cell "$sa" "$ta")"
      done
      printf '</tbody></table></div></details>\n'
    fi
    printf '</div></article>\n'
  done
  printf '<footer><span>Сформировано %s</span></footer>\n</main>\n</body>\n</html>\n' "$(date '+%Y-%m-%d %H:%M:%S')"
  } >"$OUT"
  echo "Различий в проверках: $total_diff"
}
