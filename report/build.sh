# shellcheck shell=bash
# HTML-отчёт из текстовых логов модулей. Подключается через source из audit.sh.
# Отчёт — один самодостаточный файл: стили (style.css) и скрипт (app.js) встраиваются при сборке.
# Разбор строк вывода — см. контракт формата в lib/ui.sh.

# Отчёт — один самодостаточный файл без внешних зависимостей (работает офлайн).
# bash отдаёт семантическую разметку; счётчики разделов, блок «Главное», фильтры и поиск строит JS.
html_esc() { sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g'; }

# текстовый вывод модуля -> HTML-фрагмент. $2 — префикс id (якоря для ссылок из «Главного»)
render_module() { # лог, префикс
  awk -v P="$2" -v LD="$(dirname "$1")" '
    function esc(s) { gsub(/&/, "\\&amp;", s); gsub(/</, "\\&lt;", s); gsub(/>/, "\\&gt;", s); gsub(/"/, "\\&quot;", s); return s }
    # ---- подробности проверки (файл details/…/NNN.txt, формат — lib/detail.sh) -> <template class="det"> ----
    function d_flush() {
      if (d_kv != "")  { d_out = d_out "<dl class=\"dkv\">" d_kv "</dl>"; d_kv = "" }
      if (d_pre != "") { sub(/\n$/, "", d_pre); d_out = d_out "<pre class=\"dout\">" d_pre "</pre>"; d_pre = "" }
    }
    function d_close() { d_flush(); if (d_sec) { d_out = d_out "</section>"; d_sec = 0 } }
    function d_line(l, hdr,   k) {   # строка вывода; в разделах запроса/ответа подсвечиваем заголовки HTTP
      if (hdr && match(l, /^HTTP\/[0-9.]+ [0-9][0-9][0-9]/)) return "<span class=\"hs\">" esc(l) "</span>"
      if (hdr && match(l, /^[A-Za-z0-9-]+: /)) { k = substr(l, 1, RLENGTH - 2); return "<span class=\"hk\">" esc(k) "</span>: " esc(substr(l, RLENGTH + 1)) }
      return esc(l)
    }
    function det_html(f,   l, title, hdr, n) {
      d_out = ""; d_kv = ""; d_pre = ""; d_sec = 0; title = ""; hdr = 0; n = 0
      while ((getline l < f) > 0) {
        n++
        if (n == 1 && l ~ /^# /) { title = substr(l, 3); continue }
        if (l ~ /^## /) {
          d_close(); d_sec = 1; hdr = (l ~ /^## (Запрос|Ответ|Эталон|Проба|Контроль)/)
          d_out = d_out "<section class=\"dsec\"><h4>" esc(substr(l, 4)) "</h4>"; continue
        }
        if (!d_sec) { d_out = d_out "<section class=\"dsec dlead\">"; d_sec = 1 }
        if (l ~ /^\$ /) { d_flush(); d_out = d_out "<div class=\"dcmd\"><code>" esc(substr(l, 3)) "</code><button type=\"button\" class=\"dcopy\" title=\"Копировать команду\" aria-label=\"Копировать команду\"></button></div>"; continue }
        if (match(l, /^= [^:]+: /)) {
          if (d_pre != "") d_flush()
          d_kv = d_kv "<div><dt>" esc(substr(l, 3, RLENGTH - 4)) "</dt><dd>" esc(substr(l, RLENGTH + 1)) "</dd></div>"; continue
        }
        if (d_kv != "") d_flush()
        d_pre = d_pre d_line(l, hdr) "\n"
      }
      close(f); d_close()
      if (n == 0) return ""
      return "<template class=\"det\" data-title=\"" esc(title) "\">" d_out "</template>"
    }
    function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }
    function close_row() { if (rowopen) { print "</div></div>"; rowopen = 0 } }
    function close_sec() { close_row(); if (insec) { print "</div></details>"; insec = 0 } }
    function open_sec(t) {
      close_sec(); ns++
      print "<details class=\"sec\" open id=\"" P "-s" ns "\"><summary><span class=\"chev\" aria-hidden=\"true\"></span><h3>" esc(t) "</h3><span class=\"counts\"></span></summary><div class=\"rows\">"
      insec = 1; anysec = 1
    }
    function codecls(c) { return (c ~ /^2/ ? "c2" : c ~ /^3/ ? "c3" : c ~ /^4/ ? "c4" : c ~ /^5/ ? "c5" : "c0") }
    # строка с бейджем: пытаемся разложить на колонки
    function row(cls, t,    meth, path, code, sz, ms, hp, ip, title, body, m) {
      close_row(); nr++
      body = ""; title = ""
      if (match(t, /^(GET|PUT|POST|HEAD|PATCH|DELETE) +/)) {              # эндпоинт Ringo
        meth = trim(substr(t, 1, RLENGTH)); t = substr(t, RLENGTH + 1)
        match(t, /^[^ ]+/); path = substr(t, 1, RLENGTH); t = trim(substr(t, RLENGTH + 1))
        code = ""; sz = ""; ms = ""
        if (match(t, /^[0-9][0-9][0-9]( +|$)/)) { code = trim(substr(t, 1, RLENGTH)); t = trim(substr(t, RLENGTH + 1)) }
        if (match(t, /^[0-9]+B( +|$)/))        { sz = trim(substr(t, 1, RLENGTH)); sub(/B$/, " Б", sz); t = trim(substr(t, RLENGTH + 1)) }
        if (match(t, /^(-|[0-9]+)ms( +|$)/))   { ms = trim(substr(t, 1, RLENGTH)); sub(/ms$/, " мс", ms); t = trim(substr(t, RLENGTH + 1)) }
        title = meth " " path
        body = "<div class=\"body ep\"><span class=\"meth m-" tolower(meth) "\">" meth "</span><code class=\"path\">" esc(path) "</code>" \
               (code != "" ? "<span class=\"code " codecls(code) "\">" code "</span>" : "<span></span>") \
               "<span class=\"num\">" esc(sz) "</span><span class=\"num\">" esc(ms) "</span><span class=\"msg\">" esc(t) "</span>"
      } else if (match(t, /^[A-Za-z0-9.-]+:[0-9]+ +/)) {                    # хост:порт (Apple)
        hp = trim(substr(t, 1, RLENGTH)); t = substr(t, RLENGTH + 1)
        ip = ""; if (match(t, /^ *([0-9][0-9.]*|-) +/)) { ip = trim(substr(t, 1, RLENGTH)); t = substr(t, RLENGTH + 1) }
        title = hp
        body = "<div class=\"body hp\"><code class=\"path\">" esc(hp) "</code><span class=\"ip\">" esc(ip == "-" ? "" : ip) "</span><span class=\"msg\">" esc(trim(t)) "</span>"
      } else if (match(t, /^[0-9][0-9][0-9]  /)) {                          # «код  описание» (пробы WAF, тела устройств)
        code = substr(t, 1, 3); t = trim(substr(t, 4))
        body = "<div class=\"body cm\"><span class=\"code " codecls(code) "\">" code "</span><span class=\"msg\">" esc(t) "</span>"
      } else {
        body = "<div class=\"body\"><span class=\"msg\">" esc(t) "</span>"
      }
      if (!insec) open_sec("Проверки")
      printf "<div class=\"row %s\" id=\"%s-r%d\" data-s=\"%s\" data-t=\"%s\"><span class=\"ic\" aria-label=\"%s\"></span>%s", cls, P, nr, cls, esc(title), toupper(cls), body
      rowopen = 1
    }
    index($0, "────") { div++; next }
    div < 2 {                                    # шапка модуля: «Ключ: значение»
      l = trim($0); if (l == "" || !seen_title) { if (l != "") seen_title = 1; next }
      if (match(l, /^[^:]+: +/)) { k = substr(l, 1, RLENGTH); v = substr(l, RLENGTH + 1); sub(/: +$/, "", k)
        meta = meta "<div><dt>" esc(k) "</dt><dd>" esc(v) "</dd></div>" }
      else notes = notes "<li>" esc(l) "</li>"
      next
    }
    !printed_meta {
      if (meta != "") print "<dl class=\"meta\">" meta "</dl>"
      if (notes != "") print "<ul class=\"notes\">" notes "</ul>"
      printed_meta = 1
    }
    /Итого:/ { next }
    { raw = $0; l = trim($0); was_sub = prev_sub; prev_sub = 0 }
    l == "" { next }
    index(l, "▸ ") == 1 { open_sec(substr(l, length("▸ ") + 1)); next }
    l ~ /^Вердикт по ключевым/ { open_sec(l); next }
    match(l, /^\[( OK |INFO|WARN|FAIL)\]/) { b = trim(substr(l, 2, 4)); row(tolower(b), trim(substr(l, 7))); next }
    index(l, "↳ подробнее: ") == 1 {             # ссылка на подробности — не заметка, а содержимое окна «Подробнее»
      prev_sub = 1; f = substr(l, length("↳ подробнее: ") + 1)
      if (rowopen) print det_html(LD "/" f)
      next
    }
    index(l, "↳") == 1 {
      sub(/^↳ */, "", l); prev_sub = 1
      if (raw !~ /^      /) close_row()             # «   ↳» — пояснение ко всему разделу, «          ↳» — к строке
      if (rowopen) print "<div class=\"note\">" esc(l) "</div>"; else { if (!insec) open_sec("Сведения"); print "<div class=\"hint\">" esc(l) "</div>" }
      next
    }
    was_sub && raw ~ /^     / { prev_sub = 1; if (rowopen) print "<div class=\"note\">" esc(l) "</div>"; else print "<div class=\"hint\">" esc(l) "</div>"; next }
    index(l, "•") == 1 {
      close_row(); sub(/^• */, "", l); if (!insec) open_sec("Сведения")
      if (match(l, /^[^:]+: */)) { k = substr(l, 1, RLENGTH); v = substr(l, RLENGTH + 1); sub(/: *$/, "", k)
        print "<div class=\"kv\"><span class=\"k\">" esc(k) "</span><span class=\"v\">" esc(v) "</span></div>" }
      else print "<div class=\"kv\"><span class=\"v\">" esc(l) "</span></div>"
      next
    }
    l ~ /^(Есть |Соответствует|Сетевое окружение)/ { next }       # итог модуля показан в шапке карточки
    !anysec { print "<p class=\"lead\">" esc(l) "</p>"; next }
    { close_row(); if (!insec) open_sec("Прочее"); print "<div class=\"hint\">" esc(l) "</div>" }
    END {
      if (!printed_meta) { if (meta != "") print "<dl class=\"meta\">" meta "</dl>"; if (notes != "") print "<ul class=\"notes\">" notes "</ul>" }
      close_sec()
    }
  ' "$1"
}

# SVG-график задержки: область под линией, красные полосы — потери, точки — 5xx
render_spark_svg() { # лог
  awk -F'|' '
    { n++; st[n] = $3; v[n] = $4 + 0; if ($3 != "fail" && v[n] > mx) mx = v[n] }
    END {
      w = 600; h = 64; top = 6; if (mx <= 0) mx = 1
      dx = (n < 2 ? 0 : w / (n - 1))
      printf "<svg class=\"spark\" viewBox=\"0 0 %d %d\" preserveAspectRatio=\"none\" role=\"img\" aria-label=\"задержка по времени, максимум %d мс\">", w, h, mx
      for (k = 1; k <= n; k++) if (st[k] == "fail") {
        x = (n < 2 ? w / 2 : (k - 1) * dx); bw = (dx > 3 ? dx : 3)
        printf "<rect class=\"loss\" x=\"%.1f\" y=\"0\" width=\"%.1f\" height=\"%d\"/>", x - bw / 2, bw, h
      }
      seg = ""; first = ""
      for (k = 1; k <= n + 1; k++) {
        if (k <= n && st[k] != "fail") {
          x = (n < 2 ? w / 2 : (k - 1) * dx); y = top + (h - top) - v[k] / mx * (h - top - 2)
          if (seg == "") first = x
          seg = seg sprintf("%.1f,%.1f ", x, y); lastx = x
        } else if (seg != "") {
          printf "<polygon class=\"area\" points=\"%.1f,%d %s%.1f,%d\"/>", first, h, seg, lastx, h
          printf "<polyline points=\"%s\"/>", seg; seg = ""
        }
      }
      for (k = 1; k <= n; k++) if (st[k] == "err") {
        x = (n < 2 ? w / 2 : (k - 1) * dx); y = top + (h - top) - v[k] / mx * (h - top - 2)
        printf "<circle class=\"err\" cx=\"%.1f\" cy=\"%.1f\" r=\"3\"/>", x, y
      }
      printf "</svg>"
    }' "$1"
}

build_report() {
  local worst_rc=0 t_ok=0 t_info=0 t_warn=0 t_fail=0 r name log rc sums params o i w f cls mi total
  local verdict_cls verdict_txt dur mon_issue=0
  for r in ${RESULTS[@]+"${RESULTS[@]}"}; do
    IFS='|' read -r name log rc sums params <<<"$r"
    read -r o i w f <<<"${sums:-0 0 0 0}"
    t_ok=$((t_ok + ${o:-0})); t_info=$((t_info + ${i:-0})); t_warn=$((t_warn + ${w:-0})); t_fail=$((t_fail + ${f:-0}))
    (( rc > worst_rc && rc <= 2 )) && worst_rc=$rc
  done
  if (( DO_MON )) && [[ -d "$MON_DIR" ]]; then
    for ((i=0; i<${#MON_T[@]}; i++)); do
      [[ -s "$MON_DIR/t$i.log" ]] && awk -F'|' '$3 != "ok" {x=1} END{exit !x}' "$MON_DIR/t$i.log" && mon_issue=1
    done
    (( mon_issue && worst_rc == 0 )) && worst_rc=1
  fi
  case "$worst_rc" in
    0) verdict_cls=ok;   verdict_txt="Всё в порядке" ;;
    1) verdict_cls=warn; verdict_txt="Есть замечания" ;;
    *) verdict_cls=fail; verdict_txt="Есть проблемы" ;;
  esac
  dur=${RUN_DUR:-$((SECONDS - RUN_T0))}; dur="$((dur / 60)) мин $((dur % 60)) с"
  total=$((t_ok + t_info + t_warn + t_fail))

  {
  cat <<'HTML'
<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>Сетевой аудит Ringo</title>
<style>
HTML
  cat "$ROOT/report/style.css"
  cat <<'HTML'
</style>
</head>
<body data-f="all">
<header class="bar"><div class="wrap">
  <div class="brand"><div class="logo" aria-hidden="true"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><path d="M3 12h4l3-8 4 16 3-8h4"/></svg></div><span>Сетевой аудит</span></div>
  <nav class="nav" id="nav"></nav>
  <div class="tools">
    <label class="search"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg>
      <input id="q" type="search" placeholder="Поиск" aria-label="Поиск по отчёту" autocomplete="off"><kbd>/</kbd></label>
    <div class="seg" role="group" aria-label="Фильтр">
      <button data-f="all" aria-pressed="true">Все</button><button data-f="issues" aria-pressed="false">Проблемы</button><button data-f="fail" aria-pressed="false">FAIL</button>
    </div>
    <button class="iconbtn" id="fold" title="Свернуть / развернуть разделы" aria-label="Свернуть или развернуть разделы"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="m7 15 5 5 5-5M7 9l5-5 5 5"/></svg></button>
    <button class="iconbtn" id="theme" aria-label="Тема"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M12 3a9 9 0 0 0 0 18z" fill="currentColor"/></svg></button>
  </div>
</div></header>
<main class="wrap">
HTML
  # --- шапка с вердиктом ---
  local p1 p2 p3 hostn
  if (( total > 0 )); then
    p1=$(awk -v a="$t_fail" -v t="$total" 'BEGIN{printf "%.2f", a*100/t}')
    p2=$(awk -v a="$((t_fail+t_warn))" -v t="$total" 'BEGIN{printf "%.2f", a*100/t}')
    p3=$(awk -v a="$((t_fail+t_warn+t_info))" -v t="$total" 'BEGIN{printf "%.2f", a*100/t}')
  else p1=0; p2=0; p3=0; fi
  hostn="$(hostname 2>/dev/null | html_esc)"
  printf '<section class="hero %s"><div>\n' "$verdict_cls"
  printf '<span class="status"><span class="dot"></span>%s</span>\n' "$verdict_txt"
  printf '<h1>%s</h1>\n' "$( [[ -n "$RINGO_URL" ]] && html_esc <<<"$(host_of "$RINGO_URL")" || echo "Сеть Apple MDM" )"
  printf '<ul class="facts"><li>Дата <b>%s</b></li><li>Длительность <b>%s</b></li><li>Запущено на <b>%s</b></li><li>Модулей <b>%d</b></li></ul>\n' \
    "$RUN_DATE" "$dur" "$hostn" "$(( ${#RESULTS[@]} + DO_MON ))"
  printf '<div class="cmd">$ %s %s</div>\n' "$(basename "$0")" "$(html_esc <<<"${ORIG_ARGS:-(меню)}")"
  printf '</div>'
  if (( total > 0 )); then
    printf '<div class="ring" style="--p1:%s;--p2:%s;--p3:%s" role="img" aria-label="OK %d, INFO %d, WARN %d, FAIL %d"><span><b>%d</b>проверок</span></div>' \
      "$p1" "$p2" "$p3" "$t_ok" "$t_info" "$t_warn" "$t_fail" "$total"
  fi
  printf '</section>\n'
  if (( total > 0 )); then
    printf '<div class="stats">'
    printf '<button class="stat fail" data-go="fail"><div class="n">%d</div><div class="l">FAIL — блокирует работу</div></button>' "$t_fail"
    printf '<button class="stat warn" data-go="issues"><div class="n">%d</div><div class="l">WARN — замечания</div></button>' "$t_warn"
    printf '<button class="stat info" data-go="all"><div class="n">%d</div><div class="l">INFO — к сведению</div></button>' "$t_info"
    printf '<button class="stat ok" data-go="all"><div class="n">%d</div><div class="l">OK</div></button>' "$t_ok"
    printf '</div>\n'
    printf '<section class="panel" id="main-findings"><h2>Главное</h2><div class="findings" id="findings"></div></section>\n'
  fi

  # --- модули ---
  mi=0
  for r in ${RESULTS[@]+"${RESULTS[@]}"}; do
    IFS='|' read -r name log rc sums params <<<"$r"
    ((mi++))
    case "$rc" in 0) cls=ok; o="соответствует" ;; 1) cls=warn; o="есть замечания" ;; *) cls=fail; o="есть проблемы" ;; esac
    read -r o2 i2 w2 f2 <<<"${sums:-0 0 0 0}"
    printf '<article class="module" id="m%d" data-name="%s"><header><h2>%s</h2><span class="pill %s">%s</span>' \
      "$mi" "$(html_esc <<<"$name")" "$(html_esc <<<"$name")" "$cls" "$o"
    printf '<span class="mcounts">%s%s%s%s</span></header>\n' \
      "$( (( ${f2:-0} )) && printf '<span class="cnt fail" title="FAIL">%d</span>' "$f2")" \
      "$( (( ${w2:-0} )) && printf '<span class="cnt warn" title="WARN">%d</span>' "$w2")" \
      "$( (( ${i2:-0} )) && printf '<span class="cnt info" title="INFO">%d</span>' "$i2")" \
      "$( (( ${o2:-0} )) && printf '<span class="cnt ok" title="OK">%d</span>' "$o2")"
    printf '<div class="mbody">\n'
    render_module "$log" "m$mi"
    printf '<details class="raw"><summary>Полный вывод модуля · <code>%s</code></summary><div class="rawbox"><button class="copy" type="button">Копировать</button><pre>%s</pre></div></details>\n' \
      "$(basename "$log")" "$(html_esc <"$log")"
    printf '</div></article>\n'
  done

  # --- мониторинг ---
  if (( DO_MON )) && [[ -d "$MON_DIR" ]]; then
    local tg nums lst det sp n e loss last avg best worst jit avail typ mcls ev
    printf '<article class="module" id="mon" data-name="Мониторинг"><header><h2>Мониторинг</h2><span class="pill %s">%s</span></header>\n' \
      "$( (( mon_issue )) && echo warn || echo ok)" "$( (( mon_issue )) && echo "были потери" || echo "без потерь")"
    printf '<div class="mbody"><dl class="meta"><div><dt>Период</dt><dd>%s — %s</dd></div><div><dt>Проб на цель</dt><dd>не меньше %d</dd></div><div><dt>Интервал / таймаут</dt><dd>%s с / %s с</dd></div><div><dt>Целей</dt><dd>%d</dd></div></dl>\n' \
      "$MON_STARTED" "$MON_ENDED" "$MON_ROUNDS" "$M_INTERVAL" "$M_TIMEOUT" "${#MON_T[@]}"
    printf '<div class="mgrid">\n'
    for ((i=0; i<${#MON_T[@]}; i++)); do
      [[ -s "$MON_DIR/t$i.log" ]] || continue
      tg="${MON_T[$i]}"
      IFS='|' read -r nums lst det sp <<<"$(awk -v W=40 "$MON_STATS_AWK" "$MON_DIR/t$i.log")"
      read -r n f e loss last avg best worst jit <<<"$nums"
      avail=$(awk -v l="$loss" 'BEGIN{printf "%.1f", 100-l}')
      case "$tg" in http*) typ=HTTP ;; ping:*) typ=ICMP ;; *) typ=TCP ;; esac
      mcls=ok; [[ "$loss" != "0.0" || "$e" != "0" ]] && mcls=warn; [[ "$f" == "$n" ]] && mcls=fail
      printf '<div class="mcard %s"><div class="mhead"><div class="mname"><span class="type">%s</span>%s</div><div class="avail">%s%%<small>доступность</small></div></div>\n' \
        "$mcls" "$typ" "$(html_esc <<<"$tg")" "$avail"
      printf '<dl class="mstats" title="задержка в миллисекундах"><div><dt>проб</dt><dd>%s</dd></div><div><dt>сред.</dt><dd>%s</dd></div><div><dt>мин.</dt><dd>%s</dd></div><div><dt>макс.</dt><dd>%s</dd></div><div><dt>джиттер</dt><dd>%s</dd></div></dl>\n' \
        "$n" "$avg" "$best" "$worst" "$jit"
      printf '%s\n' "$(render_spark_svg "$MON_DIR/t$i.log")"
      printf '<div class="mlast">Задержки в мс · последняя проба: %s</div></div>\n' "$(html_esc <<<"$det")"
    done
    printf '</div>\n'
    ev=""
    for ((i=0; i<${#MON_T[@]}; i++)); do
      [[ -s "$MON_DIR/t$i.log" ]] || continue
      ev="$ev$(awk -F'|' -v t="${MON_T[$i]}" '$3 != "ok" { printf "%s|%05d|%s|%s|%s\n", $2, $1, t, $3, $5 }' "$MON_DIR/t$i.log")"$'\n'
    done
    ev=$(grep -v '^$' <<<"$ev" | sort -t'|' -k1,1 -k2,2 | tail -300)
    if [[ -n "$ev" ]]; then
      printf '<details class="raw" open><summary>Журнал потерь и ошибок · %d</summary><div class="tblwrap"><table class="tbl"><thead><tr><th>Время</th><th>Проба</th><th>Цель</th><th>Статус</th><th>Причина</th></tr></thead><tbody>\n' "$(grep -c . <<<"$ev")"
      local t rnd st dt
      while IFS='|' read -r t rnd tg st dt; do
        printf '<tr class="%s"><td>%s</td><td>%d</td><td>%s</td><td>%s</td><td>%s</td></tr>\n' \
          "$([[ $st == fail ]] && echo fail || echo warn)" "$t" "$((10#$rnd))" "$(html_esc <<<"$tg")" "$([[ $st == fail ]] && echo "нет ответа" || echo "ошибка 5xx")" "$(html_esc <<<"$dt")"
      done <<<"$ev"
      printf '</tbody></table></div></details>\n'
    else
      printf '<p class="lead">Потерь и ошибок за время мониторинга не было.</p>\n'
    fi
    printf '</div></article>\n'
  fi

  printf '<footer><span>Папка запуска: <code>%s</code></span><span>Сформировано %s</span></footer>\n' \
    "$(html_esc <<<"$LOGDIR")" "$(date '+%Y-%m-%d %H:%M:%S')"
  cat <<'HTML'
</main>
<script>
HTML
  cat "$ROOT/report/app.js"
  cat <<'HTML'
</script>
</body>
</html>
HTML
  } >"$REPORT"
  return "$worst_rc"
}
