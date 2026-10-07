# shellcheck shell=bash
# Захват tcpdump во время проверки и разбор pcap.
# Подключается через source из modules/ringo/run.sh; сам не запускается.

# ---------- захват tcpdump (--capture) ----------
CAP_PID=""; SUDO=""; (( EUID )) && SUDO="sudo"
start_capture() { # интерфейс, файл, IP
  printf "   %sзапуск tcpdump на %s (нужен sudo)…%s\n" "$D" "$1" "$N"
  if ! $SUDO -v 2>/dev/null && [[ -n "$SUDO" ]]; then
    printf "   %s захват не запущен: нет прав sudo\n" "$(badge WARN)"; count WARN; return 1
  fi
  # -U: писать пакеты сразу, без буфера (иначе файл остаётся пустым до остановки)
  $SUDO tcpdump -U -nn -i "$1" -w "$2" host "$3" >/dev/null 2>&1 &
  CAP_PID=$!
  sleep 1
  if ! kill -0 "$CAP_PID" 2>/dev/null && ! $SUDO kill -0 "$CAP_PID" 2>/dev/null; then
    printf "   %s tcpdump не запустился на %s\n" "$(badge WARN)" "$1"; count WARN; CAP_PID=""; return 1
  fi
}
stop_capture() {
  [[ -n "${CAP_PID:-}" ]] || return 0
  $SUDO kill -INT "$CAP_PID" 2>/dev/null; wait "$CAP_PID" 2>/dev/null
  CAP_PID=""
}

# разбор pcap: потоки к серверу по клиентскому порту. Печатает:
# "<потоков> <без SYN-ACK> <с чужим RST> <с RST сервера> <встали на 8–40 КБ> <мин. RTT рукопожатия, мс> <TTL сервера>"
pcap_stats() { # файл, IP сервера
  tcpdump -r "$1" -nn -v "host $2 and tcp" 2>/dev/null | awk -v ip="$2" '
    function ts(s,  a) { split(s, a, ":"); return a[1]*3600 + a[2]*60 + a[3] }
    /^[0-9][0-9]:[0-9][0-9]:[0-9]/ { t = ts($1); ttl = ""; if (match($0, /ttl [0-9]+/)) ttl = substr($0, RSTART+4, RLENGTH-4) + 0; next }
    / > / {
      src = $1; dst = $3; sub(/:$/, "", dst)
      fl = ""; if (match($0, /Flags \[[^]]*\]/)) fl = substr($0, RSTART+7, RLENGTH-8)
      len = 0; if (match($0, /length [0-9]+/)) len = substr($0, RSTART+7, RLENGTH-7) + 0
      if (index(src, ip ".") == 1) { s = 1; k = dst } else { s = 0; k = src }
      flows[k] = 1
      # SYN может нести ECN-флаги ([SEW]), SYN-ACK — [S.E]
      if (!s && index(fl, "S") && !index(fl, ".")) { syn[k]++; if (!(k in synT)) synT[k] = t }
      if (s && index(fl, "S") && index(fl, ".")) { sa[k] = 1; sttl[k] = ttl; if (k in synT) { r = t - synT[k]; if (minrtt == "" || r < minrtt) minrtt = r } }
      # RST «от сервера» с TTL, отличным от TTL его же SYN-ACK, — пакет пришёл не от сервера (инжект на пути)
      if (s && index(fl, "R")) { rst[k]++; if ((k in sttl) && (ttl - sttl[k] > 2 || sttl[k] - ttl > 2)) inj[k] = 1 }
      if (s && index(fl, "F")) fin[k] = 1
      if (s && len > 0) { data[k] += len; lastS[k] = t }
      if (s && ttl != "") ttls[ttl] = 1
      last[k] = t
    }
    END {
      n = nos = ni = nr = nf = 0
      for (k in flows) {
        n++
        if ((k in syn) && !(k in sa)) nos++
        if (k in inj) ni++; else if (k in rst) nr++
        # «заморозка»: сервер передал 8–40 КБ, потом замолчал, а соединение жило ещё ≥5 с (клиент ждал).
        # Без этой паузы это обычный поток, конец которого просто не попал в захват.
        if ((k in sa) && !(k in fin) && !(k in rst) && data[k] >= 8000 && data[k] <= 40000 && last[k] - lastS[k] >= 5) nf++
      }
      tl = ""; for (x in ttls) tl = tl (tl == "" ? "" : ",") x
      printf "%d %d %d %d %d %s %s\n", n, nos, ni, nr, nf, (minrtt == "" ? "-" : sprintf("%.1f", minrtt*1000)), (tl == "" ? "-" : tl)
    }'
}
