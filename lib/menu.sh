# shellcheck shell=bash
# Интерактивное меню audit.sh. Подключается через source; сам не запускается.

ask() { # вопрос, значение по умолчанию -> REPLY
  local q="$1" def="${2:-}"
  if [[ -n "$def" ]]; then printf " %s %s[%s]%s: " "$q" "$D" "$def" "$N"; else printf " %s: " "$q"; fi
  read -r REPLY </dev/tty || REPLY=""
  [[ -z "$REPLY" ]] && REPLY="$def"
}
yesno() { # вопрос, y|n по умолчанию -> 0 если да
  local d="$2" hint="y/N"; [[ "$d" == y ]] && hint="Y/n"
  ask "$1 ($hint)" ""
  [[ -z "$REPLY" ]] && REPLY="$d"
  [[ "$REPLY" =~ ^[YyДд] ]]
}

interactive_menu() {
  echo
  echo "${BD}Сетевой аудит Ringo MDM — мастер${N}"
  echo "${D}────────────────────────────────────────────────────────────────${N}"
  echo " Что проверять (номера через пробел):"
  echo "   ${BD}1${N}) Ringo: эндпоинты за reverse proxy, TLS, WAF"
  echo "   ${BD}2${N}) Apple: сеть для MDM (APNs, активация, OCSP, NTP)"
  echo "   ${BD}3${N}) Мониторинг как mtr: постоянная параллельная проверка"
  echo "   ${BD}4${N}) Полный аудит: всё сразу (Ringo со всеми проверками, Apple со всеми хостами, мониторинг)"
  ask "Выбор" "4"
  for x in $REPLY; do case "$x" in 1) DO_RINGO=1 ;; 2) DO_APPLE=1 ;; 3) DO_MON=1 ;; 4) FULL=1 ;; esac; done
  if (( FULL )); then
    ask "URL сервера Ringo (пусто — без Ringo)" ""; RINGO_URL="$REPLY"
    yesno "Запуск изнутри разрешённой подсети (--internal)?" n && R_INTERNAL=1
    if yesno "Захват tcpdump во время проверки (нужен sudo)?" n; then
      def_if=$(route -n get "$(host_of "${RINGO_URL:-apple.com}")" 2>/dev/null | awk '/interface:/{print $2}')
      ask "Интерфейс" "${def_if:-en0}"; R_CAPTURE="$REPLY"
    fi
    apply_full; echo; return 0
  fi

  if (( DO_RINGO )); then
    echo; echo " ${B}${BD}▸ Ringo${N}"
    ask "URL сервера" "https://mdm.example.com"; RINGO_URL="$REPLY"
    yesno "Запуск изнутри разрешённой подсети (--internal)?" n && R_INTERNAL=1
    yesno "Проверять /scep-proxy?" n && R_SCEPPROXY=1
    yesno "Пробы WAF тестовыми строками?" y || R_WAF=0
    yesno "Проверка вмешательства на пути (DPI / ТСПУ)?" n && R_DPI=1
    if yesno "Захват tcpdump во время проверки (нужен sudo)?" n; then
      R_DPI=1
      def_if=$(route -n get "$(host_of "$RINGO_URL")" 2>/dev/null | awk '/interface:/{print $2}')
      ask "Интерфейс" "${def_if:-en0}"; R_CAPTURE="$REPLY"
    fi
  fi
  if (( DO_APPLE )); then
    echo; echo " ${B}${BD}▸ Apple${N}"
    echo "   где запущено: ${BD}server${N} — MDM-сервер, ${BD}client${N} — сеть устройств, ${BD}both${N} — оба"
    ask "Роль" "both"; A_ROLE="$REPLY"
    ask "Таймаут подключения, с" "4"; A_TIMEOUT="$REPLY"
    A_EXTRA=""
    yesno "Хосты обновлений ПО (--updates)?" n && A_EXTRA="$A_EXTRA --updates"
    yesno "Хосты Apple Account (--accounts)?" n && A_EXTRA="$A_EXTRA --accounts"
    yesno "Хосты приложений (--apps)?" n && A_EXTRA="$A_EXTRA --apps"
  fi
  if (( DO_MON )); then
    echo; echo " ${B}${BD}▸ Мониторинг${N}"
    echo "   цели: https://host/путь · host:port · ping:host; пусто — ключевые эндпоинты по умолчанию"
    ask "Свои цели через пробел" ""
    for x in $REPLY; do M_TARGETS+=("$x"); done
    ask "Интервал между раундами, с" "2"; M_INTERVAL="$REPLY"
    ask "Сколько раундов (0 — до Ctrl-C)" "0"; M_COUNT="$REPLY"
  fi
  echo
}
