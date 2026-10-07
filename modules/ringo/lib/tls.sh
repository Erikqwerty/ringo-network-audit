# shellcheck shell=bash
# TLS: версии протокола, цепочка сертификатов, срок/отзыв/SAN.
# Подключается через source из modules/ringo/run.sh; сам не запускается.

# ---------- проверка версии TLS: curl, при сомнениях — openssl ----------
# результат: TLS_RES=ok|fail|unknown, TLS_VIA=curl|openssl, TLS_DETAIL=пояснение
tls_check() {
  local v="$1" args cout out rc hn hp sni flag
  TLS_RES="unknown"; TLS_VIA=""; TLS_DETAIL=""
  if [[ "$v" == "1.2" ]]; then args=(--tlsv1.2 --tls-max 1.2); flag="-tls1_2"; else args=(--tlsv1.3); flag="-tls1_3"; fi

  cout=$(curl -sS -k -m 10 -o /dev/null "${args[@]}" "$HOST/" 2>&1); rc=$?
  det_sec "Проверка через curl"; det_cmd curl -sSk -m 10 -o /dev/null "${args[@]}" "$HOST/"
  det_kv "Код возврата curl" "$rc$( ((rc == 0)) && echo " — рукопожатие прошло")"; [[ -n "$cout" ]] && det_text "$cout"
  if (( rc == 0 )); then TLS_RES="ok"; TLS_VIA="curl"; return; fi

  # curl не справился: может быть и отказ сервера, и ограничение самого curl (частый случай на macOS)
  TLS_DETAIL="curl rc=$rc"
  if command -v openssl >/dev/null 2>&1; then
    hn="${HOST#https://}"; hn="${hn%%/*}"; sni="${hn%%:*}"
    [[ "$hn" == *:* ]] && hp="$hn" || hp="$hn:443"
    out=$(with_timeout 12 openssl s_client -connect "$hp" -servername "$sni" "$flag" </dev/null 2>&1)
    det_sec "Проверка через openssl (curl не дал ответа)"; det_cmd openssl s_client -connect "$hp" -servername "$sni" "$flag"
    det_text "$(grep -E 'CONNECTED|Protocol|Cipher is|alert|error|Verify return' <<<"$out" | head -12)"
    if echo "$out" | grep -Eqi "unknown option|unrecognized option|usage:"; then
      : # этот openssl не умеет такой флаг — вердикта нет
    elif echo "$out" | grep -Eq "Protocol *: TLSv${v//./\\.}|New, TLSv${v//./\\.}, Cipher is [A-Za-z0-9]"; then
      TLS_RES="ok"; TLS_VIA="openssl"; TLS_DETAIL=""; return
    elif echo "$out" | grep -Eqi "Cipher is \(NONE\)|alert protocol version|handshake failure|no protocols available|wrong version number|unsupported protocol"; then
      TLS_RES="fail"; TLS_VIA="openssl"; TLS_DETAIL="сервер отклонил TLS $v"; return
    else
      TLS_DETAIL="$TLS_DETAIL; openssl без чёткого ответа"
    fi
  fi

  # openssl вердикта не дал: rc 2/4 у curl = «не умею», а не «сервер не смог»
  if (( rc == 2 || rc == 4 )) || echo "$cout" | grep -qiE "doesn't support|not supported|unknown option"; then
    TLS_RES="unknown"; TLS_DETAIL="ваш curl не поддерживает эту проверку (rc=$rc), openssl недоступен"
  elif (( rc == 28 || rc == 52 || rc == 56 || rc == 7 )); then
    TLS_RES="unknown"; TLS_DETAIL="$(net_hint "$rc") — это сеть, а не версия TLS"
  else
    TLS_RES="fail"; TLS_VIA="curl"
  fi
}

# ---------- цепочка сертификатов, которую отдаёт сервер ----------
# Доверие системы здесь не показатель: корня (например, Russian Trusted Root CA) может не быть локально,
# и тогда ошибка проверки одинакова для полной и неполной цепочки. Поэтому смотрим на структуру: кто кем выдан,
# и догружаем по AIA (caIssuers) издателя последнего отданного сертификата — корень это или промежуточный.
# результат: CH_RES=ok|placeholder|name|incomplete|incomplete?|untrusted|order|self|expired|none, CH_N — сколько сертификатов отдано,
#   CH_MISSING — CN недостающего издателя, CH_AIA — откуда его взять, CH_DETAIL — пояснение
# сертификаты-заглушки обратных прокси: их отдают вместо настоящего, когда для имени ничего не настроено
PLACEHOLDER_RE='letsencrypt-nginx-proxy-companion|traefik default cert|kubernetes ingress controller fake certificate|ssl-cert-snakeoil|^localhost(\.localdomain)?$|^nginx$|default'
placeholder_hint() { # CN заглушки -> что это значит
  case "$(tr 'A-Z' 'a-z' <<<"$1")" in
    *letsencrypt-nginx-proxy-companion*) echo "nginx-proxy (+ acme-companion) отдаёт заглушку: для этого имени нет виртуального хоста или сертификата — контейнер Ringo не запущен / без VIRTUAL_HOST, либо Let's Encrypt не выпустил сертификат" ;;
    *traefik*)    echo "Traefik отдаёт сертификат по умолчанию: для этого имени нет роутера или TLS-сертификата" ;;
    *kubernetes*) echo "ingress-nginx отдаёт поддельный сертификат по умолчанию: нет Ingress с TLS для этого имени" ;;
    *)            echo "прокси отдаёт сертификат по умолчанию: для этого имени ничего не настроено" ;;
  esac
}
name_ok() { # имя, список имён сертификата (по строке) -> совпадает ли (с учётом *.домен)
  local h="$1" n pre
  while IFS= read -r n; do
    [[ -z "$n" ]] && continue
    n="$(tr 'A-Z' 'a-z' <<<"$n")"
    [[ "$n" == "$h" ]] && return 0
    if [[ "$n" == \*.* ]]; then   # *.домен покрывает ровно один уровень: a.домен, но не a.b.домен
      pre="${h%."${n#\*.}"}"
      [[ "$pre" != "$h" && -n "$pre" && "$pre" != *.* ]] && return 0
    fi
  done <<<"$2"
  return 1
}
cn_of() { sed -nE 's/.*CN *= *([^,/]+).*/\1/p' <<<"$1" | head -1; }
chain_check() {
  local hn hp sni out l n=0 vcode last_pem aia dl dsub diss i f
  local -a subj=() iss=()
  CH_RES="none"; CH_N=0; CH_MISSING=""; CH_AIA=""; CH_DETAIL=""
  command -v openssl >/dev/null 2>&1 || { CH_DETAIL="openssl недоступен"; return; }
  hn="${HOST#https://}"; hn="${hn%%/*}"; sni="${hn%%:*}"
  [[ "$hn" == *:* ]] && hp="$hn" || hp="$hn:443"
  out=$(with_timeout 12 openssl s_client -connect "$hp" -servername "$sni" -showcerts </dev/null 2>&1)
  while IFS= read -r l; do
    if [[ "$l" =~ ^\ *[0-9]+\ s:(.*)$ ]]; then subj+=("${BASH_REMATCH[1]}"); ((n++))
    elif [[ "$l" =~ ^\ +i:(.*)$ ]] && (( n > ${#iss[@]} )); then iss+=("${BASH_REMATCH[1]}")
    fi
  done < <(sed -n '/^Certificate chain/,/^---$/p' <<<"$out")
  CH_N=$n
  awk '/-----BEGIN CERTIFICATE-----/{c++} c==1{print} /-----END CERTIFICATE-----/{if(c==1)exit}' <<<"$out" >"$FPD/leaf.pem"
  det_sec "Цепочка, которую отдаёт сервер"; det_cmd openssl s_client -connect "$hp" -servername "$sni" -showcerts
  det_text "$(sed -n '/^Certificate chain/,/^---$/p' <<<"$out" | grep -E '^ *[0-9]+ s:|^ +[iv]:')"
  det_kv "Отдано сертификатов" "$n"
  det_kv "Проверка openssl" "$(sed -nE 's/.*Verify return code: (.*)/\1/p' <<<"$out" | tail -1)"
  det_text "s: — владелец сертификата, i: — кем выдан. Цепочка полная, если i: каждого совпадает с s: следующего," \
           "а последний выдан корнем, который есть у клиента."
  (( n )) || { CH_DETAIL="сервер не отдал сертификаты (openssl: $(grep -m1 -iE 'error|errno' <<<"$out" | cut -c1-80))"; return; }
  vcode=$(sed -nE 's/.*Verify return code: ([0-9]+).*/\1/p' <<<"$out" | tail -1)

  # имя: сертификат должен быть выдан на этот хост (CN или SAN, с учётом *.домен)
  local names lcn
  names=$(openssl x509 -in "$FPD/leaf.pem" -noout -text 2>/dev/null | grep -oE 'DNS:[^,[:space:]]+' | sed 's/^DNS://')
  lcn=$(cn_of "${subj[0]}")
  CH_NAMES="$(printf '%s\n' "$names" "$lcn" | grep . | sort -u | paste -sd, - | sed 's/,/, /g')"
  CH_NAME_OK=0; name_ok "$sni" "$names"$'\n'"$lcn" && CH_NAME_OK=1
  det_kv "Выдан на имена" "${CH_NAMES:-—}"; det_kv "Имя $sni в сертификате" "$( ((CH_NAME_OK)) && echo есть || echo нет)"
  det_kv "Срок" "$(openssl x509 -in "$FPD/leaf.pem" -noout -dates 2>/dev/null | paste -sd' ' -)"
  # заглушка прокси: её отдают, когда для имени нет своего сертификата / виртуального хоста
  if (( ! CH_NAME_OK )) && grep -Eqi "$PLACEHOLDER_RE" <<<"$lcn"; then
    CH_RES="placeholder"; CH_MISSING="$lcn"
    CH_DETAIL="$(placeholder_hint "$lcn")"
    (( vcode == 10 )) && CH_DETAIL="$CH_DETAIL; заглушка к тому же истекла ($(openssl x509 -in "$FPD/leaf.pem" -noout -enddate 2>/dev/null | sed 's/notAfter=//'))"
    return
  fi
  if (( ! CH_NAME_OK )); then CH_RES="name"; CH_DETAIL="сертификат выдан на «${CH_NAMES:-?}», а не на $sni"; return; fi
  if [[ "$vcode" == "10" ]]; then CH_RES="expired"; CH_DETAIL="в цепочке есть сертификат с истёкшим сроком"; return; fi
  if (( n == 1 )) && [[ "${subj[0]}" == "${iss[0]}" ]]; then CH_RES="self"; return; fi
  for ((i = 0; i < n - 1; i++)); do
    if [[ "${iss[i]}" != "${subj[i+1]}" ]]; then
      CH_RES="order"; CH_DETAIL="сертификат #$i выдан «$(cn_of "${iss[i]}")», а следующим идёт «$(cn_of "${subj[i+1]}")»"; return
    fi
  done
  [[ "$vcode" == "0" ]] && { CH_RES="ok"; return; }
  # последний отданный сертификат самоподписанный — это корень, цепочка полная
  if [[ "${subj[n-1]}" == "${iss[n-1]}" ]]; then CH_RES="untrusted"; CH_MISSING="$(cn_of "${subj[n-1]}")"; return; fi

  # издатель последнего сертификата не отдан: корень (норма) или промежуточный (ошибка)? Спрашиваем AIA.
  CH_MISSING="$(cn_of "${iss[n-1]}")"
  last_pem=$(awk '/-----BEGIN CERTIFICATE-----/{c++; b=""} c{b=b $0 "\n"} /-----END CERTIFICATE-----/{last=b} END{printf "%s", last}' <<<"$out")
  aia=$(openssl x509 -noout -text <<<"$last_pem" 2>/dev/null | sed -nE 's/.*CA Issuers - URI:(https?:[^[:space:]]+).*/\1/p' | head -1)
  CH_AIA="$aia"
  det_sec "Издатель последнего сертификата — по ссылке AIA (caIssuers)"
  [[ -z "$aia" ]] && det_text "В сертификате нет ссылки caIssuers — издателя не скачать."
  if [[ -n "$aia" ]] && curl -s -m 8 -o "$FPD/aia.crt" "$aia" 2>/dev/null; then
    for f in DER PEM; do
      dl=$(openssl x509 -inform "$f" -in "$FPD/aia.crt" -noout -subject -issuer 2>/dev/null) && break
    done
    det_cmd curl -s -m 8 -o aia.crt "$aia"; det_cmd openssl x509 -inform "$f" -in aia.crt -noout -subject -issuer
    det_text "${dl:-(не удалось прочитать сертификат)}"
    det_text "Если subject = issuer, это корень (сервер вправе его не отдавать); иначе это промежуточный, и сервер обязан его отдать."
    dsub=$(sed -nE 's/^subject= *//p' <<<"$dl"); diss=$(sed -nE 's/^issuer= *//p' <<<"$dl")
    if [[ -n "$dsub" ]]; then
      if [[ "$dsub" == "$diss" ]]; then CH_RES="untrusted"   # издатель — корень: сервер вправе его не отдавать
      else CH_RES="incomplete"; CH_DETAIL="по AIA получен промежуточный «$(cn_of "$dsub")», выданный «$(cn_of "$diss")»"; fi
      return
    fi
  fi
  # AIA не помог: конечный сертификат почти никогда не выдаётся корнем напрямую
  if (( n == 1 )); then CH_RES="incomplete?"; CH_DETAIL="AIA недоступен — вывод по структуре: сертификат сервера редко выдаётся корнем напрямую"
  else CH_RES="untrusted"; fi
}

# ---------- сертификат сервера: срок, отзыв (CRL/OCSP), имена SAN ----------
# печатает строки проверок; работает с $FPD/leaf.pem, который оставляет chain_check
cert_extras() {
  local leaf="$FPD/leaf.pem" txt end urls u c ok=0 bad=0 badl="" names nm ip hc shown=0
  [[ -s "$leaf" ]] || return 0
  txt=$(openssl x509 -in "$leaf" -noout -text 2>/dev/null) || return 0
  end=$(openssl x509 -in "$leaf" -noout -enddate 2>/dev/null | sed 's/^notAfter=//')

  # срок: -checkend есть и в OpenSSL, и в LibreSSL — без разбора дат
  det_new "Срок действия сертификата"; det_sec "Сертификат сервера"
  det_cmd openssl x509 -in leaf.pem -noout -subject -issuer -dates
  det_text "$(openssl x509 -in "$leaf" -noout -subject -issuer -dates 2>/dev/null)"
  det_text "Порог предупреждения — 30 дней (openssl x509 -checkend)."
  if [[ "$CH_RES" =~ ^(expired|placeholder)$ ]]; then :   # уже FAIL в проверке цепочки (у заглушки — её срок)
  elif ! openssl x509 -in "$leaf" -noout -checkend 0 >/dev/null 2>&1; then
    printf "   %s сертификат истёк %s(%s)%s\n" "$(badge FAIL)" "$D" "$end" "$N"; count FAIL "сертификат сервера истёк"
  elif ! openssl x509 -in "$leaf" -noout -checkend $((30*86400)) >/dev/null 2>&1; then
    printf "   %s сертификат истекает меньше чем через 30 дней %s(%s)%s\n" "$(badge WARN)" "$D" "$end" "$N"; count WARN "сертификат истекает < 30 дней"
  else
    printf "   %s срок действия сертификата %s(до %s)%s\n" "$(badge OK)" "$D" "$end" "$N"; count OK
  fi
  det_ref

  # отзыв: устройства Apple проверяют OCSP/CRL — адреса должны открываться у клиентов.
  # Здесь видно только с этого компьютера; любой HTTP-ответ = адрес доступен (OCSP на GET отвечает 4xx).
  urls=$( { sed -nE 's/.*OCSP - URI:(http[^[:space:],]+).*/OCSP \1/p' <<<"$txt"
            awk '/CRL Distribution Points/{f=1;next} f&&/URI:/{sub(/.*URI:/,""); print "CRL " $0; next} f&&!/Full Name|^ *$/{f=0}' <<<"$txt"; } | sort -u)
  if [[ -n "$urls" ]]; then
    det_new "Адреса проверки отзыва (OCSP / CRL)"; det_sec "Адреса из сертификата и их доступность"
    det_text "Любой HTTP-ответ означает, что адрес доступен (OCSP на GET обычно отвечает 4xx)."
    while read -r kind u; do
      [[ -n "$u" ]] || continue
      c=$(curl -s -m 8 -r 0-2047 -o /dev/null -w '%{http_code}' "$u" 2>/dev/null)
      det_cmd curl -s -m 8 -r 0-2047 -o /dev/null -w '%{http_code}' "$u"; det_kv "$kind" "HTTP ${c:-000}$([[ "${c:-000}" == 000 ]] && echo ' — нет ответа')"
      if [[ "${c:-000}" != 000 ]]; then ((ok++)); else ((bad++)); badl="$badl $kind ${u#http://}"; fi
    done <<<"$urls"
    if (( bad == 0 )); then
      printf "   %s адреса проверки отзыва доступны %s(%d: %s)%s\n" "$(badge OK)" "$D" "$ok" "$(awk '{print $1}' <<<"$urls" | sort | uniq -c | awk '{printf "%s%s×%s", (NR>1?", ":""), $2, $1}')" "$N"; count OK
    elif (( ok == 0 )); then
      printf "   %s адреса проверки отзыва недоступны:%s%s\n" "$(badge WARN)" "$badl" "$N"; count WARN "OCSP/CRL сертификата недоступны"
      printf "          %s↳ если и у устройств так, проверка отзыва затянется или сорвётся; откройте эти адреса для клиентов%s\n" "$D" "$N"
    else
      printf "   %s часть адресов отзыва недоступна:%s %s(доступно %d из %d)%s\n" "$(badge INFO)" "$badl" "$D" "$ok" "$((ok+bad))" "$N"; count INFO
    fi
    det_ref
  fi

  # SAN: другие имена из сертификата могут быть адресами Ringo (отдельные хосты для DEP, приложения и т. п.)
  names=$(grep -oE 'DNS:[^,[:space:]]+' <<<"$txt" | sed 's/^DNS://' | grep -vFx "$HN" | grep -v '^\*' | sort -u | head -5)
  for nm in $names; do
    ip=$( (dig +short A "$nm" 2>/dev/null; dscacheutil -q host -a name "$nm" 2>/dev/null | awk '/^ip_address:/{print $2}') \
          | grep -E '^[0-9]+(\.[0-9]+){3}$' | head -1)
    if [[ -z "$ip" ]]; then
      printf "   • SAN %s: %sне резолвится%s\n" "$nm" "$D" "$N"
    else
      hc=$(curl -sk -m 8 -o /dev/null -w '%{http_code}' "https://$nm/" 2>/dev/null)
      printf "   • SAN %s: %s, HTTPS %s%s%s\n" "$nm" "$ip" "$BD" "${hc:-000}" "$N"
    fi
    shown=1
  done
  (( shown )) && printf "     %s↳ другие имена из сертификата: если Ringo использует их, проверьте их этим же скриптом%s\n" "$D" "$N"
  return 0
}
