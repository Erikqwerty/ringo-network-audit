# shellcheck shell=bash
# Цепочка сертификатов, которую отдаёт сервер: полная ли, в том ли порядке, на то ли имя, не заглушка ли прокси.
# Итог: OK — полная; FAIL — неполная (нет промежуточного), заглушка, чужое имя, истёк срок;
#       WARN — корень не доверен на этом компьютере, неверный порядок, самоподписанный, проверить не удалось.
# Оставляет $FPD/leaf.pem — сертификат сервера для следующих проверок раздела.
[[ "$HOST" == https://* ]] || return 0

# Доверие системы здесь не показатель: корня (например, Russian Trusted Root CA) может не быть локально,
# и тогда ошибка проверки одинакова для полной и неполной цепочки. Поэтому смотрим на структуру: кто кем выдан,
# и догружаем по AIA (caIssuers) издателя последнего отданного сертификата — корень это или промежуточный.
# результат: CH_RES=ok|placeholder|name|incomplete|incomplete?|untrusted|order|self|expired|none, CH_N — сколько сертификатов отдано,
#   CH_MISSING — CN недостающего издателя, CH_AIA — откуда его взять, CH_DETAIL — пояснение
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

prog "   %s…%s" "$D" "$N"
det_new "Цепочка сертификатов"
chain_check
clear_line
case "$CH_RES" in
  ok)   printf "   %s цепочка сертификатов полная %s(отдано: %d)%s\n" "$(badge OK)" "$D" "$CH_N" "$N"; count OK ;;
  incomplete)
    printf "   %s неполная цепочка сертификатов: сервер отдаёт %d, нет промежуточного «%s»\n" "$(badge FAIL)" "$CH_N" "$CH_MISSING"; count FAIL "неполная цепочка сертификатов (нет «${CH_MISSING}»)"
    [[ -n "$CH_DETAIL" ]] && printf "          %s↳ %s%s\n" "$D" "$CH_DETAIL" "$N"
    printf "          %s↳ клиенты без догрузки по AIA (Android, Java, curl/openssl, агенты) не установят TLS%s\n" "$D" "$N"
    printf "          %s↳ в ssl_certificate nginx нужен fullchain: сертификат сервера, затем промежуточный%s\n" "$D" "$N"
    [[ -n "$CH_AIA" ]] && printf "          %s↳ промежуточный: %s%s\n" "$D" "$CH_AIA" "$N" ;;
  incomplete\?)
    printf "   %s вероятно, неполная цепочка: сервер отдаёт только свой сертификат, издатель «%s» не отдан и локально не найден\n" "$(badge WARN)" "$CH_MISSING"; count WARN "вероятно, неполная цепочка сертификатов"
    printf "          %s↳ %s%s\n" "$D" "$CH_DETAIL" "$N" ;;
  untrusted)
    printf "   %s цепочка полная %s(отдано: %d)%s, но корень «%s» не в доверенных этого компьютера\n" "$(badge WARN)" "$D" "$CH_N" "$N" "$CH_MISSING"; count WARN "корень «${CH_MISSING}» не доверен на этом компьютере"
    printf "          %s↳ на устройствах корень должен быть установлен (например, профилем MDM)%s\n" "$D" "$N" ;;
  order)   printf "   %s цепочка сертификатов в неверном порядке или с лишним сертификатом %s(%s)%s\n" "$(badge WARN)" "$D" "$CH_DETAIL" "$N"; count WARN "порядок цепочки сертификатов" ;;
  self)    printf "   %s сертификат самоподписанный\n" "$(badge WARN)"; count WARN "самоподписанный сертификат" ;;
  expired) printf "   %s %s\n" "$(badge FAIL)" "$CH_DETAIL"; count FAIL "истёкший сертификат в цепочке" ;;
  placeholder)
    printf "   %s сервер отдаёт сертификат-заглушку «%s» вместо сертификата %s\n" "$(badge FAIL)" "$CH_MISSING" "$HN"
    count FAIL "сертификат-заглушка прокси «${CH_MISSING}» вместо сертификата $HN"
    printf "          %s↳ %s%s\n" "$D" "$CH_DETAIL" "$N"
    printf "          %s↳ браузер покажет ошибку сертификата (на домене с HSTS её нельзя обойти), устройства и агенты не подключатся%s\n" "$D" "$N" ;;
  name)
    printf "   %s %s\n" "$(badge FAIL)" "$CH_DETAIL"; count FAIL "сертификат выдан не на $HN" ;;
  *)       printf "   %s цепочку сертификатов проверить не удалось %s(%s)%s\n" "$(badge WARN)" "$D" "$CH_DETAIL" "$N"; count WARN "цепочка сертификатов не проверена" ;;
esac
det_ref
