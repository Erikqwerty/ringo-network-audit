# shellcheck shell=bash
# Доступность хостов Apple из lib/targets.sh (по роли и флагам): DNS → TCP → TLS с проверкой издателя
# (check_target в lib/check.sh). Для captive.apple.com дополнительно проверяется содержимое ответа.
# Итог по хосту: OK; FAIL — обязательный недоступен; WARN — желательный недоступен или издатель не Apple.
# Задаёт: результаты по хостам (res_get), CERT_FAIL — недоступные OCSP/CRL; их читает вердикт.

# устройство Apple ждёт страницу со словом Success; другой ответ — captive-портал или прозрачный прокси
captive_content() {
  body=$(curl -s -m 8 http://captive.apple.com/hotspot-detect.html 2>/dev/null)
  det_new "captive.apple.com — содержимое"; det_kv "Как проверяется" "устройство Apple ждёт страницу со словом Success; другой ответ — captive-портал или прозрачный прокси"
  det_cmd curl -s -m 8 http://captive.apple.com/hotspot-detect.html; det_text "${body:-(пустой ответ)}"
  if grep -q 'Success' <<<"$body"; then
    printf "   %s %-38s %s%s%s\n" "$(badge OK)" "captive.apple.com (содержимое)" "$D" "ответ «Success» — портала/подмены нет" "$N"; count OK; det_ref
  else
    printf "   %s %-38s %s%s%s\n" "$(badge WARN)" "captive.apple.com (содержимое)" "$D" "ответ не «Success» — captive-портал или прозрачный прокси" "$N"; count WARN; det_ref
  fi
}

if (( ${#SEL[@]} == 0 )); then echo; echo " Нет целей для проверки (--no-builtin без --add?)"; exit 1; fi
CUR=""; NT=${#SEL[@]}; i=0; CERT_FAIL=0
for row in "${SEL[@]}"; do
  IFS='|' read -r r grp host port tls req desc <<<"$row"
  ((i++))
  if [[ "$grp" != "$CUR" ]]; then echo; echo " ${BD}${B}▸ $grp${N}"; CUR="$grp"; fi
  prog "   %s(%d/%d)%s %-38s %s…%s" "$D" "$i" "$NT" "$N" "$host:$port" "$D" "$N"
  cust=0; [[ "$grp" == Свои* ]] && cust=1
  det_new "$host:$port"; det_kv "Назначение" "$desc"; det_kv "Обязателен" "$([[ "$req" == 1 ]] && echo "да — недоступность = FAIL" || echo "желателен — недоступность = WARN")"
  check_target "$host" "$port" "$tls" "$req" "$cust"
  clear_line
  count "$ST"
  [[ "$ST" == "OK" ]] && res_set "$host" "$port" ok || res_set "$host" "$port" bad
  [[ "$grp" == "$GCERT" && "$ST" == "FAIL" ]] && ((CERT_FAIL++))
  printf "   %s %-38s %s%-15s%s %s%s%s\n" "$(badge "$ST")" "$host:$port" "$D" "$IPSHOW" "$N" "$D" "$MSG" "$N"
  det_ref
  [[ "$ST" != "OK" ]] && printf "          %s↳ назначение: %s%s\n" "$D" "$desc" "$N"

  if [[ "$host:$port" == "captive.apple.com:80" && "$ST" == "OK" ]] && have curl; then
    captive_content
  fi
done
