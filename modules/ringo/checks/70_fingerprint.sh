# shellcheck shell=bash
# Проверка: веб-сервер, прокси, CDN и WAF по сигнатурам. Выполняется по порядку из modules/ringo/run.sh (source, общие переменные).

# ---------- веб-сервер, прокси, WAF ----------
fp_fetch() { # $1 = путь+query, $2 = метка -> печатает http-код
  local c
  c=$(curl -sk -m 10 -D "$FPD/$2.h" -o "$FPD/$2.b" -w '%{http_code}' "$HOST$1" 2>/dev/null)
  printf '%s' "${c:-000}"   # при ошибке curl сам печатает 000 — не дублировать
}

echo
echo " ${BD}${B}▸ Веб-сервер, прокси и WAF${N}"
prog "   %s…%s" "$D" "$N"
fp_fetch "/" root >/dev/null
fp_fetch "/enroll" enroll >/dev/null
fp_fetch "/__ringo_probe_$RANDOM$RANDOM" nf >/dev/null
hver=$(curl -sk -m 10 -o /dev/null -w '%{http_version}' "$HOST/" 2>/dev/null)

clear_line

RAWH=$(cat "$FPD"/*.h 2>/dev/null | tr -d '\r')
ALLH=$(tr 'A-Z' 'a-z' <<<"$RAWH")
ALLB=$(cat "$FPD"/*.b 2>/dev/null | head -c 40000 | tr -d '\0' | tr 'A-Z' 'a-z')

# --- Server и сигнатуры страниц ---
srv=$(grep -i '^server:' <<<"$RAWH" | sed -E 's/^[Ss]erver: *//' | sort -u | paste -sd, - | sed 's/,/, /g')
SIG=()
(( SEEN_HAPROXY )) || grep -q 'no server is available to handle this request' <<<"$ALLB" && SIG+=("HAProxy (заглушка 503)")
(( SEEN_NGINX )) || grep -q '<center>nginx' <<<"$ALLB" && SIG+=("nginx (страница ошибки)")
grep -Eq 'apache/[0-9.]+ .*server at|<address>apache' <<<"$ALLB" && SIG+=("Apache (страница ошибки)")
[[ "$(cat "$FPD/nf.b" 2>/dev/null)" == "404 page not found" ]] && SIG+=("Go-сервер или Traefik (стандартный 404)")
grep -q '^x-envoy-' <<<"$ALLH" && SIG+=("Envoy (заголовки x-envoy-*)")
grep -q '^x-varnish:' <<<"$ALLH" && SIG+=("Varnish (x-varnish)")
grep -q '^server: microsoft-iis' <<<"$ALLH" && SIG+=("IIS")

if [[ -n "$srv" ]]; then
  printf "   • Заголовок Server:    %s%s%s\n" "$BD" "$srv" "$N"
  if grep -Eqi '(nginx|apache|openresty|haproxy|caddy)/[0-9]' <<<"$srv"; then
    det_new "Заголовок Server"; det_cmd curl -skI "$HOST/"
    det_text "$(sed -n '1p;/^[Ss]erver:/p' "$FPD/root.h" 2>/dev/null | tr -d '\r')"
    det_text "Версия в заголовке подсказывает, какие уязвимости искать. В nginx: server_tokens off; в http {}."
    printf "   %s заголовок Server раскрывает версию (%s) %s— в nginx: server_tokens off%s\n" "$(badge INFO)" "$srv" "$D" "$N"; count INFO
    det_ref
  fi
else
  printf "   • Заголовок Server:    %sнет (скрыт: server_tokens off / del-header)%s\n" "$D" "$N"
fi
if (( ${#SIG[@]} )); then
  printf "   • По сигнатурам:       %s%s%s\n" "$BD" "$(printf '%s; ' "${SIG[@]}" | sed 's/; $//')" "$N"
else
  printf "   • По сигнатурам:       %sне определён%s\n" "$D" "$N"
fi

# --- прочие заголовки-подсказки ---
hints=()
for h in x-powered-by via x-cache x-served-by x-envoy-upstream-service-time strict-transport-security; do
  v=$(grep -i "^$h:" <<<"$RAWH" | head -1 | sed -E 's/^[^:]+: *//')
  [[ -n "$v" ]] && hints+=("$h: ${v:0:50}")
done
printf "   • HTTP:                %sHTTP/%s%s" "$BD" "${hver:-?}" "$N"
grep -q '^alt-svc:.*h3' <<<"$ALLH" && printf " %s(+ HTTP/3 по Alt-Svc)%s" "$D" "$N"
echo
for h in "${hints[@]:-}"; do [[ -n "$h" ]] && printf "   • %s%s%s\n" "$D" "$h" "$N"; done

# --- заголовки безопасности: по первому ответу 2xx (страница 403 от nginx их обычно не несёт) ---
miss=(); H_FILE=""
for x in root enroll; do head -1 "$FPD/$x.h" 2>/dev/null | grep -q ' 2[0-9][0-9]' && { H_FILE="$FPD/$x.h"; break; }; done
H_ROOT=$(tr -d '\r' <"${H_FILE:-/dev/null}" 2>/dev/null | tr 'A-Z' 'a-z')
grep -q '^x-content-type-options: *nosniff' <<<"$H_ROOT" || miss+=("X-Content-Type-Options")
grep -Eq '^x-frame-options:|^content-security-policy:.*frame-ancestors' <<<"$H_ROOT" || miss+=("X-Frame-Options / CSP frame-ancestors")
grep -q '^referrer-policy:' <<<"$H_ROOT" || miss+=("Referrer-Policy")
grep -q '^strict-transport-security:' <<<"$H_ROOT" || miss+=("Strict-Transport-Security")
if [[ -n "$H_FILE" ]]; then
  if (( ${#miss[@]} )); then
    printf "   • Нет заголовков:      %s%s %s(в ответе на /%s)%s\n" "$D" "$(printf '%s, ' "${miss[@]}" | sed 's/, $//')" "$D" "$(basename "$H_FILE" .h | sed 's/root//')" "$N"
  else
    printf "   • Заголовки безопасности: %sесть все базовые%s\n" "$D" "$N"
  fi
fi

# --- CDN / кэш ---
CDNS=()
grep -Eq '^(cf-cache-status|cf-ray):' <<<"$ALLH" && CDNS+=("Cloudflare")
grep -Eq '^(x-amz-cf-id:|server: cloudfront)' <<<"$ALLH" && CDNS+=("CloudFront")
grep -Eq '^(x-azure-ref|x-msedge-ref):' <<<"$ALLH" && CDNS+=("Azure Front Door")
grep -Eq '^(x-served-by:.*cache|via:.*varnish|x-fastly-request-id:)' <<<"$ALLH" && CDNS+=("Fastly/Varnish")
grep -Eq '^server: (akamaighost|akamainetstorage)|^x-akamai-' <<<"$ALLH" && CDNS+=("Akamai")
grep -Eq '^server: ddos-guard|^set-cookie: __ddg[0-9]_' <<<"$ALLH" && CDNS+=("DDoS-Guard")
grep -Eq '^server: qrator|^x-qrator' <<<"$ALLH" && CDNS+=("Qrator")
if (( ${#CDNS[@]} )); then
  printf "   • CDN / anti-DDoS:     %s%s%s\n" "$BD" "$(printf '%s, ' "${CDNS[@]}" | sed 's/, $//')" "$N"
else
  printf "   • CDN / anti-DDoS:     %sне обнаружено%s\n" "$D" "$N"
fi

# --- WAF по сигнатурам ---
WAFS=()
w() { # имя, regex по заголовкам, [regex по телу]
  if grep -Eq "$2" <<<"$ALLH"; then WAFS+=("$1")
  elif [[ -n "${3:-}" ]] && grep -Eq "$3" <<<"$ALLB"; then WAFS+=("$1"); fi
}
w "Cloudflare WAF"        '^server: cloudflare|^set-cookie: __cf_bm'
w "Akamai (Kona/Bot Mgr)" '^set-cookie: (ak_bmsc|bm_sz)|^x-akamai-'
w "Imperva / Incapsula"   '^x-iinfo:|^x-cdn: (imperva|incapsula)|^set-cookie: (incap_ses_|visid_incap_)'
w "F5 BIG-IP (ASM/AWAF)"  '^server: big-?ip|^set-cookie: (bigipserver|ts[0-9a-f]{8,})|^x-wa-info:'
w "AWS WAF"               '^x-amzn-waf-|^x-amzn-errortype:.*waf'
w "Sucuri"                '^x-sucuri-|^server: sucuri'
w "Fortinet FortiWeb"     '^set-cookie: (cookiesession1|fortiwafsid)'
w "Barracuda WAF"         '^set-cookie: (barra_counter_session|bni__barracuda)'
w "Citrix NetScaler AppFW" '^via: ns-cache|^set-cookie: (ns_af|citrix_ns_id|nsc_)'
w "ModSecurity"           '^server: .*mod_?security' 'mod_security|modsecurity|this error was generated by mod'
w "Wallarm"               '^server: nginx-wallarm|^x-wallarm'
w "Qrator"                '^server: qrator|^x-qrator'
w "DDoS-Guard"            '^server: ddos-guard|^set-cookie: __ddg[0-9]_'
w "Azure Front Door WAF"  '^x-azure-ref:'

BLK=$(cat "$FPD"/post*.b "$FPD"/atk*.b 2>/dev/null | head -c 20000 | tr -d '\0' | tr 'A-Z' 'a-z')
if grep -Eqi "$BLOCK_RE" <<<"$BLK"; then
  WAFS+=("не опознан по вендору (есть страница блокировки)")
  ids=$(cat "$FPD"/post*.b "$FPD"/atk*.b 2>/dev/null | grep -Eoi 'support id: *[0-9a-z-]+' | sed -E 's/^[^:]+: *//' | sort -u | head -3 | paste -sd, - | sed 's/,/, /g')
  [[ -n "$ids" ]] && printf "   • Support ID блокировок: %s%s%s\n" "$BD" "$ids" "$N"
fi
if (( ${#WAFS[@]} )); then
  printf "   • WAF (сигнатуры):     %s%s%s\n" "$Y$BD" "$(printf '%s, ' "${WAFS[@]}" | sed 's/, $//')" "$N"
else
  printf "   • WAF (сигнатуры):     %sв заголовках/cookie/страницах не найдены%s\n" "$D" "$N"
fi
case "${WAF_ACTIVE%%:*}" in
  hit)  printf "   • WAF (активный тест): %s%s%s\n" "$Y$BD" "${WAF_ACTIVE#*:}" "$N" ;;
  none) printf "   • WAF (активный тест): %s%s%s\n" "$D" "${WAF_ACTIVE#*:}" "$N" ;;
  skip) printf "   • WAF (активный тест): %sпропущен — %s%s\n" "$D" "${WAF_ACTIVE#*:}" "$N" ;;
  *)    printf "   • WAF (активный тест): %sотключён (--no-waf-probe)%s\n" "$D" "$N" ;;
esac
if [[ "${WAF_ACTIVE%%:*}" == "none" && ${#WAFS[@]} -eq 0 ]]; then
  printf "     %s↳ «не найден» ≠ «нет»: WAF без сигнатур и без блокировки простого теста так не выявить%s\n" "$D" "$N"
fi
printf "     %s↳ виден только внешний слой; между HAProxy/nginx/приложением заголовки могут переписываться%s\n" "$D" "$N"
