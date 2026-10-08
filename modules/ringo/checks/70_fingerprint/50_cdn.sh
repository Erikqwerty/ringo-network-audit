# shellcheck shell=bash
# CDN / anti-DDoS по характерным заголовкам и cookie.

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
