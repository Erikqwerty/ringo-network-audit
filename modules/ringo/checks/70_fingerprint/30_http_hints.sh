# shellcheck shell=bash
# Версия HTTP (и HTTP/3 по Alt-Svc) и прочие заголовки-подсказки: x-powered-by, via, x-cache и др.

hints=()
for h in x-powered-by via x-cache x-served-by x-envoy-upstream-service-time strict-transport-security; do
  v=$(grep -i "^$h:" <<<"$RAWH" | head -1 | sed -E 's/^[^:]+: *//')
  [[ -n "$v" ]] && hints+=("$h: ${v:0:50}")
done
printf "   • HTTP:                %sHTTP/%s%s" "$BD" "${hver:-?}" "$N"
grep -q '^alt-svc:.*h3' <<<"$ALLH" && printf " %s(+ HTTP/3 по Alt-Svc)%s" "$D" "$N"
echo
for h in "${hints[@]:-}"; do [[ -n "$h" ]] && printf "   • %s%s%s\n" "$D" "$h" "$N"; done
