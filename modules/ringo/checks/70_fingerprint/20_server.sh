# shellcheck shell=bash
# Заголовок Server и сигнатуры стандартных страниц ошибок (HAProxy, nginx, Apache, Traefik, Envoy…).
# Итог: INFO, если Server раскрывает версию (подсказка, какие уязвимости искать). Задаёт srv для --compare.

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
