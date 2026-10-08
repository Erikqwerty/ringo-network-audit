# shellcheck shell=bash
# Базовые заголовки безопасности — по первому ответу 2xx (страница 403 от nginx их обычно не несёт).

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
