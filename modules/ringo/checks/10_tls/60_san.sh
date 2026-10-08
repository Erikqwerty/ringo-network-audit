# shellcheck shell=bash
# Другие имена из сертификата (SAN) могут быть адресами Ringo (отдельные хосты для DEP, приложения и т. п.):
# показываем, резолвятся ли они и что отвечают по HTTPS. Только справка, без вердикта.
[[ "$HOST" == https://* ]] || return 0
leaf="$FPD/leaf.pem"
[[ -s "$leaf" ]] || return 0
txt=$(openssl x509 -in "$leaf" -noout -text 2>/dev/null) || return 0
shown=0

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
