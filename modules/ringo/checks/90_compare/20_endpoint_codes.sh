# shellcheck shell=bash
# Коды ответов на одних и тех же маршрутах и телах устройств. Расхождения сразу показывают,
# где прокси/версия ведут себя иначе.
[[ -n "$COMPARE" ]] || return 0

# «ключ|код|размер» из чужого отчёта: эндпоинты — «[ OK ] GET  /путь  400  164B …», тела — после заголовка раздела
OTHER=$(awk '
  /▸ Реальные тела/ { body = 1; next }
  /▸ / { body = 0 }
  match($0, /\] (GET|PUT|POST|PATCH|DELETE) +[^ ]+ +([0-9][0-9][0-9]|—)/) {
    n = split(substr($0, RSTART + 2), f, / +/); m = f[1]; p = f[2]; sub(/\?.*/, "", p); c = f[3]
    sz = (f[4] ~ /^[0-9]+B$/) ? f[4] : ""; sub(/B$/, "", sz)
    print (body ? "тело " : "") m " " p "|" c "|" (body ? "" : sz)
  }' "$COMPARE")
same=0; diffs=0
for r in "${ROWS[@]}"; do
  IFS='|' read -r key c1 s1 <<<"$r"
  o=$(grep -F "$key|" <<<"$OTHER" | head -1)
  [[ -n "$o" ]] || continue
  IFS='|' read -r _ c2 s2 <<<"$o"
  if [[ "$c1" == "$c2" ]]; then ((same++)); continue; fi
  ((diffs++))
  [[ "$c1" == "—" ]] && { c1="нет в API"; s1=""; }; [[ "$c2" == "—" ]] && { c2="нет в API"; s2=""; }
  printf "   • %s: здесь %s%s%s%s, там %s%s%s%s\n" "$key" "$BD" "$c1" "$N" "${s1:+ (${s1} Б)}" "$BD" "$c2" "$N" "${s2:+ (${s2} Б)}"
done
printf "   • Совпало кодов: %d, различается: %d\n" "$same" "$diffs"
(( diffs )) && printf "     %s↳ разный код на одном маршруте — разная версия Ringo или разные правила прокси; сверяйте ответы в responses/%s\n" "$D" "$N"
