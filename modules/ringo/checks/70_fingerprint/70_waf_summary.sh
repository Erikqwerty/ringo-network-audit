# shellcheck shell=bash
# Итог активного теста WAF (раздел 40_waf) и оговорки: «не найден» ≠ «нет».

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
