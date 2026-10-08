# shellcheck shell=bash
# Эталон: безобидная строка на том же пути. С ним сравниваются пробы; если сам эталон не проходит
# (000/401/403/429/5xx), сравнение неинформативно — пробы пропускаются (INFO).
(( WAF_PROBE )) || return 0

probe_retry "/enroll?q=audit"
B_CODE="$CODE"; B_STUB="$STUB"
det_new "WAF: эталонный запрос"; det_probe "Эталон: безобидная строка"; det_probe_verdict "$STUB"
case "$B_CODE" in
  000|401|403|429|502|503|504)
    WAF_ACTIVE="skip:эталонный запрос даёт $B_CODE — сравнение неинформативно"
    printf "   %s эталон /enroll?q=audit → %s — пробы пропущены\n" "$(badge INFO)" "$B_CODE"; det_ref ;;
esac
