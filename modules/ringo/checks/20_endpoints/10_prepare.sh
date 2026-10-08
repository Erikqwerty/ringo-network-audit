# shellcheck shell=bash
# Подготовка: список эндпоинтов (lib/endpoints.sh), эталонный ответ на несуществующий путь
# и маршруты устройств из схемы API, которых нет во встроенном списке (схема актуальнее списка).
# Задаёт: ENDPOINTS, NF_CODE/NF_SIZE, same_as_nf, UNTESTED — маршруты с параметром в пути.

endpoints_init

# эталон: ответ на заведомо несуществующий путь (чем прокси отвечает на «не мой» путь)
read -r NF_CODE NF_SIZE _ NF_STUB <<<"$(probe "/__ringo_nf_$RANDOM$RANDOM")"
same_as_nf() { [[ "$NF_CODE" != "000" && "$1" == "$NF_CODE" && "$2" == "$NF_SIZE" ]]; }

# маршруты устройств из схемы API, которых нет во встроенном списке, — проверяем тоже (схема актуальнее списка)
UNTESTED=""
if [[ -n "$API_OPS" ]]; then
  LISTED=$(for row in "${ENDPOINTS[@]}"; do IFS='|' read -r m p _ <<<"$row"; echo "$m ${p%%\?*}"; done)
  while read -r m p; do
    [[ -n "$p" ]] || continue
    grep -qFx "$m $p" <<<"$LISTED" && continue
    [[ "$p" == /scep-proxy* ]] && (( ! CHECK_SCEP_PROXY )) && continue
    # PKIOperation без настоящего PKCS7 даёт 500 — проверять пустым телом бессмысленно
    [[ "$m" == POST && "$p" == /scep* ]] && continue
    if [[ "$p" == *"{"* ]]; then UNTESTED="${UNTESTED:+$UNTESTED, }$m $p"; continue; fi
    ct=""; [[ "$m" != GET ]] && ct="$JSON"
    ENDPOINTS+=("$m|$p|$ct|Прочие маршруты устройств из схемы API|1|из схемы")
  done < <(device_ops <<<"$API_OPS")
fi
