# shellcheck shell=bash
# Список хостов и портов Apple (support.apple.com/101555) и фильтр по роли.
# Подключается через source из modules/apple/run.sh; сам не запускается.

# ---------- список целей ----------
# роль: s — MDM-сервер, c — устройство/сеть клиентов, b — оба
# tls: 0 — только TCP, 1 — TCP+TLS, h2 — TCP+TLS+ALPN h2
# req: 1 — обязателен (FAIL), 0 — желателен/есть замена (WARN)
TARGETS=()
t() { TARGETS+=("$1|$2|$3|$4|$5|$6|$7"); }

GAPNS_D="APNs: устройство → Apple (TCP 5223, запасной 443)"
GAPNS_S="APNs: MDM-сервер → Apple (HTTP/2, 443 или 2197)"
GACT="Активация устройства и identity-сертификат (albert.apple.com и др.)"
GMGMT="Управление и регистрация (APNs-портал, ADE, Apple Business, VPP)"
GCERT="Проверка сертификатов (OCSP / CRL)"

t c "$GAPNS_D" courier.push.apple.com   5223 1 0 "основной канал push до устройства"
t c "$GAPNS_D" courier.push.apple.com   443  1 0 "запасной канал, если 5223 закрыт"
t c "$GAPNS_D" 1-courier.push.apple.com 5223 1 0 "пул N-courier (1..50): выборочная проверка"
t c "$GAPNS_D" 10-courier.push.apple.com 5223 1 0 "пул N-courier"
t c "$GAPNS_D" 25-courier.push.apple.com 5223 1 0 "пул N-courier"
t c "$GAPNS_D" 50-courier.push.apple.com 5223 1 0 "пул N-courier"

t s "$GAPNS_S" api.push.apple.com 443  h2 0 "отправка MDM-push (HTTP/2)"
t s "$GAPNS_S" api.push.apple.com 2197 h2 0 "альтернативный порт APNs (HTTP/2)"

t c "$GACT" albert.apple.com        443 1 1 "активация: выдача устройству сертификатов активации/identity"
t c "$GACT" gs.apple.com            443 1 1 "активация и обновления"
t c "$GACT" humb.apple.com          443 1 1 "настройка устройства"
t c "$GACT" tbsc.apple.com          443 1 1 "настройка устройства"
t c "$GACT" static.ips.apple.com    443 1 0 "настройка устройства"
t c "$GACT" static.ips.apple.com    80  0 0 "настройка устройства"
t c "$GACT" captive.apple.com       80  0 1 "проверка captive-портала"
t c "$GACT" captive.apple.com       443 1 0 "проверка captive-портала"

t s "$GMGMT" identity.apple.com              443 1 1 "портал APNs-сертификата (для администратора/сервера)"
t s "$GMGMT" mdmenrollment.apple.com         443 1 1 "ADE/DEP: профили регистрации, поиск устройств"
t s "$GMGMT" vpp.itunes.apple.com            443 1 0 "Apps and Books: лицензии"
t s "$GMGMT" deviceservices-external.apple.com 443 1 0 "снятие Activation Lock"
t b "$GMGMT" gdmf.apple.com                  443 1 1 "каталог обновлений для managed software updates"
t c "$GMGMT" deviceenrollment.apple.com      443 1 1 "DEP provisional enrollment"
t c "$GMGMT" iprofiles.apple.com             443 1 1 "профили регистрации ADE"
t c "$GMGMT" axm-servicediscovery.apple.com  443 1 0 "account-driven enrollment"
t b "$GMGMT" axm-adm-enroll.apple.com        443 1 0 "Apple Business: сервер ADE-регистрации"
t b "$GMGMT" axm-adm-mdm.apple.com           443 1 0 "Apple Business: сервис управления"
t b "$GMGMT" axm-adm-scep.apple.com          443 1 0 "Apple Business: SCEP"
t s "$GMGMT" api-business.apple.com          443 1 0 "Apple Business API"

t b "$GCERT" certs.apple.com      80  0 1 "проверка сертификатов"
t b "$GCERT" certs.apple.com      443 1 0 "проверка сертификатов"
t b "$GCERT" crl.apple.com        80  0 1 "списки отзыва (CRL)"
t b "$GCERT" ocsp.apple.com       80  0 1 "OCSP"
t b "$GCERT" ocsp2.apple.com      443 1 1 "OCSP"
t b "$GCERT" valid.apple.com      443 1 1 "валидация сертификатов"
t b "$GCERT" ocsp.digicert.com    80  0 1 "OCSP DigiCert"
t b "$GCERT" crl3.digicert.com    80  0 1 "CRL DigiCert"
t b "$GCERT" crl4.digicert.com    80  0 1 "CRL DigiCert"

if (( G_UPD )); then
  GU="Обновления ПО (--updates)"
  for h in mesu.apple.com swscan.apple.com swcdn.apple.com swdist.apple.com updates.cdn-apple.com gg.apple.com ig.apple.com osrecovery.apple.com oscdn.apple.com configuration.apple.com xp.apple.com gsra.apple.com; do
    t c "$GU" "$h" 443 1 0 "обновления ПО / macOS Recovery"
  done
  t c "$GU" appldnld.apple.com 80 0 0 "обновления iOS/iPadOS"
  t c "$GU" updates-http.cdn-apple.com 80 0 0 "загрузка обновлений"
fi
if (( G_ACC )); then
  GA="Apple Account (--accounts)"
  for h in account.apple.com appleid.cdn-apple.com idmsa.apple.com gsa.apple.com; do
    t c "$GA" "$h" 443 1 0 "аутентификация Apple Account"
  done
fi
if (( G_APPS )); then
  GP="Приложения (--apps)"
  for h in itunes.apple.com apps.apple.com ppq.apple.com api.apple-cloudkit.com gateway.icloud.com; do
    t c "$GP" "$h" 443 1 0 "приложения / нотаризация / CloudKit"
  done
fi

if (( ${#ADD[@]} )); then
  for a in "${ADD[@]}"; do
    IFS=':' read -r ah ap at <<<"$a"
    [[ -z "${at:-}" ]] && case "$ap" in 443|5223|2197|8443) at=1 ;; *) at=0 ;; esac
    t b "Свои цели (--add)" "$ah" "$ap" "$at" 1 "пользовательская цель"
  done
fi

# фильтр по роли
SEL=()
if (( NO_BUILTIN )); then
  for row in "${TARGETS[@]}"; do [[ "${row#*|}" == Свои* ]] && SEL+=("$row"); done
else
  for row in "${TARGETS[@]}"; do
    r="${row%%|*}"
    case "$ROLE" in
      both) SEL+=("$row") ;;
      server) [[ "$r" == s || "$r" == b ]] && SEL+=("$row") ;;
      client) [[ "$r" == c || "$r" == b ]] && SEL+=("$row") ;;
    esac
  done
fi
