# shellcheck shell=bash
# Сеть: TLS-рукопожатие на IP с заданным SNI, расшифровка кодов curl.
# Подключается через source из modules/ringo/run.sh; сам не запускается.

# TLS-рукопожатие напрямую на IP сервера с заданным SNI через curl --resolve (openssl при таймауте теряет
# буфер вывода). Этап: «* Connected to» в -v — TCP есть (time_connect curl при таймауте обнуляет). HS_RES:
#   ok          — рукопожатие прошло (HS_SUBJ — subject сертификата)
#   reject      — TCP есть, сервер сам закрыл/alert (нормальный отказ по неизвестному имени)
#   tls-drop    — TCP есть, на ClientHello нет ответа до таймаута (типично для DPI по SNI)
#   rst         — сброс после ClientHello
#   tcp-drop    — SYN без ответа (до SNI дело не дошло — фильтр по имени тут ни при чём)
#   tcp-refused — порт закрыт
tls_hs() {
  local sni="$1" out rc tc ta tt
  out=$(curl -skv -m 8 --resolve "$sni:$SRV_PORT:$SRV_IP" -o /dev/null \
        -w 'TIMES %{time_connect} %{time_appconnect} %{time_total}\n' "https://$sni:$SRV_PORT/" 2>&1); rc=$?
  read -r _ tc ta tt <<<"$(grep '^TIMES' <<<"$out" | tail -1)"
  HS_SUBJ=$(sed -nE 's/^\*[[:space:]]+subject: *//p' <<<"$out" | head -1)
  if awk -v x="${ta:-0}" 'BEGIN{exit !(x>0)}'; then HS_MS=$(awk -v x="$ta" 'BEGIN{printf "%d", x*1000}')
  else HS_MS=$(awk -v x="${tt:-0}" 'BEGIN{printf "%d", x*1000}'); fi
  if (( rc == 7 )); then HS_RES="tcp-refused"
  elif ! grep -q '^\* Connected to' <<<"$out" && awk -v x="${tc:-0}" 'BEGIN{exit !(x==0)}'; then HS_RES="tcp-drop"
  elif [[ -n "$HS_SUBJ" ]] || awk -v x="${ta:-0}" 'BEGIN{exit !(x>0)}'; then HS_RES="ok"
  elif (( rc == 28 )); then HS_RES="tls-drop"
  elif grep -qiE 'reset by peer|ECONNRESET|errno 54|errno 104' <<<"$out"; then HS_RES="rst"
  else HS_RES="reject"; fi
}


# расшифровка кода возврата curl при отсутствии HTTP-ответа (признаки блокировки на пути)
# $1 — rc curl, $2 — этап, на котором встал запрос: tcp|tls|http (по time_connect/time_appconnect)
net_hint() {
  case "$1:${2:-}" in
    6:*)  echo "DNS: имя не резолвится" ;;
    7:*)  echo "соединение отклонено (порт закрыт / RST на SYN)" ;;
    28:tcp)  echo "таймаут на TCP — SYN без ответа (файрвол / ТСПУ?)" ;;
    28:tls)  echo "таймаут на TLS — TCP есть, ServerHello нет (DPI / ТСПУ по SNI?)" ;;
    28:http) echo "таймаут после TLS — нет HTTP-ответа (бэкенд / обрыв потока)" ;;
    28:*) echo "таймаут — пакеты отбрасываются (файрвол / ТСПУ?)" ;;
    35:*) echo "обрыв на TLS-рукопожатии (DPI / ТСПУ по SNI?)" ;;
    52:*) echo "пустой ответ — сервер закрыл соединение (nginx 444?)" ;;
    56:*) echo "соединение сброшено после установки (RST — DPI / ТСПУ?)" ;;
    *)  echo "нет ответа (curl rc=$1)" ;;
  esac
}
# stub вида curl-rc28:tls -> "28 tls"
stub_rc() { local s="${1#curl-rc}"; echo "${s%%:*} ${s#*:}"; }
