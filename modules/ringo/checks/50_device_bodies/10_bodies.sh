# shellcheck shell=bash
# Тела запросов для следующей проверки: plist (с DOCTYPE и без), JSON агента, бинарный PKCS7.
# Значения заведомо невалидные — приложение отвечает 4xx и ничего не создаёт.

cat >"$FPD/body_checkin.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>MessageType</key>
	<string>RingoAuditProbe</string>
	<key>UDID</key>
	<string>00000000-0000000000AUDIT</string>
</dict>
</plist>
PLIST
sed 's/MessageType/Status/' "$FPD/body_checkin.plist" >"$FPD/body_connect.plist"
printf '{"request_type":"RingoAuditProbe","device_udid":"00000000-AUDIT"}' >"$FPD/body_agent.json"
{ printf '\x30\x82\x01\x00\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02'; head -c 241 /dev/urandom; } >"$FPD/body_pkcs7.der"
# варианты для поиска причины блокировки
grep -v '^<!DOCTYPE' "$FPD/body_checkin.plist" >"$FPD/body_checkin_nodtd.plist"
grep -v '^<!DOCTYPE' "$FPD/body_connect.plist" >"$FPD/body_connect_nodtd.plist"
