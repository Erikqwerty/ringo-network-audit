# shellcheck shell=bash
# Список проверяемых эндпоинтов (дополняется маршрутами из схемы API в checks/20_endpoints/10_prepare.sh).
# Подключается через source из modules/ringo/run.sh; сам не запускается.

# ---------- эндпоинты ----------
# Сверено с docs.ringomdm.ru (Reverse Proxy) и swagger сервера (/api/v1/documentation-json).
# Метод — как у настоящего клиента: check-in/connect — PUT, OTA-профиль и авторизация — POST.
# Тело запросов пустое: приложение отвечает 400 с JSON {"statusCode":…} — значит, запрос дошёл до Ringo.
# метод|путь|Content-Type|группа|публичный(1/0)|пояснение
endpoints_init() {
  JSON=application/json
  ENDPOINTS=(
    "GET|/scep?operation=GetCACaps||MDM|1|SCEP: возможности CA"
    "PUT|/mdm/checkin|application/x-apple-aspen-mdm-checkin|MDM|1|check-in устройств"
    "PUT|/mdm/connect|application/x-apple-aspen-mdm|MDM|1|получение MDM-команд"
    "GET|/socket.io/||Агент|1|websocket агента"
    "GET|/agent/bundle||Агент|1|пакет агента"
    "GET|/agent/manifest||Агент|1|манифест агента"
    "POST|/agent/certificate|$JSON|Агент|1|сертификат идентификации агента"
    "PUT|/agent/checkin|$JSON|Агент|1|check-in агента"
    "PUT|/agent/connect|$JSON|Агент|1|команды агента"
    "GET|/enroll||Enroll|1|страница регистрации"
    "POST|/enroll/auth|$JSON|Enroll|1|вход на странице регистрации"
    "GET|/mdm/enroll||Enroll|1|скачивание MDM-профиля"
    "POST|/mdm/enroll/profile|application/pkcs7-signature|Enroll|1|OTA-профиль"
    "POST|/api/v1/auth|$JSON|Enroll|1|аутентификация (по схеме документации — публичный)"
    "POST|/api/v1/self-service/auth|$JSON|Self Service|1|вход в портал самообслуживания"
  )
  (( CHECK_SCEP_PROXY )) && ENDPOINTS+=("GET|/scep-proxy?operation=GetCACaps||SCEP Proxy|1|прокси к внешнему SCEP")
  GUI="Веб-интерфейс и API (по рекомендации — только для подсети)"
  ENDPOINTS+=(
    "GET|/||$GUI|0|UI"
    "GET|/api/v1/version||$GUI|0|API интерфейса"
    "GET|/api/v1/device-users||$GUI|0|API интерфейса"
    "GET|/api/v1/documentation-json||$GUI|0|Swagger: полная карта API"
  )
}
