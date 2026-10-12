# Заметки для доработки

Карта: `README.md` → «Как устроен проект». Правьте узкий файл, а не читайте всё подряд:

| Задача | Файл |
|---|---|
| новый эндпоинт Ringo | `modules/ringo/lib/endpoints.sh` (маршруты устройств из swagger добавляются сами) |
| логика вердикта эндпоинта | `endpoint_verdict` в `modules/ringo/checks/20_endpoints/20_endpoints.sh` |
| HTTP-проба, разбор ответа NestJS | `modules/ringo/lib/http.sh` |
| TLS, цепочка, сертификат | `modules/ringo/checks/10_tls/` (файл на проверку); имена и заглушки — `lib/tls.sh` |
| любая другая проверка | `modules/<модуль>/checks/NN_раздел/NN_проверка.sh` — карта разделов в README |
| версия Ringo, swagger, снимки схем | `modules/ringo/lib/api.sh` |
| что значит ответ приложения | `schemas/known_responses.tsv` (данные), `resp_explain` в `lib/api.sh` |
| хосты Apple | `modules/apple/lib/targets.sh` |
| вид отчёта | `report/style.css`, `report/app.js`; разбор строк — `render_module` в `report/build.sh` |
| окно «Подробнее» | данные — `lib/detail.sh` (+ `det_probe` в `modules/ringo/lib/http.sh`), окно — `report/app.js` |
| флаги мастера, `--full`, `--watch`, `--archive` | `audit.sh`, запуск модулей — `lib/runner.sh` |
| «Что делать» у WARN/FAIL | `lib/remedies.tsv` (регулярка по подписи `count` → действие), вставка — `det_remedy` в `lib/ui.sh` |
| DNS, узлы, часы, MTU | `modules/ringo/checks/15_path/`; MTU по TCP — `modules/ringo/lib/mss_probe.py` |
| удержание websocket | запуск — `00_header/65_ws_hold.sh`, итог — `75_ws_hold/`, клиент — `modules/ringo/lib/ws_hold.py` |
| мониторинг, цель `ws:` | `modules/monitor/monitor.sh` |
| сравнение двух запусков (`--diff`) | `report/diff.sh` |
| сборка одним файлом | `tools/bundle.sh` |

## Соглашения

- bash 3.2 (macOS): без ассоциативных массивов, `${x,,}`, `mapfile`; `local -a` можно.
- Переменная перед кириллицей или `»` — только в фигурных скобках: `"${VAR}»"`. Иначе bash 3.2
  склеивает байты UTF-8 с именем → `unbound variable`.
- `checks/NN_раздел/NN_проверка.sh` подключаются через `source` по порядку и делят глобальные переменные
  модуля. Один файл — одна проверка: шапка (что, почему, когда какой итог, «Задаёт: …»), условие запуска
  `… || return 0`, функции только этой проверки, сама проверка. Общее для нескольких — в `lib/`.
  `count` нельзя вызывать внутри `$(…)` — счётчик останется в подоболочке.
- Каждый WARN/FAIL — с подписью: `count WARN "что не так"` (попадает в «Итог: что требует внимания»).
  Новая подпись — добавьте правило в `lib/remedies.tsv`, иначе у замечания не будет «Что делать».
  `count` вписывает действие в открытые подробности, поэтому зовите его до `det_ref`.
- У каждой строки проверки — подробности: `det_new "заголовок"` → `det_cmd`/`det_kv`/`det_file`
  (для HTTP — `det_probe` сразу после пробы, пока `$TMP` не перезаписан) → `printf` строки → `det_ref`.
  `det_ref` — строго после строки проверки, иначе подробности уйдут к соседней.
- Формат строк вывода — контракт с отчётом (см. шапку `lib/ui.sh`). Изменили формат — проверьте
  `render_module` и `tests/run.sh`.
- Комментарии и вывод — на русском, коротко, объясняют «почему».

## Проверка изменений

1. `./tests/run.sh` — синтаксис и юнит-тесты, без сети.
2. Живой прогон: `modules/ringo/run.sh https://<сервер> --scep-proxy` (и `--internal` для закрытого сервера).
3. Отчёт: `./audit.sh --rebuild results/<папка>` и открыть `report.html`.
