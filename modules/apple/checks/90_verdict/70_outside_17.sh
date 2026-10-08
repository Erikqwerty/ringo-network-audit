# shellcheck shell=bash
# Хосты вне 17.0.0.0/8 (CDN): при allow-list по IP их придётся разрешать отдельно. Итог: INFO, если такие есть.

if [[ "$OUTSIDE_LIST" != "|" ]]; then
  n=$(tr -cd '|' <<<"$OUTSIDE_LIST" | awk '{print length($0)-1}')
  verdict INFO "Хостов вне 17.0.0.0/8 (CDN): $n — при allow-list по IP их придётся разрешать отдельно, надёжнее фильтровать по имени"; count INFO
fi
