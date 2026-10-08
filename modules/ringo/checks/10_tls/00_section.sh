# shellcheck shell=bash
# Раздел TLS: версии протокола, цепочка и сертификат, порт 80. Без https проверять нечего —
# остальные файлы раздела в этом случае сами пропускаются.

echo
echo " ${BD}${B}▸ TLS (требование документации: TLS 1.2 и TLS 1.3)${N}"
if [[ "$HOST" != https://* ]]; then
  printf "   %s схема не https — проверка пропущена\n" "$(badge WARN)"; count WARN "схема не https"
fi
