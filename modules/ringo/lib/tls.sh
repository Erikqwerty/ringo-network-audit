# shellcheck shell=bash
# Сертификат: имена (CN/SAN с учётом *.домен) и сертификаты-заглушки обратных прокси.
# Сами проверки TLS — в checks/10_tls/. Подключается через source из modules/ringo/run.sh; сам не запускается.

# сертификаты-заглушки обратных прокси: их отдают вместо настоящего, когда для имени ничего не настроено
PLACEHOLDER_RE='letsencrypt-nginx-proxy-companion|traefik default cert|kubernetes ingress controller fake certificate|ssl-cert-snakeoil|^localhost(\.localdomain)?$|^nginx$|default'
placeholder_hint() { # CN заглушки -> что это значит
  case "$(tr 'A-Z' 'a-z' <<<"$1")" in
    *letsencrypt-nginx-proxy-companion*) echo "nginx-proxy (+ acme-companion) отдаёт заглушку: для этого имени нет виртуального хоста или сертификата — контейнер Ringo не запущен / без VIRTUAL_HOST, либо Let's Encrypt не выпустил сертификат" ;;
    *traefik*)    echo "Traefik отдаёт сертификат по умолчанию: для этого имени нет роутера или TLS-сертификата" ;;
    *kubernetes*) echo "ingress-nginx отдаёт поддельный сертификат по умолчанию: нет Ingress с TLS для этого имени" ;;
    *)            echo "прокси отдаёт сертификат по умолчанию: для этого имени ничего не настроено" ;;
  esac
}
name_ok() { # имя, список имён сертификата (по строке) -> совпадает ли (с учётом *.домен)
  local h="$1" n pre
  while IFS= read -r n; do
    [[ -z "$n" ]] && continue
    n="$(tr 'A-Z' 'a-z' <<<"$n")"
    [[ "$n" == "$h" ]] && return 0
    if [[ "$n" == \*.* ]]; then   # *.домен покрывает ровно один уровень: a.домен, но не a.b.домен
      pre="${h%."${n#\*.}"}"
      [[ "$pre" != "$h" && -n "$pre" && "$pre" != *.* ]] && return 0
    fi
  done <<<"$2"
  return 1
}
cn_of() { sed -nE 's/.*CN *= *([^,/]+).*/\1/p' <<<"$1" | head -1; }
