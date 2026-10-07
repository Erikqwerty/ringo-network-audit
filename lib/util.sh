# shellcheck shell=bash
# Общие утилиты. Подключается через source; сам не запускается. Совместимо с bash 3.2 (macOS).

# Числа — всегда с точкой. В ru_RU awk читает «23.421668» как 23 и печатает «0,0»: ломаются RTT
# из pcap, паузы, тайминги. LC_ALL перекрыл бы LC_NUMERIC, поэтому переносим его в LANG (UTF-8 сохраняется).
if [[ -n "${LC_ALL:-}" ]]; then export LANG="$LC_ALL"; unset LC_ALL; fi
export LC_NUMERIC=C

have() { command -v "$1" >/dev/null 2>&1; }
now_ms() { perl -MTime::HiRes=time -e 'printf "%d", time*1000'; }
host_of() { local h="${1#*://}"; h="${h%%/*}"; echo "${h%%:*}"; }

# таймаут для команд без своего (openssl s_client и т. п.): timeout/gtimeout, иначе perl alarm
TOUT="$(command -v timeout || command -v gtimeout || true)"
with_timeout() { # секунды, команда...
  local s="$1"; shift
  if [[ -n "$TOUT" ]]; then "$TOUT" "$s" "$@"
  else perl -e 'alarm shift; exec @ARGV' "$s" "$@"; fi
}

# python3, который можно звать без побочных эффектов: /usr/bin/python3 без Command Line Tools
# открывает окно установки — такой не годится. Печатает путь или ничего.
safe_python() {
  local py; py="$(command -v python3 || true)"
  [[ "$py" == /usr/bin/python3 ]] && ! xcode-select -p >/dev/null 2>&1 && py=""
  printf '%s' "$py"
}
