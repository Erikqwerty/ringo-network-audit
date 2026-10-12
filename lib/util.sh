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

# сдвиг часов этого компьютера относительно NTP-сервера, в секундах («+1.25» — наши часы отстают).
# python3 (UDP 123 напрямую, до трёх попыток), иначе sntp. Код: 0 — есть ответ, 1 — нет ответа, 9 — нечем проверить.
ntp_offset() { # хост
  local py out; py="$(safe_python)"
  if [[ -n "$py" ]]; then
    out=$("$py" - "$1" <<'PY' 2>/dev/null
import socket, struct, sys, time
# UDP теряется: разовая потеря — ещё не «NTP закрыт», поэтому три попытки
for _ in range(3):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2)
    try:
        t0 = time.time(); s.sendto(b'\x1b' + 47 * b'\0', (sys.argv[1], 123)); d, _ = s.recvfrom(512); t1 = time.time()
        w = struct.unpack('!12I', d[:48])
        print("%+.2f" % (w[10] - 2208988800 + w[11] / 2**32 - (t0 + t1) / 2)); sys.exit(0)
    except (OSError, struct.error):
        pass
sys.exit(1)
PY
) || return 1
  elif have sntp; then
    out=$(with_timeout 6 sntp -t 3 "$1" 2>/dev/null | awk 'NR==1 && $1 ~ /^[+-]?[0-9.]+$/ {print $1}')
    [[ -n "$out" ]] || return 1
  else return 9; fi
  printf '%s' "$out"
}
