#!/usr/bin/env python3
# Удержание websocket агента (socket.io) через прокси: сколько живёт соединение и кто его закрывает.
# Агент Ringo держит websocket постоянно; если прокси или балансировщик рвёт его по таймауту,
# агент «то онлайн, то оффлайн». Клиент ведёт себя как агент: отвечает на ping сервера (EIO=4)
# или сам шлёт ping (EIO=3), подключается к пространству «/» и переподключается после разрыва.
#
#   ws_hold.py имя ip порт eio секунд                    — удержание, события построчно в stdout
#       eio: 4 (socket.io v3+), 3 (v2) или auto — сначала 4, при отказе в upgrade — 3
#   ws_hold.py имя ip порт eio 0 --mon лог интервал стоп  — для мониторинга: каждые «интервал» секунд
#       строка «проба|время|статус|мс|подробности» в лог, пока не появится файл «стоп»
#
# События (stdout):
#   start N                      — сессия N: подключение
#   open N <мс> <pingInterval> <pingTimeout> — websocket открыт (мс — TCP+TLS+upgrade)
#   ns N ok | ns N error <текст> — подключение к «/»: принято / отказ (обычно — нет авторизации агента)
#   end N <причина> <с> <ping>   — конец сессии: причина, сколько жила, сколько ping прошло
#        причины: done — время вышло (закрыли мы); close:<код> — пришёл close-кадр;
#                 disconnect — сервер отключил socket.io; eof — TCP закрыт без close-кадра;
#                 rst — сброс; silent — данные перестали идти; fail:<этап> — не подключились
import base64, os, socket, ssl, struct, sys, time

name, ip, port, eio, total = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4], float(sys.argv[5])
MON = None
if len(sys.argv) > 6 and sys.argv[6] == "--mon":
    MON = {"log": sys.argv[7], "interval": float(sys.argv[8]), "stop": sys.argv[9], "n": 0, "next": time.time()}


def say(*a):
    if MON is None:
        print(*a, flush=True)


class Gone(Exception):
    pass


def connect():
    t0 = time.time()
    s = socket.create_connection((ip, port), timeout=10)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    t = ctx.wrap_socket(s, server_hostname=name)
    key = base64.b64encode(os.urandom(16)).decode()
    t.sendall(("GET /socket.io/?EIO=%s&transport=websocket HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\n"
               "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n"
               "User-Agent: ringo-audit\r\n\r\n" % (eio, name, key)).encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = t.recv(4096)
        if not d:
            raise Gone("upgrade")
        buf += d
    head, rest = buf.split(b"\r\n\r\n", 1)
    code = head.split(b" ", 2)[1].decode() if head.startswith(b"HTTP/") else "000"
    if code != "101":
        raise Gone("upgrade-%s" % code)
    return t, rest, int((time.time() - t0) * 1000)


def send(t, text, op=1):
    data = text.encode() if isinstance(text, str) else text
    mask = os.urandom(4)
    n = len(data)
    hdr = bytes([0x80 | op])
    hdr += bytes([0x80 | n]) if n < 126 else bytes([0x80 | 126]) + struct.pack("!H", n)
    t.sendall(hdr + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))


class Reader:
    # кадр читается целиком или не читается вовсе: при таймауте посреди кадра прочитанное остаётся в буфере
    def __init__(self, t, rest):
        self.t, self.buf, self.pos = t, rest, 0

    def need(self, n):
        while len(self.buf) - self.pos < n:
            d = self.t.recv(65536)
            if not d:
                raise Gone("eof")
            self.buf += d
        out = self.buf[self.pos:self.pos + n]
        self.pos += n
        return out

    def frame(self):
        self.pos = 0
        b1, b2 = self.need(2)
        n = b2 & 0x7F
        if n == 126:
            n = struct.unpack("!H", self.need(2))[0]
        elif n == 127:
            n = struct.unpack("!Q", self.need(8))[0]
        if b2 & 0x80:
            self.need(4)
        data = self.need(n)
        self.buf, self.pos = self.buf[self.pos:], 0
        return b1 & 0x0F, data


def mon_tick(status, ms, det, force=False):
    # мониторинг: строка лога раз в интервал (или сразу — при разрыве)
    now = time.time()
    if MON is None or (not force and now < MON["next"]):
        return
    MON["n"] += 1
    MON["next"] = now + MON["interval"]
    with open(MON["log"], "a") as f:
        f.write("%d|%s|%s|%d|%s\n" % (MON["n"], time.strftime("%H:%M:%S"), status, ms, det))


def stop_now(t_end):
    if MON is not None:
        return os.path.exists(MON["stop"])
    return time.time() >= t_end


def session(n, t_end):
    global eio
    say("start", n)
    try:
        if eio == "auto":
            try:
                eio = "4"
                t, rest, ms = connect()
            except Gone:
                eio = "3"
                t, rest, ms = connect()
        else:
            t, rest, ms = connect()
    except Gone as e:
        return "fail:%s" % e, 0, 0, 0, False
    except socket.timeout:
        return "fail:timeout", 0, 0, 0, False
    except (ssl.SSLError, OSError) as e:
        return "fail:%s" % ("rst" if "reset" in str(e).lower() else "tcp"), 0, 0, 0, False
    r = Reader(t, rest)
    born = time.time()
    pings, ping_iv, ping_to, auth_err = 0, 25.0, 20.0, False
    last_rx, last_tx = time.time(), time.time()
    reason = "done"
    try:
        while True:
            if stop_now(t_end):
                try:
                    send(t, b"\x03\xe8", 8)
                except OSError:
                    pass
                break
            age = int(time.time() - born)
            mon_tick("ok", ms, "websocket открыт %d с, ping %d" % (age, pings))
            # EIO=3: ping шлёт клиент
            if eio == "3" and time.time() - last_tx >= ping_iv:
                send(t, "2"); last_tx = time.time()
            t.settimeout(1.0)
            try:
                op, data = r.frame()
            except socket.timeout:
                if time.time() - last_rx > ping_iv + ping_to + 5:
                    reason = "silent"
                    break
                continue
            last_rx = time.time()
            if op == 8:
                code = struct.unpack("!H", data[:2])[0] if len(data) >= 2 else 1005
                reason = "close:%d" % code
                break
            if op == 9:
                send(t, data, 10)
                continue
            if op != 1:
                continue
            msg = data.decode(errors="replace")
            if msg.startswith("0{"):
                try:
                    import json
                    o = json.loads(msg[1:])
                    ping_iv, ping_to = o.get("pingInterval", 25000) / 1000.0, o.get("pingTimeout", 20000) / 1000.0
                except ValueError:
                    pass
                say("open", n, ms, int(ping_iv), int(ping_to))
                send(t, "40"); last_tx = time.time()
            elif msg == "2":                      # EIO=4: ping сервера — отвечаем pong
                send(t, "3"); last_tx = time.time(); pings += 1
            elif msg == "3":                      # EIO=3: pong на наш ping
                pings += 1
            elif msg.startswith("40"):
                say("ns", n, "ok")
            elif msg.startswith("44"):
                say("ns", n, "error", msg[2:200]); auth_err = True
            elif msg.startswith("41") or msg == "1":
                reason = "disconnect"
                break
    except Gone as e:
        reason = str(e)
    except (ssl.SSLError, OSError) as e:
        reason = "rst" if "reset" in str(e).lower() else "eof"
    try:
        t.close()
    except OSError:
        pass
    return reason, time.time() - born, pings, ms, auth_err


TXT = {"done": "держалось до конца", "eof": "TCP закрыт без close-кадра", "rst": "сброс соединения (RST)",
       "silent": "данные перестали идти", "disconnect": "сервер отключил socket.io"}

t_end = time.time() + total
n = 0
while not stop_now(t_end):
    n += 1
    reason, life, pings, ms, auth_err = session(n, t_end)
    say("end", n, reason, int(life), pings)
    # без авторизации агента socket.io закрывает соединение сам через ~45 с (connectTimeout) — не разрыв
    if auth_err and life >= 40 and (reason.startswith("close:") or reason == "disconnect"):
        mon_tick("ok", ms, "переподключение: сервер закрыл неавторизованное соединение через %d с — норма" % life, force=True)
    elif reason != "done":
        why = TXT.get(reason) or ("close-кадр %s" % reason[6:] if reason.startswith("close:") else "не подключились: %s" % reason[5:])
        mon_tick("fail", ms, "разрыв через %d с: %s" % (life, why), force=True)
        time.sleep(2)
