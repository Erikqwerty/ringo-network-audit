#!/usr/bin/env python3
# Большая передача по TLS с заданным MSS: проходят ли полноразмерные пакеты в обе стороны.
# MSS (TCP_MAXSEG) ограничивает размер сегментов и в нашу сторону (его объявляем серверу), и от нас.
# Если с MSS по умолчанию передача встаёт, а с меньшим идёт — на пути «чёрная дыра» MTU:
# большие пакеты теряются, а ICMP «need fragmentation» до отправителя не доходит.
#
#   mss_probe.py имя ip порт путь down|up mss байт [таймаут]
#   mss 0 — по умолчанию (как у обычного клиента)
# До подключения MSS задаётся только в Linux — тогда он ограничивает обе стороны. macOS позволяет лишь
# уменьшить его после подключения: ограничена только отправка (up), приём идёт с MSS по умолчанию.
# Печатает одну строку:
#   ok <байт> <мс> <код HTTP> <mss: pre|post|-> — передача прошла
#   stall <байт> <этап>           — данные перестали идти (этап: tls — рукопожатие, send — отправка, recv — приём)
#   err <этап> <сообщение>        — соединение не установлено или оборвано
import socket, ssl, sys, time

name, ip, port, path, direction, mss, size = sys.argv[1:8]
port, mss, size = int(port), int(mss), int(size)
stall = float(sys.argv[8]) if len(sys.argv) > 8 else 6.0
t0 = time.time()
got = 0
stage = "tcp"
how = "-"
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if mss:
        try:
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, mss); how = "pre"
        except OSError:
            pass
    s.settimeout(stall)
    s.connect((ip, port))
    if mss and how == "-":
        try:
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, mss); how = "post"
        except OSError:
            pass
    stage = "tls"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    t = ctx.wrap_socket(s, server_hostname=name)
    if direction == "down":
        req = ("GET %s HTTP/1.1\r\nHost: %s\r\nRange: bytes=0-%d\r\nUser-Agent: ringo-audit\r\n"
               "Connection: close\r\n\r\n" % (path, name, size - 1)).encode()
        stage = "send"
        t.sendall(req)
    else:
        # text/plain приложение не разбирает как JSON: ответит 400, ничего не создав
        hdr = ("POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n"
               "User-Agent: ringo-audit\r\nConnection: close\r\n\r\n" % (path, name, size)).encode()
        stage = "send"
        t.sendall(hdr)
        chunk = b"A" * 16384
        sent = 0
        while sent < size:
            n = min(len(chunk), size - sent)
            t.sendall(chunk[:n])
            sent += n
        got = sent
    stage = "recv"
    buf = b""
    while True:
        d = t.recv(65536)
        if not d:
            break
        if direction == "down":
            got += len(d)
        buf = (buf + d)[:256] if len(buf) < 256 else buf
        if direction == "down" and got >= size:
            break
        if direction == "up" and b"\r\n" in buf:
            break
    code = buf.split(b" ", 2)[1].decode(errors="replace") if buf.startswith(b"HTTP/") else "000"
    print("ok %d %d %s %s" % (got, (time.time() - t0) * 1000, code, how))
except socket.timeout:
    print("stall %d %s" % (got, stage))
except (ssl.SSLError, OSError) as e:
    print("err %s %s" % (stage, str(e).replace("\n", " ")[:120]))
