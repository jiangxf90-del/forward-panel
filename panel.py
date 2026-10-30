#!/usr/bin/env python3
"""Forwarding-rules panel for a transit/relay VPS.

This is a small self-hosted panel, installed on the relay machine itself
(like 3xui). It manages *pure forwarding* rules: it does NOT terminate any
proxy protocol. Each rule listens on one port of this machine and forwards
raw bytes (TCP and UDP) to a landing node's address:port. The phone's node
config points at this machine's entry address:port; the landing still speaks
its own protocol (e.g. SOCKS5) and its credentials do not change.

Python 3 standard library only -- no pip packages, no external services.

Files:
    data/rules.json   rule list (created on first save)
    data/admin.json   salted admin password hash (never a plaintext password)

Environment variables:
    PANEL_HOST        bind address, default 0.0.0.0
    PANEL_PORT        panel port, default 2080
    PANEL_DATA_DIR    data directory, default <package>/data
    RELAY_IP          override for the entry address shown in the panel
                      (auto-detected when unset)

Usage:
    python3 panel.py [--host 127.0.0.1] [--port 2080]
    python3 panel.py --set-admin   # read password from stdin, store hash only
"""

import argparse
import asyncio
import hashlib
import hmac
import json
import os
import random
import re
import secrets
import sys
import time
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
DEFAULT_PORT = 2080
DEFAULT_HOST = "0.0.0.0"
SESSION_TTL = 24 * 3600          # login sessions last 24 hours
PBKDF2_ITERATIONS = 200_000     # password hashing cost
UDP_SESSION_IDLE = 120           # seconds before an idle UDP session closes
SAVE_INTERVAL = 15               # seconds between traffic-counter saves


def get_data_dir():
    """Data directory: explicit --data-dir / PANEL_DATA_DIR, else <package>/data."""
    override = os.environ.get("PANEL_DATA_DIR")
    if override:
        return Path(override)
    return PACKAGE_DIR / "data"


def detect_relay_ip():
    """IP address this machine is reached at, for display as the rule entry.

    Order: RELAY_IP env override, else the source address the OS would use
    for outbound traffic (a route lookup -- no packet is actually sent),
    else 127.0.0.1. The entry address is only a display value: forwarders
    bind 0.0.0.0, so any address of this machine works.
    """
    override = os.environ.get("RELAY_IP")
    if override:
        return override
    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # connect() on a UDP socket sends nothing; it only picks a route.
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
        finally:
            sock.close()
    except Exception:
        return "127.0.0.1"


# ---------------------------------------------------------------------------
# Password handling: only a salted PBKDF2 hash is ever stored.
# ---------------------------------------------------------------------------

def hash_password(password, salt=None):
    """Return (salt_hex, hash_hex) for a password."""
    if salt is None:
        salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
    )
    return salt.hex(), digest.hex()


def verify_password(password, salt_hex, hash_hex):
    """Constant-time password check against a stored salt/hash pair."""
    try:
        salt = bytes.fromhex(salt_hex)
        _, digest_hex = hash_password(password, salt)
        return hmac.compare_digest(digest_hex, hash_hex)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Target validation: one "host:port" per rule.
# host may be an IPv4 address, a [bracketed IPv6] address, or a domain name.
# ---------------------------------------------------------------------------

_HOST_RE = re.compile(
    r"^(?:"
    r"(?:\d{1,3}\.){3}\d{1,3}"                       # IPv4
    r"|(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"  # domain name
    r"|\[[0-9A-Fa-f:]+\]"                            # [IPv6]
    r")$"
)


def parse_limit(value, field):
    """Parse an advanced-option limit: blank/None -> 0 (unlimited).

    0 means unlimited for all three limits. Negative or non-integer
    values are rejected.
    """
    if value in (None, ""):
        return 0
    if isinstance(value, bool):
        raise ValueError(f"{field} must be a number")
    if isinstance(value, str):
        value = value.strip()
        if value == "":
            return 0
        if not value.isdigit():
            raise ValueError(f"{field} must be a non-negative number")
        value = int(value)
    if not isinstance(value, int) or value < 0:
        raise ValueError(f"{field} must be a non-negative number")
    return value


def parse_target(text):
    """Parse 'host:port' into (host, port). Raises ValueError on bad input.

    IPv6 must be bracketed, e.g. [2001:db8::1]:1080, so the final colon
    unambiguously separates the port.
    """
    if not text or not isinstance(text, str):
        raise ValueError("target address is required")
    text = text.strip()
    if text.startswith("["):
        # Bracketed IPv6: [addr]:port
        end = text.find("]")
        if end == -1 or not text[end + 1:].startswith(":"):
            raise ValueError("IPv6 target must look like [2001:db8::1]:1080")
        host, port_text = text[: end + 1], text[end + 2:]
    else:
        if ":" not in text:
            raise ValueError("target must be host:port, e.g. 203.0.113.10:1080")
        host, port_text = text.rsplit(":", 1)
    if not _HOST_RE.match(host):
        raise ValueError("invalid host in target address")
    if not port_text.isdigit():
        raise ValueError("port must be a number")
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    return host, port


# ---------------------------------------------------------------------------
# Rule storage
# ---------------------------------------------------------------------------

class Panel:
    """Holds rules, forwarders, sessions, and the JSON store."""

    def __init__(self, data_dir, host, port):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.rules_file = self.data_dir / "rules.json"
        self.admin_file = self.data_dir / "admin.json"
        self.host = host
        self.port = port
        self.relay_ip = detect_relay_ip()
        self.rules = {}        # rule id -> rule dict
        self.forwarders = {}   # rule id -> RuleForwarder
        self.sessions = {}     # session token -> expiry timestamp
        self._dirty = False    # traffic counters changed since last save

    # -- persistence ------------------------------------------------------
    def load_rules(self):
        if not self.rules_file.exists():
            return
        try:
            with open(self.rules_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            for rule in data.get("rules", []):
                if isinstance(rule, dict) and rule.get("id"):
                    self.rules[rule["id"]] = rule
            print(f"[panel] loaded {len(self.rules)} rule(s) from {self.rules_file}",
                  flush=True)
        except Exception as exc:
            print(f"[panel] WARNING: could not load {self.rules_file}: {exc}",
                  flush=True)

    def save_rules(self):
        """Atomic save: write a temp file, then rename over the old one."""
        tmp = self.rules_file.with_suffix(".json.tmp")
        payload = {"rules": list(self.rules.values())}
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        os.replace(tmp, self.rules_file)
        self._dirty = False

    def mark_dirty(self):
        """Traffic counters moved; a background task saves them shortly."""
        self._dirty = True

    # -- admin / sessions ---------------------------------------------------
    def admin_exists(self):
        return self.admin_file.exists()

    def check_password(self, password):
        try:
            with open(self.admin_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            return verify_password(password, data["salt"], data["hash"])
        except Exception:
            return False

    def new_session(self):
        token = secrets.token_hex(32)
        self.sessions[token] = time.time() + SESSION_TTL
        return token

    def valid_session(self, token):
        if not token:
            return False
        expiry = self.sessions.get(token)
        if expiry is None or expiry < time.time():
            self.sessions.pop(token, None)
            return False
        return True

    def drop_session(self, token):
        self.sessions.pop(token, None)

    # -- rules ---------------------------------------------------------------
    def used_ports(self):
        return {r["listen_port"] for r in self.rules.values()}

    def pick_random_port(self):
        """Random free listen port in 10000-65535 (never the panel port)."""
        taken = self.used_ports() | {self.port}
        for _ in range(200):
            port = random.randint(10000, 65535)
            if port not in taken:
                return port
        raise ValueError("no free listen port available in 10000-65535")

    def entry_of(self, rule):
        """Entry address shown to the user: relay_ip:listen_port."""
        return f"{self.relay_ip}:{rule['listen_port']}"

    def public_rule(self, rule):
        """Rule dict as sent to the frontend (entry address included)."""
        return {
            "id": rule["id"],
            "name": rule["name"],
            "group": rule["group"],
            "listen_port": rule["listen_port"],
            "entry": self.entry_of(rule),
            "target": f"{rule['target_host']}:{rule['target_port']}",
            "enabled": rule["enabled"],
            "bytes_in": rule["bytes_in"],
            "bytes_out": rule["bytes_out"],
            "created_at": rule["created_at"],
            # Advanced options, 0 = unlimited. Old rules (pre-v2) lack
            # these keys, so default them here instead of migrating files.
            "speed_limit_mbps": rule.get("speed_limit_mbps", 0),
            "ip_limit": rule.get("ip_limit", 0),
            "conn_limit": rule.get("conn_limit", 0),
        }

    async def add_rule(self, name, group, listen_port, target_text,
                       speed_limit_mbps=0, ip_limit=0, conn_limit=0):
        """Validate, store, and (if enabled) start forwarding for a new rule."""
        name = (name or "").strip()
        if not name:
            raise ValueError("rule name is required")
        if len(name) > 64:
            raise ValueError("rule name is too long (max 64 characters)")
        group = (group or "").strip() or "未分组"
        host, target_port = parse_target(target_text)
        speed_limit_mbps = parse_limit(speed_limit_mbps, "speed limit")
        ip_limit = parse_limit(ip_limit, "IP limit")
        conn_limit = parse_limit(conn_limit, "connection limit")
        if listen_port in (None, ""):
            listen_port = self.pick_random_port()
        else:
            listen_port = int(listen_port)
            if not 1 <= listen_port <= 65535:
                raise ValueError("listen port must be between 1 and 65535")
            if listen_port == self.port:
                raise ValueError("listen port must differ from the panel port")
            if listen_port in self.used_ports():
                raise ValueError(f"listen port {listen_port} is already used")
        rule = {
            "id": secrets.token_hex(6),
            "name": name,
            "group": group,
            "listen_port": listen_port,
            "target_host": host,
            "target_port": target_port,
            "speed_limit_mbps": speed_limit_mbps,
            "ip_limit": ip_limit,
            "conn_limit": conn_limit,
            "enabled": True,
            "bytes_in": 0,
            "bytes_out": 0,
            "created_at": int(time.time()),
        }
        self.rules[rule["id"]] = rule
        self.save_rules()
        await self.start_forwarder(rule)
        print(f"[panel] rule added: {name} on port {listen_port}", flush=True)
        return rule

    async def set_enabled(self, rule_id, enabled):
        rule = self.rules.get(rule_id)
        if rule is None:
            raise KeyError("rule not found")
        rule["enabled"] = bool(enabled)
        self.save_rules()
        if enabled:
            await self.start_forwarder(rule)
        else:
            await self.stop_forwarder(rule_id)
        return rule

    async def delete_rule(self, rule_id):
        await self.stop_forwarder(rule_id)
        rule = self.rules.pop(rule_id, None)
        if rule is not None:
            self.save_rules()
            print(f"[panel] rule deleted: {rule['name']}", flush=True)
        return rule

    async def start_forwarder(self, rule):
        if rule["id"] in self.forwarders:
            return
        forwarder = RuleForwarder(self, rule)
        await forwarder.start()
        self.forwarders[rule["id"]] = forwarder

    async def stop_forwarder(self, rule_id):
        forwarder = self.forwarders.pop(rule_id, None)
        if forwarder is not None:
            await forwarder.stop()

    async def start_enabled_forwarders(self):
        for rule in list(self.rules.values()):
            if rule.get("enabled"):
                try:
                    await self.start_forwarder(rule)
                except Exception as exc:
                    print(f"[panel] WARNING: could not start rule "
                          f"{rule['name']}: {exc}", flush=True)

    async def stop_all_forwarders(self):
        for rule_id in list(self.forwarders):
            await self.stop_forwarder(rule_id)


# ---------------------------------------------------------------------------
# Forwarders: one per rule, TCP + UDP, userspace (no root-only features).
# ---------------------------------------------------------------------------

class _RateLimiter:
    """Per-rule token bucket. 0 Mbps means unlimited (no waiting at all).

    Up and down pumps share one bucket, so the cap is the rule's total
    (up + down). Tokens refill at the configured rate, with at most one
    second's worth banked, so a burst cannot exceed roughly one second
    of traffic over the cap.
    """

    def __init__(self, mbps):
        self.rate = mbps * 1_000_000 // 8 if mbps else 0  # bytes/second
        self.tokens = float(self.rate)
        self.last = time.monotonic()
        self.lock = asyncio.Lock()

    async def consume(self, n):
        if self.rate <= 0:
            return
        async with self.lock:
            while True:
                now = time.monotonic()
                self.tokens = min(
                    float(self.rate),
                    self.tokens + (now - self.last) * self.rate)
                self.last = now
                if self.tokens >= n:
                    self.tokens -= n
                    return
                wait = (n - self.tokens) / self.rate
                self.tokens = 0.0
                self.last = time.monotonic()
                await asyncio.sleep(wait)


class RuleForwarder:
    """Listens on a rule's port and forwards raw bytes to its target."""

    def __init__(self, panel, rule):
        self.panel = panel
        self.rule = rule
        self.tcp_server = None
        self.udp_transport = None
        self.tcp_tasks = set()     # pump tasks for live TCP connections
        self.tcp_conns = set()     # (client_writer, target_writer) pairs
        self.udp_sessions = {}     # client addr -> _UDPSession
        self.running = False
        # Advanced limits, all 0 = unlimited. seen_ips is in-memory only:
        # it resets when the rule is paused/resumed or the panel restarts,
        # so re-enabling a rule re-locks it to the next device that connects.
        self.seen_ips = set()
        self.rate_limiter = _RateLimiter(rule.get("speed_limit_mbps", 0))

    def ip_allowed(self, ip):
        """IP limit: max distinct source IPs, 0 = unlimited.

        The first ip_limit distinct IPs are remembered; any further IP
        is rejected. With ip_limit=1, a rule copied to another phone
        (different source IP) cannot connect at all.
        """
        limit = self.rule.get("ip_limit", 0)
        if not limit or ip in self.seen_ips:
            return True
        if len(self.seen_ips) >= limit:
            return False
        self.seen_ips.add(ip)
        return True

    async def start(self):
        if self.running:
            return
        loop = asyncio.get_running_loop()
        port = self.rule["listen_port"]
        # TCP and UDP may share one port (different protocols).
        self.tcp_server = await asyncio.start_server(
            self._handle_tcp, "0.0.0.0", port)
        try:
            self.udp_transport, _ = await loop.create_datagram_endpoint(
                lambda: _UDPListenProtocol(self),
                local_addr=("0.0.0.0", port))
        except Exception as exc:
            # Some hosts block UDP entirely (sandboxes, containers). The
            # rule still works for TCP; warn instead of failing the rule.
            self.udp_transport = None
            print(f"[panel] WARNING: UDP listen on port {port} failed "
                  f"({exc}); forwarding TCP only for this rule", flush=True)
        self.running = True
        asyncio.ensure_future(self._udp_reaper())
        print(f"[panel] forwarding started on port {port}", flush=True)

    async def stop(self):
        self.running = False
        if self.tcp_server is not None:
            self.tcp_server.close()
            await self.tcp_server.wait_closed()
            self.tcp_server = None
        for task in list(self.tcp_tasks):
            task.cancel()
        for client_writer, target_writer in list(self.tcp_conns):
            for writer in (client_writer, target_writer):
                try:
                    writer.close()
                except Exception:
                    pass
        self.tcp_conns.clear()
        self.tcp_tasks.clear()
        for session in list(self.udp_sessions.values()):
            session.close()
        self.udp_sessions.clear()
        if self.udp_transport is not None:
            self.udp_transport.close()
            self.udp_transport = None
        print(f"[panel] forwarding stopped on port {self.rule['listen_port']}",
              flush=True)

    # -- TCP ---------------------------------------------------------------
    async def _handle_tcp(self, client_reader, client_writer):
        """One phone/client connection: open the target, pump both ways."""
        peer = client_writer.get_extra_info("peername") or (None,)
        if not self.ip_allowed(peer[0] if peer[0] else "unknown"):
            try:
                client_writer.close()
            except Exception:
                pass
            return
        conn_limit = self.rule.get("conn_limit", 0)
        if conn_limit and len(self.tcp_conns) >= conn_limit:
            try:
                client_writer.close()
            except Exception:
                pass
            return
        try:
            target_reader, target_writer = await asyncio.wait_for(
                asyncio.open_connection(
                    self.rule["target_host"], self.rule["target_port"]),
                timeout=10)
        except Exception:
            # Target unreachable: drop the client connection cleanly.
            try:
                client_writer.close()
            except Exception:
                pass
            return
        pair = (client_writer, target_writer)
        self.tcp_conns.add(pair)
        pump_up = asyncio.ensure_future(
            self._pump(client_reader, target_writer, "bytes_in"))
        pump_down = asyncio.ensure_future(
            self._pump(target_reader, client_writer, "bytes_out"))
        self.tcp_tasks.add(pump_up)
        self.tcp_tasks.add(pump_down)
        try:
            # When either direction ends, the connection is over.
            await asyncio.wait([pump_up, pump_down],
                               return_when=asyncio.FIRST_COMPLETED)
        finally:
            for task in (pump_up, pump_down):
                if not task.done():
                    task.cancel()
            for writer in pair:
                try:
                    writer.close()
                except Exception:
                    pass
            self.tcp_conns.discard(pair)
            self.tcp_tasks.discard(pump_up)
            self.tcp_tasks.discard(pump_down)

    async def _pump(self, reader, writer, counter_key):
        """Copy bytes one way, counting them. Ends on EOF or error."""
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                await self.rate_limiter.consume(len(data))
                writer.write(data)
                await writer.drain()
                self.rule[counter_key] += len(data)
                self.panel.mark_dirty()
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        # CancelledError is intentionally not caught: stopping the
        # forwarder cancels pumps, and they must actually end.

    # -- UDP ---------------------------------------------------------------
    async def _udp_reaper(self):
        """Close UDP sessions idle for more than UDP_SESSION_IDLE seconds."""
        while self.running:
            await asyncio.sleep(60)
            now = time.time()
            for addr, session in list(self.udp_sessions.items()):
                if now - session.last_seen > UDP_SESSION_IDLE:
                    session.close()
                    self.udp_sessions.pop(addr, None)


class _UDPSession:
    """One phone's UDP flow: client addr <-> one upstream UDP socket."""

    def __init__(self, forwarder, client_addr):
        self.forwarder = forwarder
        self.client_addr = client_addr
        self.transport = None
        self.pending = []   # datagrams received before the socket is ready
        self.closed = False
        self.last_seen = time.time()

    async def ensure(self):
        """Open the upstream socket, then flush queued datagrams."""
        if self.closed or self.transport is not None:
            return
        loop = asyncio.get_running_loop()
        rule = self.forwarder.rule
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _UDPUpstreamProtocol(self),
            remote_addr=(rule["target_host"], rule["target_port"]))
        if self.closed:
            transport.close()
            return
        self.transport = transport
        for data in self.pending:
            transport.sendto(data)
        self.pending.clear()

    def send(self, data):
        if self.transport is not None and not self.closed:
            self.transport.sendto(data)
        elif not self.closed:
            self.pending.append(data)

    def close(self):
        self.closed = True
        if self.transport is not None:
            self.transport.close()
            self.transport = None


class _UDPListenProtocol(asyncio.DatagramProtocol):
    """Receives phone datagrams on the rule's port and forwards them."""

    def __init__(self, forwarder):
        self.forwarder = forwarder

    def datagram_received(self, data, addr):
        rule = self.forwarder.rule
        if not self.forwarder.ip_allowed(addr[0]):
            return
        rule["bytes_in"] += len(data)
        self.forwarder.panel.mark_dirty()
        session = self.forwarder.udp_sessions.get(addr)
        if session is None or session.closed:
            session = _UDPSession(self.forwarder, addr)
            self.forwarder.udp_sessions[addr] = session
            session.send(data)  # queued until ensure() opens the socket
            asyncio.ensure_future(session.ensure())
        else:
            session.send(data)
        session.last_seen = time.time()


class _UDPUpstreamProtocol(asyncio.DatagramProtocol):
    """Receives replies from the target and sends them back to the phone."""

    def __init__(self, session):
        self.session = session

    def datagram_received(self, data, _addr):
        forwarder = self.session.forwarder
        if forwarder.udp_transport is not None:
            forwarder.udp_transport.sendto(data, self.session.client_addr)
        self.session.forwarder.rule["bytes_out"] += len(data)
        self.session.forwarder.panel.mark_dirty()
        self.session.last_seen = time.time()

    def connection_lost(self, _exc):
        self.session.closed = True


# ---------------------------------------------------------------------------
# HTTP server + JSON API (asyncio, standard library only).
# Every request gets "Connection: close" -- simple and robust for a panel.
# ---------------------------------------------------------------------------

REASONS = {
    200: "OK", 201: "Created", 204: "No Content",
    400: "Bad Request", 401: "Unauthorized",
    404: "Not Found", 405: "Method Not Allowed",
    500: "Internal Server Error",
}


def http_response(status, body=b"", content_type="application/json",
                  set_cookie=None):
    lines = [
        f"HTTP/1.1 {status} {REASONS.get(status, 'OK')}",
        f"Content-Type: {content_type}",
        f"Content-Length: {len(body)}",
        "Connection: close",
    ]
    if set_cookie:
        lines.append(f"Set-Cookie: {set_cookie}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8") + body


def json_response(status, obj, set_cookie=None):
    return http_response(status, json.dumps(obj).encode("utf-8"),
                         set_cookie=set_cookie)


def parse_cookies(header_value):
    cookies = {}
    for part in (header_value or "").split(";"):
        part = part.strip()
        if "=" in part:
            key, value = part.split("=", 1)
            cookies[key.strip()] = value.strip()
    return cookies


class HttpServer:
    """Minimal HTTP layer: static frontend + /api/* JSON endpoints."""

    def __init__(self, panel):
        self.panel = panel
        index_path = PACKAGE_DIR / "static" / "index.html"
        self.index_bytes = index_path.read_bytes() if index_path.exists() else b""

    async def handle(self, reader, writer):
        try:
            await self._handle(reader, writer)
        except Exception as exc:
            print(f"[panel] HTTP error: {exc}", flush=True)
            try:
                writer.write(http_response(500, b'{"error":"internal error"}'))
                await writer.drain()
            except Exception:
                pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    async def _handle(self, reader, writer):
        try:
            header_blob = await asyncio.wait_for(
                reader.readuntil(b"\r\n\r\n"), timeout=15)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError):
            return
        lines = header_blob.decode("iso-8859-1").split("\r\n")
        request_line = lines[0].split()
        if len(request_line) < 2:
            return
        method, raw_path = request_line[0], request_line[1]
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip().lower()] = value.strip()
        body = b""
        length = int(headers.get("content-length", "0") or "0")
        if length > 0:
            body = await reader.readexactly(length)
        path = raw_path.split("?", 1)[0]
        session = parse_cookies(headers.get("cookie", "")).get("session")
        logged_in = self.panel.valid_session(session)

        # -- static frontend (no login needed to load the page itself) --
        if method == "GET" and path in ("/", "/index.html"):
            writer.write(http_response(200, self.index_bytes, "text/html"))
            await writer.drain()
            return
        if method == "GET" and path == "/favicon.ico":
            writer.write(http_response(204, b"", "text/plain"))
            await writer.drain()
            return

        # -- API ---------------------------------------------------------
        if not path.startswith("/api/"):
            writer.write(json_response(404, {"error": "not found"}))
            await writer.drain()
            return
        if method == "POST" and path == "/api/login":
            await self._login(writer, body)
            return
        if not logged_in:
            writer.write(json_response(401, {"error": "login required"}))
            await writer.drain()
            return
        if method == "POST" and path == "/api/logout":
            self.panel.drop_session(session)
            writer.write(json_response(
                200, {"ok": True},
                set_cookie="session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"))
            await writer.drain()
            return
        if method == "GET" and path == "/api/me":
            writer.write(json_response(200, {"logged_in": True}))
            await writer.drain()
            return
        if method == "GET" and path == "/api/rules":
            rules = [self.panel.public_rule(r)
                     for r in self.panel.rules.values()]
            writer.write(json_response(200, {
                "relay_ip": self.panel.relay_ip,
                "rules": rules,
                "total_in": sum(r["bytes_in"] for r in self.panel.rules.values()),
                "total_out": sum(r["bytes_out"] for r in self.panel.rules.values()),
            }))
            await writer.drain()
            return
        if method == "POST" and path == "/api/rules":
            await self._create_rule(writer, body)
            return
        if method == "POST" and path == "/api/rules/batch-delete":
            await self._batch_delete(writer, body)
            return
        parts = path.split("/")
        # /api/rules/<id>
        if len(parts) == 4 and parts[1] == "api" and parts[2] == "rules":
            rule_id = parts[3]
            if method == "PATCH":
                await self._toggle_rule(writer, rule_id, body)
                return
            if method == "DELETE":
                rule = await self.panel.delete_rule(rule_id)
                if rule is None:
                    writer.write(json_response(404, {"error": "rule not found"}))
                else:
                    writer.write(json_response(200, {"ok": True}))
                await writer.drain()
                return
        writer.write(json_response(404, {"error": "not found"}))
        await writer.drain()

    async def _login(self, writer, body):
        try:
            data = json.loads(body or b"{}")
        except Exception:
            writer.write(json_response(400, {"error": "invalid JSON"}))
            await writer.drain()
            return
        # Never log the submitted password.
        if self.panel.check_password(data.get("password", "")):
            token = self.panel.new_session()
            cookie = (f"session={token}; Path=/; HttpOnly; "
                      f"SameSite=Lax; Max-Age={SESSION_TTL}")
            writer.write(json_response(200, {"ok": True}, set_cookie=cookie))
        else:
            writer.write(json_response(401, {"error": "wrong password"}))
        await writer.drain()

    async def _create_rule(self, writer, body):
        try:
            data = json.loads(body or b"{}")
        except Exception:
            writer.write(json_response(400, {"error": "invalid JSON"}))
            await writer.drain()
            return
        try:
            listen_port = data.get("listen_port")
            if isinstance(listen_port, str) and listen_port.strip() == "":
                listen_port = None
            rule = await self.panel.add_rule(
                data.get("name"), data.get("group"),
                listen_port, data.get("target"),
                data.get("speed_limit_mbps"),
                data.get("ip_limit"),
                data.get("conn_limit"))
        except ValueError as exc:
            writer.write(json_response(400, {"error": str(exc)}))
            await writer.drain()
            return
        except Exception as exc:
            writer.write(json_response(400, {"error": f"cannot start rule: {exc}"}))
            await writer.drain()
            return
        writer.write(json_response(201, {
            "rule": self.panel.public_rule(rule),
            "entry": self.panel.entry_of(rule),
        }))
        await writer.drain()

    async def _toggle_rule(self, writer, rule_id, body):
        try:
            data = json.loads(body or b"{}")
        except Exception:
            writer.write(json_response(400, {"error": "invalid JSON"}))
            await writer.drain()
            return
        try:
            rule = await self.panel.set_enabled(rule_id, data.get("enabled"))
        except KeyError:
            writer.write(json_response(404, {"error": "rule not found"}))
            await writer.drain()
            return
        except Exception as exc:
            writer.write(json_response(400, {"error": f"cannot toggle: {exc}"}))
            await writer.drain()
            return
        writer.write(json_response(200, {"rule": self.panel.public_rule(rule)}))
        await writer.drain()

    async def _batch_delete(self, writer, body):
        try:
            data = json.loads(body or b"{}")
        except Exception:
            writer.write(json_response(400, {"error": "invalid JSON"}))
            await writer.drain()
            return
        deleted = 0
        for rule_id in data.get("ids", []):
            if await self.panel.delete_rule(rule_id) is not None:
                deleted += 1
        writer.write(json_response(200, {"ok": True, "deleted": deleted}))
        await writer.drain()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def run_server(panel):
    """Load rules, restart enabled forwarders, serve HTTP, save counters."""
    panel.load_rules()
    await panel.start_enabled_forwarders()
    server = await asyncio.start_server(
        HttpServer(panel).handle, panel.host, panel.port)
    print(f"[panel] listening on http://{panel.host}:{panel.port} "
          f"(entry IP shown as {panel.relay_ip})", flush=True)

    async def periodic_save():
        while True:
            await asyncio.sleep(SAVE_INTERVAL)
            if panel._dirty:
                try:
                    panel.save_rules()
                except Exception as exc:
                    print(f"[panel] WARNING: periodic save failed: {exc}",
                          flush=True)

    saver = asyncio.ensure_future(periodic_save())
    try:
        async with server:
            await server.serve_forever()
    finally:
        saver.cancel()
        await panel.stop_all_forwarders()
        try:
            panel.save_rules()
        except Exception:
            pass


def set_admin_password(data_dir):
    """Read a password from stdin, store only its salted hash.

    The password arrives on stdin (piped by install.sh), never as a command
    line argument, and is never printed or logged.
    """
    data_dir = Path(data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
    password = sys.stdin.readline().rstrip("\n")
    if not password:
        print("error: empty password", file=sys.stderr)
        return 2
    salt_hex, hash_hex = hash_password(password)
    admin_file = data_dir / "admin.json"
    tmp = admin_file.with_suffix(".json.tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"salt": salt_hex, "hash": hash_hex}, f)
    os.replace(tmp, admin_file)
    try:
        os.chmod(admin_file, 0o600)
    except Exception:
        pass
    print("Admin password set.")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="forwarding-rules panel")
    parser.add_argument("--host", default=None,
                        help="bind address (default: PANEL_HOST or 0.0.0.0)")
    parser.add_argument("--port", type=int, default=None,
                        help="panel port (default: PANEL_PORT or 2080)")
    parser.add_argument("--data-dir", default=None,
                        help="data directory (default: PANEL_DATA_DIR or ./data)")
    parser.add_argument("--set-admin", action="store_true",
                        help="read admin password from stdin and store its hash")
    args = parser.parse_args(argv)

    if args.data_dir:
        os.environ["PANEL_DATA_DIR"] = args.data_dir
    data_dir = get_data_dir()

    if args.set_admin:
        return set_admin_password(data_dir)

    host = args.host or os.environ.get("PANEL_HOST", DEFAULT_HOST)
    port = args.port or int(os.environ.get("PANEL_PORT", DEFAULT_PORT))
    panel = Panel(data_dir, host, port)
    if not panel.admin_exists():
        print("error: no admin password set yet.", file=sys.stderr)
        print("Run: python3 panel.py --set-admin  (install.sh does this)",
              file=sys.stderr)
        return 2
    try:
        asyncio.run(run_server(panel))
    except KeyboardInterrupt:
        print("[panel] stopped", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
