#!/usr/bin/env python3
"""Tunnel agent for the exit side of a forward-panel tunnel rule.

Run this ON THE LANDING MACHINE (not on the relay), e.g.:

    python3 tunnel-agent.py --listen 20000 --target 127.0.0.1:1080

It listens on --listen and forwards raw bytes to --target, which is the
SOCKS5 (or other) service as seen FROM THIS MACHINE, usually a loopback
address. A forward-panel rule in tunnel mode dials this agent instead of
dialing the SOCKS5 service directly, so the relay->landing leg is a
separately terminated, socket-tuned TCP leg, and the last hop from the
agent to the local service is loopback.

This is NOT for vendor landings: a vendor Singapore/US residential box
cannot run this agent, so those rules must stay on direct mode.
Only use tunnel mode when you control the landing machine and can run
this script there (in a terminal, tmux, or a systemd service).

Python 3 standard library only. Sockets get TCP_NODELAY, keepalive,
1 MB buffers, and per-socket BBR when the kernel offers it, matching
panel.py's tune_socket.
"""

import argparse
import asyncio
import socket
import sys


def tune_socket(sock):
    if sock is None:
        return
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except Exception:
        pass
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except Exception:
        pass
    for opt, val in ((socket.SO_RCVBUF, 1024 * 1024),
                     (socket.SO_SNDBUF, 1024 * 1024)):
        try:
            sock.setsockopt(socket.SOL_SOCKET, opt, val)
        except Exception:
            pass
    try:
        sock.setsockopt(socket.IPPROTO_TCP, 13, b"bbr")
    except Exception:
        pass


def parse_target(text):
    if ":" not in text:
        raise ValueError("target must be host:port")
    host, port_text = text.rsplit(":", 1)
    return host, int(port_text)


async def pump(reader, writer):
    try:
        while True:
            data = await reader.read(262144)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionError, asyncio.IncompleteReadError):
        pass


async def handle(client_reader, client_writer, target_host, target_port):
    try:
        tune_socket(client_writer.get_extra_info("socket"))
    except Exception:
        pass
    try:
        target_reader, target_writer = await asyncio.wait_for(
            asyncio.open_connection(target_host, target_port), timeout=10)
    except Exception:
        try:
            client_writer.close()
        except Exception:
            pass
        return
    try:
        tune_socket(target_writer.get_extra_info("socket"))
    except Exception:
        pass
    try:
        await asyncio.wait(
            [asyncio.ensure_future(pump(client_reader, target_writer)),
             asyncio.ensure_future(pump(target_reader, client_writer))],
            return_when=asyncio.FIRST_COMPLETED)
    finally:
        for w in (client_writer, target_writer):
            try:
                w.close()
            except Exception:
                pass


async def main():
    parser = argparse.ArgumentParser(description="forward-panel tunnel agent")
    parser.add_argument("--listen", type=int, required=True,
                        help="port to listen on (the tunnel endpoint)")
    parser.add_argument("--target", required=True,
                        help="local target, e.g. 127.0.0.1:1080")
    parser.add_argument("--host", default="0.0.0.0")
    args = parser.parse_args()
    target_host, target_port = parse_target(args.target)
    server = await asyncio.start_server(
        lambda r, w: handle(r, w, target_host, target_port),
        args.host, args.listen)
    for s in server.sockets or []:
        tune_socket(s)
    print(f"[tunnel-agent] listening on {args.host}:{args.listen} "
          f"-> {target_host}:{target_port}", flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
