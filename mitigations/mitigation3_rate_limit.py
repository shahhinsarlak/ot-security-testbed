#!/usr/bin/env python3
"""
Mitigation 3 — Modbus TCP Rate-Limiting Proxy
==============================================

CONCEPT
-------
The DoS scenario (scenario 3) floods the RTU with FC03 read requests at
~3,600 req/s. Real embedded RTUs fail at 200–500 req/s (Dragos/Claroty
field data). A rate-limiting proxy enforces a per-source-IP cap, letting
legitimate SCADA polling through while cutting off the flood.

This is the software equivalent of a Modbus-aware firewall rate-limit rule
or QoS shaping on the OT network switch.

ALGORITHM — sliding window per source IP
-----------------------------------------
For each source IP, maintain a deque of request timestamps. On each new
request:
  1. Discard timestamps older than 1 second.
  2. If the deque length is < max_rps → allow the request, append timestamp.
  3. If the deque length is >= max_rps → block: close the connection and log.

The window tracks exact arrival times, so the limit is "no more than N
requests in any 1-second window" regardless of burst pattern.

ARCHITECTURE
------------
  Client ──► Proxy (listen_port) ──► RTU Server (upstream_host:upstream_port)

USAGE — standalone
-------------------
  # Terminal 1: start the RTU
  python3 servers/modbus_server.py

  # Terminal 2: start the rate-limit proxy (max 20 req/s per source IP)
  python3 mitigations/mitigation3_rate_limit.py \\
      --listen-port 5503 \\
      --upstream 127.0.0.1:5502 \\
      --max-rps 20

  # Terminal 3: flood (should be throttled to 20 req/s)
  python3 attacks/scenario3_dos.py --target 127.0.0.1 --port 5503 --duration 15

  # Terminal 4: legitimate poll (should succeed despite flood on terminal 3)
  for i in $(seq 1 5); do mbpoll -1 -a 1 -t 4 -r 30001 -c 1 127.0.0.1 -p 5503; sleep 2; done

USAGE — inside Mininet
-----------------------
  See mitigations/run_mitigations_demo.py
"""

import argparse
import asyncio
import struct
import sys
import time
import threading
from collections import defaultdict, deque
from datetime import datetime


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def parse_args():
    p = argparse.ArgumentParser(description="Modbus rate-limiting proxy")
    p.add_argument("--listen-port", type=int, default=5503,
                   help="Port this proxy listens on (default: 5503)")
    p.add_argument("--upstream", default="127.0.0.1:5502",
                   help="Upstream RTU address host:port (default: 127.0.0.1:5502)")
    p.add_argument("--max-rps", type=int, default=20,
                   help="Max requests per second per source IP (default: 20)")
    return p.parse_args()


def log(msg: str):
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    print(f"{ts}  {msg}", flush=True)


# ---------------------------------------------------------------------------
# Per-IP sliding window rate limiter
# ---------------------------------------------------------------------------
class RateLimiter:
    """
    Thread/coroutine-safe sliding window rate limiter.

    Each source IP gets a deque of request timestamps.  On each call to
    is_allowed(ip), timestamps older than 1 second are pruned and the
    current window size is compared against max_rps.
    """

    def __init__(self, max_rps: int):
        self.max_rps = max_rps
        self._lock = asyncio.Lock()
        self._windows: dict[str, deque] = defaultdict(deque)
        # Global counters for the stats printer
        self.total_allowed = 0
        self.total_blocked = 0

    async def is_allowed(self, ip: str) -> bool:
        async with self._lock:
            now = time.monotonic()
            window = self._windows[ip]

            # Slide: remove timestamps outside the 1-second window
            while window and window[0] < now - 1.0:
                window.popleft()

            if len(window) >= self.max_rps:
                self.total_blocked += 1
                return False

            window.append(now)
            self.total_allowed += 1
            return True

    def current_rps(self, ip: str) -> int:
        """Return how many requests this IP has made in the last second."""
        now = time.monotonic()
        window = self._windows[ip]
        return sum(1 for t in window if t >= now - 1.0)


# ---------------------------------------------------------------------------
# Per-connection handler
# ---------------------------------------------------------------------------
async def handle_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    upstream_host: str,
    upstream_port: int,
    limiter: RateLimiter,
):
    peer = writer.get_extra_info("peername")
    client_ip = peer[0] if peer else "unknown"

    # Open a persistent upstream connection for this client session
    try:
        up_reader, up_writer = await asyncio.open_connection(upstream_host, upstream_port)
    except ConnectionRefusedError:
        log(f"ERROR      Cannot reach upstream {upstream_host}:{upstream_port}")
        writer.close()
        return

    requests_this_conn = 0

    try:
        while True:
            # Read 7-byte MBAP header
            header = await reader.readexactly(7)
            remaining = struct.unpack(">H", header[4:6])[0]
            pdu = await reader.readexactly(remaining - 1)
            full_request = header + pdu
            requests_this_conn += 1

            allowed = await limiter.is_allowed(client_ip)

            if not allowed:
                # Close the connection — the flood has exceeded the rate limit.
                # Closing forces the flood client to reconnect, burning its own
                # time on TCP handshakes and keeping pressure off the RTU.
                current_rate = limiter.current_rps(client_ip)
                log(
                    f"RATE-LIMIT {client_ip:<15}  "
                    f">{limiter.max_rps} req/s (current ~{current_rate}/s)  "
                    f"→  connection closed  "
                    f"[total blocked: {limiter.total_blocked}]"
                )
                break

            # Forward to RTU and relay response
            up_writer.write(full_request)
            await up_writer.drain()

            resp_header = await up_reader.readexactly(7)
            resp_remaining = struct.unpack(">H", resp_header[4:6])[0]
            resp_pdu = await up_reader.readexactly(resp_remaining - 1)

            writer.write(resp_header + resp_pdu)
            await writer.drain()

    except asyncio.IncompleteReadError:
        pass
    except Exception as exc:
        log(f"ERROR      {client_ip}  {exc}")
    finally:
        try:
            up_writer.close()
        except Exception:
            pass
        writer.close()


# ---------------------------------------------------------------------------
# Periodic stats printer
# ---------------------------------------------------------------------------
async def print_stats(limiter: RateLimiter, interval: float = 5.0):
    """Print a running summary every `interval` seconds."""
    while True:
        await asyncio.sleep(interval)
        log(
            f"STATS      allowed={limiter.total_allowed}  "
            f"blocked={limiter.total_blocked}  "
            f"limit={limiter.max_rps} req/s per IP"
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
async def run_proxy(
    listen_port: int,
    upstream_host: str,
    upstream_port: int,
    max_rps: int,
):
    limiter = RateLimiter(max_rps)

    server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, upstream_host, upstream_port, limiter),
        "0.0.0.0",
        listen_port,
    )

    print()
    print("=" * 62)
    print("  Mitigation 3 — Rate-Limiting Proxy")
    print(f"  Listening  :  0.0.0.0:{listen_port}")
    print(f"  Upstream   :  {upstream_host}:{upstream_port}")
    print(f"  Limit      :  {max_rps} req/s per source IP")
    print(f"  Algorithm  :  sliding window (1-second window)")
    print(f"  On exceed  :  connection closed (force TCP reconnect)")
    print("=" * 62)
    print()

    async with server:
        asyncio.create_task(print_stats(limiter))
        await server.serve_forever()


def main():
    args = parse_args()
    upstream_host, upstream_port_str = args.upstream.rsplit(":", 1)
    upstream_port = int(upstream_port_str)
    asyncio.run(run_proxy(args.listen_port, upstream_host, upstream_port, args.max_rps))


if __name__ == "__main__":
    main()
