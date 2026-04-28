#!/usr/bin/env python3
"""
Goulburn Water Treatment Plant -- Mitigation 3: Rate-Limiting Proxy
====================================================================
AquaOps Utilities | 31261 Internetworking Capstone (UTS)

CONCEPT
-------
Scenario 3 floods plc1 with FC03 read requests at hundreds of req/s.
Real embedded PLCs fail at 200-500 req/s (Dragos/Claroty field data).
A rate-limiting proxy enforces a per-source-IP cap, letting legitimate
SCADA polling through while cutting off the flood.

This is the software equivalent of a Modbus-aware firewall rate-limit
rule or QoS shaping on the OT network switch.

ALGORITHM -- sliding window per source IP
------------------------------------------
For each source IP, maintain a deque of request timestamps. On each
new request:
  1. Discard timestamps older than 1 second.
  2. If the deque length is < threshold --> allow, append timestamp.
  3. If the deque length is >= threshold --> timeout the IP for
     `timeout` seconds and drop requests until the timer expires.

ARCHITECTURE
------------
  Client -> Proxy (listen_port) -> plc1 (upstream_host:upstream_port)

USAGE -- standalone
--------------------
  # Terminal 1: start plc1 Modbus server
  python3 servers/modbus_server.py

  # Terminal 2: start rate-limit proxy (max 100 req/s per IP, 20s timeout)
  python3 mitigations/mitigation3_rate_limit.py \\
      --listen-port 5503 --upstream 127.0.0.1:5502 \\
      --threshold 100 --timeout 20

  # Terminal 3: flood (should be throttled)
  python3 attacks/scenario3_dos_flood.py --target 127.0.0.1 --port 5503 --duration 15

USAGE -- inside Mininet
------------------------
  See mitigations/run_mitigations_demo.py
"""

import argparse
import asyncio
import struct
import sys
import time
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
                   help="Upstream plc1 address host:port (default: 127.0.0.1:5502)")
    p.add_argument("--threshold", type=int, default=100,
                   help="Max requests per second per source IP (default: 100)")
    p.add_argument("--timeout", type=int, default=20,
                   help="Seconds to block an IP that exceeds threshold (default: 20)")
    return p.parse_args()


def log(msg):
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    print(f"{ts}  {msg}", flush=True)


# ---------------------------------------------------------------------------
# Per-IP rate limiter with timeout support
# ---------------------------------------------------------------------------
class RateLimiter:
    """
    Sliding window rate limiter with per-IP timeout on threshold breach.

    Each source IP gets:
      - A deque of request timestamps (1-second sliding window)
      - An optional timeout expiry timestamp (set when threshold is breached)

    On is_allowed(ip):
      1. If the IP is currently timed out --> drop (return False)
      2. Slide the window (discard timestamps older than 1 second)
      3. If window length >= threshold --> set timeout, drop
      4. Otherwise --> allow
    """

    def __init__(self, threshold, timeout_secs):
        self.threshold    = threshold
        self.timeout_secs = timeout_secs
        self._lock        = asyncio.Lock()
        self._windows     = defaultdict(deque)
        self._timeouts    = {}        # ip -> expiry (monotonic time)
        self.total_allowed = 0
        self.total_blocked = 0
        self.total_timed_out = 0

    async def is_allowed(self, ip):
        async with self._lock:
            now = time.monotonic()

            # Check if IP is currently in timeout
            if ip in self._timeouts:
                if now < self._timeouts[ip]:
                    self.total_timed_out += 1
                    return False
                else:
                    # Timeout expired -- re-admit and clear window
                    del self._timeouts[ip]
                    self._windows[ip].clear()

            # Slide the 1-second window
            window = self._windows[ip]
            while window and window[0] < now - 1.0:
                window.popleft()

            if len(window) >= self.threshold:
                # Threshold breached -- impose timeout
                self._timeouts[ip] = now + self.timeout_secs
                self.total_blocked += 1
                return False

            window.append(now)
            self.total_allowed += 1
            return True

    def timeout_remaining(self, ip):
        now = time.monotonic()
        expiry = self._timeouts.get(ip)
        if expiry and now < expiry:
            return expiry - now
        return 0.0


# ---------------------------------------------------------------------------
# Per-connection handler
# ---------------------------------------------------------------------------
async def handle_client(reader, writer, upstream_host, upstream_port, limiter):
    peer      = writer.get_extra_info("peername")
    client_ip = peer[0] if peer else "unknown"

    try:
        up_reader, up_writer = await asyncio.open_connection(upstream_host, upstream_port)
    except ConnectionRefusedError:
        log(f"ERROR      Cannot reach upstream {upstream_host}:{upstream_port}")
        writer.close()
        return

    try:
        while True:
            # Read 7-byte MBAP header
            header    = await reader.readexactly(7)
            remaining = struct.unpack(">H", header[4:6])[0]
            pdu       = await reader.readexactly(remaining - 1)

            allowed = await limiter.is_allowed(client_ip)

            if not allowed:
                remaining_s = limiter.timeout_remaining(client_ip)
                log(
                    f"RATE-LIMIT {client_ip:<15}  "
                    f">{limiter.threshold} req/s  "
                    f"timeout {remaining_s:.0f}s remaining  "
                    f"-> connection closed  "
                    f"[total timed-out: {limiter.total_timed_out}]"
                )
                break   # drop connection; flood client must reconnect

            # Forward to plc1 and relay response
            full_request = header + pdu
            up_writer.write(full_request)
            await up_writer.drain()

            resp_header    = await up_reader.readexactly(7)
            resp_remaining = struct.unpack(">H", resp_header[4:6])[0]
            resp_pdu       = await up_reader.readexactly(resp_remaining - 1)

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
async def print_stats(limiter, interval=5.0):
    while True:
        await asyncio.sleep(interval)
        log(
            f"STATS      allowed={limiter.total_allowed}  "
            f"blocked={limiter.total_blocked}  "
            f"timed-out-drops={limiter.total_timed_out}  "
            f"limit={limiter.threshold} req/s  "
            f"timeout={limiter.timeout_secs}s"
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
async def run_proxy(listen_port, upstream_host, upstream_port, threshold, timeout_secs):
    limiter = RateLimiter(threshold, timeout_secs)

    server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, upstream_host, upstream_port, limiter),
        "0.0.0.0",
        listen_port,
    )

    print()
    print("=" * 64)
    print("  Goulburn WTP -- Mitigation 3: Rate-Limiting Proxy")
    print(f"  Listening  :  0.0.0.0:{listen_port}")
    print(f"  Upstream   :  {upstream_host}:{upstream_port}  (plc1 Modbus server)")
    print(f"  Threshold  :  {threshold} req/s per source IP")
    print(f"  Timeout    :  {timeout_secs}s block on threshold breach")
    print(f"  Algorithm  :  sliding window (1-second window)")
    print(f"  On exceed  :  connection closed + IP blocked for {timeout_secs}s")
    print("=" * 64)
    print()

    async with server:
        asyncio.create_task(print_stats(limiter))
        await server.serve_forever()


def main():
    args = parse_args()
    upstream_host, upstream_port_str = args.upstream.rsplit(":", 1)
    upstream_port = int(upstream_port_str)
    asyncio.run(
        run_proxy(
            args.listen_port,
            upstream_host,
            upstream_port,
            args.threshold,
            args.timeout,
        )
    )


if __name__ == "__main__":
    main()
