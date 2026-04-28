#!/usr/bin/env python3
"""
Goulburn Water Treatment Plant -- Scenario 1: Reconnaissance
=============================================================
Enumerates all readable Modbus data types on PLC-PUMP1 (plc1).
Sweeps FC01 coils, FC03 holding registers, FC02 discrete inputs,
FC04 input registers and prints a complete register map with tag names.
Reports total sweep time in milliseconds.

Usage:
    python3 scenario1_recon.py [--target 10.0.0.2] [--port 5502]
"""

import argparse
import sys
import time
from datetime import datetime

from pymodbus.client import ModbusTcpClient
from pymodbus.exceptions import ModbusException


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(description="Modbus reconnaissance scanner")
    parser.add_argument("--target", default="10.0.0.2", help="Target IP (default: 10.0.0.2)")
    parser.add_argument("--port", type=int, default=5502, help="Target port (default: 5502)")
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def separator(char="-", width=60):
    print(char * width)


# Tag name lookup for known registers
COIL_TAGS = {
    0: "pump1-valve.closed",
    1: "pump2-valve.closed",
}

HR_TAGS = {
    30000: "pump1-flow.Lps",
    30001: "pump2-flow.Lps",
}


# ---------------------------------------------------------------------------
# Scan functions
# ---------------------------------------------------------------------------
def scan_coils(client, start=0, count=10):
    """FC01 -- Read Coils."""
    print(f"\n[*] FC01 Read Coils {start} to {start + count - 1} ...")
    separator()
    results = {}
    for addr in range(start, start + count):
        try:
            r = client.read_coils(addr, count=1, device_id=1)
            if r.isError():
                val = "ERROR"
            else:
                val = r.bits[0]
            results[addr] = val
            tag = COIL_TAGS.get(addr, "")
            tag_str = f"  [{tag}]" if tag else ""
            state = "CLOSED" if val is True else ("OPEN" if val is False else str(val))
            print(f"  Coil {addr:>5}  =>  {str(val):<5}  ({state}){tag_str}")
        except Exception as e:
            results[addr] = f"EXCEPTION: {e}"
            print(f"  Coil {addr:>5}  =>  EXCEPTION: {e}")
    return results


def scan_holding_registers(client, start=30000, count=16):
    """FC03 -- Read Holding Registers."""
    print(f"\n[*] FC03 Read Holding Registers {start} to {start + count - 1} ...")
    separator()
    results = {}
    for addr in range(start, start + count):
        try:
            r = client.read_holding_registers(addr, count=1, device_id=1)
            if r.isError():
                val = "ERROR"
            else:
                val = r.registers[0]
            results[addr] = val
            tag = HR_TAGS.get(addr, "")
            tag_str = f"  [{tag}]" if tag else ""
            print(f"  HR {addr}  =>  {val}{tag_str}")
        except Exception as e:
            results[addr] = f"EXCEPTION: {e}"
            print(f"  HR {addr}  =>  EXCEPTION: {e}")
    return results


def scan_discrete_inputs(client, start=0, count=10):
    """FC02 -- Read Discrete Inputs."""
    print(f"\n[*] FC02 Read Discrete Inputs {start} to {start + count - 1} ...")
    separator()
    results = {}
    for addr in range(start, start + count):
        try:
            r = client.read_discrete_inputs(addr, count=1, device_id=1)
            if r.isError():
                val = "NO RESPONSE / ERROR"
            else:
                val = r.bits[0]
            results[addr] = val
            print(f"  DI {addr:>5}  =>  {val}")
        except Exception as e:
            results[addr] = f"EXCEPTION: {e}"
            print(f"  DI {addr:>5}  =>  EXCEPTION: {e}")
    return results


def scan_input_registers(client, start=0, count=10):
    """FC04 -- Read Input Registers."""
    print(f"\n[*] FC04 Read Input Registers {start} to {start + count - 1} ...")
    separator()
    results = {}
    for addr in range(start, start + count):
        try:
            r = client.read_input_registers(addr, count=1, device_id=1)
            if r.isError():
                val = "NO RESPONSE / ERROR"
            else:
                val = r.registers[0]
            results[addr] = val
            print(f"  IR {addr:>5}  =>  {val}")
        except Exception as e:
            results[addr] = f"EXCEPTION: {e}"
            print(f"  IR {addr:>5}  =>  EXCEPTION: {e}")
    return results


# ---------------------------------------------------------------------------
# Register map summary table
# ---------------------------------------------------------------------------
def print_register_map(coils, hr, di, ir, target, port, sweep_ms, output_file=None):
    lines = []
    lines.append("")
    lines.append("=" * 62)
    lines.append("  REGISTER MAP SUMMARY -- Goulburn WTP / AquaOps Utilities")
    lines.append(f"  Target: {target}:{port}  |  {datetime.now().strftime('%Y-%m-%dT%H:%M:%S')}")
    lines.append(f"  Total sweep time: {sweep_ms:.0f} ms")
    lines.append("=" * 62)

    # Coils
    lines.append("")
    lines.append("  COILS (FC01 Read Coils)")
    lines.append("  " + "-" * 48)
    lines.append(f"  {'Address':<10} {'Value':<8} {'State':<8} Tag")
    lines.append("  " + "-" * 48)
    for addr, val in coils.items():
        if isinstance(val, bool):
            state = "CLOSED" if val else "OPEN"
        else:
            state = str(val)
        tag = COIL_TAGS.get(addr, "")
        lines.append(f"  {addr:<10} {str(val):<8} {state:<8} {tag}")

    # Holding registers
    lines.append("")
    lines.append("  HOLDING REGISTERS (FC03 Read Holding Registers)")
    lines.append("  " + "-" * 48)
    lines.append(f"  {'Address':<10} {'Value':<10} Tag")
    lines.append("  " + "-" * 48)
    for addr, val in hr.items():
        tag = HR_TAGS.get(addr, f"telemetry-{addr - 30000}")
        lines.append(f"  {addr:<10} {str(val):<10} {tag}")

    # Discrete inputs
    lines.append("")
    lines.append("  DISCRETE INPUTS (FC02 Read Discrete Inputs)")
    lines.append("  " + "-" * 48)
    responding = {a: v for a, v in di.items()
                  if "ERROR" not in str(v) and "EXCEPTION" not in str(v)}
    if responding:
        for addr, val in responding.items():
            lines.append(f"  DI {addr}: {val}")
    else:
        lines.append("  No discrete inputs responded (server returned errors -- expected)")

    # Input registers
    lines.append("")
    lines.append("  INPUT REGISTERS (FC04 Read Input Registers)")
    lines.append("  " + "-" * 48)
    responding = {a: v for a, v in ir.items()
                  if "ERROR" not in str(v) and "EXCEPTION" not in str(v)}
    if responding:
        for addr, val in responding.items():
            lines.append(f"  IR {addr}: {val}")
    else:
        lines.append("  No input registers responded (server returned errors -- expected)")

    lines.append("")
    lines.append("=" * 62)

    output = "\n".join(lines)
    print(output)

    if output_file:
        import os
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, "w") as f:
            f.write(output)
        print(f"\n[+] Register map saved to: {output_file}")

    return output


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    args = parse_args()

    print("=" * 62)
    print("  Goulburn WTP -- Scenario 1: Reconnaissance")
    print("  AquaOps Utilities | 31261 Internetworking Capstone (UTS)")
    print(f"  Target: {args.target}:{args.port}")
    print(f"  Time:   {datetime.now().strftime('%Y-%m-%dT%H:%M:%S')}")
    print("=" * 62)

    client = ModbusTcpClient(args.target, port=args.port)
    if not client.connect():
        print(f"[!] Failed to connect to {args.target}:{args.port}")
        sys.exit(1)

    print(f"[+] Connected to {args.target}:{args.port}")

    sweep_start = time.time()

    coils = scan_coils(client, start=0, count=10)
    hr    = scan_holding_registers(client, start=30000, count=16)
    di    = scan_discrete_inputs(client, start=0, count=10)
    ir    = scan_input_registers(client, start=0, count=10)

    sweep_ms = (time.time() - sweep_start) * 1000

    client.close()

    import os
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    map_file = os.path.join(base, "results", "scenario1_register_map.txt")

    print_register_map(coils, hr, di, ir, args.target, args.port, sweep_ms,
                       output_file=map_file)

    print(f"\n[+] Total sweep time: {sweep_ms:.0f} ms")


if __name__ == "__main__":
    main()
