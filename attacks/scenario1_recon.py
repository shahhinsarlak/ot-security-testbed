#!/usr/bin/env python3
"""
OT Security Testbed — Scenario 1: Reconnaissance
=================================================
Enumerates all readable Modbus data types on the target RTU.

Usage:
    python3 scenario1_recon.py [--target 10.0.0.2] [--port 5502]
"""

import argparse
import sys
from datetime import datetime

from pymodbus.client import ModbusTcpClient
from pymodbus.exceptions import ModbusException


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(description="Modbus reconnaissance scanner")
    parser.add_argument("--target", default="10.0.0.2", help="Target IP")
    parser.add_argument("--port", type=int, default=5502, help="Target port")
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def separator(char="─", width=60):
    print(char * width)


def safe_read(fn, label, *args, **kwargs):
    """Call a pymodbus read function; return list of values or None on error."""
    try:
        result = fn(*args, **kwargs)
        if result.isError():
            return None, f"Modbus error: {result}"
        return result.registers if hasattr(result, "registers") else result.bits, None
    except ModbusException as e:
        return None, str(e)
    except Exception as e:
        return None, str(e)


# ---------------------------------------------------------------------------
# Scan functions
# ---------------------------------------------------------------------------
def scan_coils(client, start=0, count=10):
    print(f"\n[*] Scanning coils {start} to {start + count - 1} ...")
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
            state = "CLOSED" if val is True else ("OPEN" if val is False else val)
            print(f"  Coil {addr:>5}  =>  {str(val):<5}  ({state})")
        except Exception as e:
            results[addr] = f"EXCEPTION: {e}"
            print(f"  Coil {addr:>5}  =>  EXCEPTION: {e}")
    return results


def scan_holding_registers(client, start=30000, count=16):
    print(f"\n[*] Scanning holding registers {start} to {start + count - 1} ...")
    separator()
    # pymodbus 3.12: pass full Modbus address directly
    results = {}
    for addr in range(start, start + count):
        try:
            r = client.read_holding_registers(addr, count=1, device_id=1)
            if r.isError():
                val = "ERROR"
            else:
                val = r.registers[0]
            results[addr] = val
            print(f"  HR {addr}  =>  {val}")
        except Exception as e:
            results[addr] = f"EXCEPTION: {e}"
            print(f"  HR {addr}  =>  EXCEPTION: {e}")
    return results


def scan_discrete_inputs(client, start=0, count=10):
    print(f"\n[*] Scanning discrete inputs {start} to {start + count - 1} ...")
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
    print(f"\n[*] Scanning input registers {start} to {start + count - 1} ...")
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
# Register map table
# ---------------------------------------------------------------------------
def print_register_map(coils, hr, di, ir, target, port, output_file=None):
    lines = []
    lines.append("")
    lines.append("=" * 60)
    lines.append("  REGISTER MAP SUMMARY")
    lines.append(f"  Target: {target}:{port}  |  {datetime.now().strftime('%Y-%m-%dT%H:%M:%S')}")
    lines.append("=" * 60)

    lines.append("")
    lines.append("  COILS (FC01 Read Coils)")
    lines.append("  " + "-" * 40)
    lines.append(f"  {'Address':<10} {'Value':<8} {'State'}")
    lines.append("  " + "-" * 40)
    for addr, val in coils.items():
        if isinstance(val, bool):
            state = "CLOSED" if val else "OPEN"
        else:
            state = str(val)
        lines.append(f"  {addr:<10} {str(val):<8} {state}")

    lines.append("")
    lines.append("  HOLDING REGISTERS (FC03 Read Holding Registers)")
    lines.append("  " + "-" * 40)
    lines.append(f"  {'Address':<10} {'Value'}")
    lines.append("  " + "-" * 40)
    for addr, val in hr.items():
        tag = {
            30000: "line-650632.kW",
            30001: "line-651634.kW",
        }.get(addr, f"telemetry-{addr - 30000}")
        lines.append(f"  {addr:<10} {val:<8} [{tag}]")

    lines.append("")
    lines.append("  DISCRETE INPUTS (FC02 Read Discrete Inputs)")
    lines.append("  " + "-" * 40)
    responding = {a: v for a, v in di.items() if "ERROR" not in str(v) and "EXCEPTION" not in str(v)}
    if responding:
        for addr, val in responding.items():
            lines.append(f"  DI {addr}: {val}")
    else:
        lines.append("  No discrete inputs responded (server returned errors)")

    lines.append("")
    lines.append("  INPUT REGISTERS (FC04 Read Input Registers)")
    lines.append("  " + "-" * 40)
    responding = {a: v for a, v in ir.items() if "ERROR" not in str(v) and "EXCEPTION" not in str(v)}
    if responding:
        for addr, val in responding.items():
            lines.append(f"  IR {addr}: {val}")
    else:
        lines.append("  No input registers responded (server returned errors)")

    lines.append("")
    lines.append("=" * 60)

    output = "\n".join(lines)
    print(output)

    if output_file:
        with open(output_file, "w") as f:
            f.write(output)
        print(f"\n[+] Register map saved to: {output_file}")

    return output


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    args = parse_args()

    print("=" * 60)
    print("  OT Security Testbed — Scenario 1: Reconnaissance")
    print(f"  Target: {args.target}:{args.port}")
    print(f"  Time:   {datetime.now().strftime('%Y-%m-%dT%H:%M:%S')}")
    print("=" * 60)

    client = ModbusTcpClient(args.target, port=args.port)
    if not client.connect():
        print(f"[!] Failed to connect to {args.target}:{args.port}")
        sys.exit(1)

    print(f"[+] Connected to {args.target}:{args.port}")

    coils = scan_coils(client, start=0, count=10)
    hr = scan_holding_registers(client, start=30000, count=16)
    di = scan_discrete_inputs(client, start=0, count=10)
    ir = scan_input_registers(client, start=0, count=10)

    client.close()

    # Determine output path relative to script location
    import os
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    map_file = os.path.join(base, "results", "scenario1_register_map.txt")

    print_register_map(coils, hr, di, ir, args.target, args.port, output_file=map_file)


if __name__ == "__main__":
    main()
