#!/usr/bin/env python3
"""
Mitigation 2 — Modbus TCP Function Code Filter Proxy
=====================================================

CONCEPT
-------
Modbus TCP carries no authentication — any host that can reach the RTU's
TCP port can issue any function code. This proxy sits in front of the RTU
and enforces a read-only allowlist: requests carrying write function codes
are rejected before they ever reach the device.

This is the software equivalent of an OT-aware deep-packet inspection
firewall (e.g. Claroty, Dragos Platform, Snort with Modbus preprocessor).

WHAT IT BLOCKS
--------------
  FC05  Write Single Coil         <- used in scenario 2 (breaker trip)
  FC06  Write Single Register
  FC15  Write Multiple Coils
  FC16  Write Multiple Registers

WHAT IT ALLOWS
--------------
  FC01  Read Coils
  FC02  Read Discrete Inputs
  FC03  Read Holding Registers    <- used in scenario 1 (recon) and scenario 3 (DoS)
  FC04  Read Input Registers

HOW THE BLOCK WORKS
-------------------
When a blocked FC is received the proxy returns a Modbus exception response
with Exception Code 0x01 (Illegal Function) — the same code a real device
returns for an unsupported function. The attacking client sees the write
rejected at the protocol level; it cannot tell whether the block came from
the device or an intermediate proxy.

ARCHITECTURE
------------
  Client ──► Proxy (listen_port) ──► RTU Server (upstream_host:upstream_port)
  Client ◄── Proxy                ◄── RTU Server

USAGE — standalone (no Mininet needed)
--------------------------------------
  # Terminal 1: start the RTU
  python3 servers/modbus_server.py

  # Terminal 2: start the FC filter proxy
  python3 mitigations/mitigation2_fc_filter.py \\
      --listen-port 5503 \\
      --upstream 127.0.0.1:5502

  # Terminal 3: try a write (should be BLOCKED)
  python3 attacks/scenario2_command_injection.py --target 127.0.0.1 --port 5503

  # Terminal 3: try a read (should be ALLOWED)
  python3 attacks/scenario1_recon.py --target 127.0.0.1 --port 5503

USAGE — inside Mininet (automated demo)
----------------------------------------
  See mitigations/run_mitigations_demo.py
"""

import argparse
import asyncio
import struct
import sys
from datetime import datetime


# ---------------------------------------------------------------------------
# Modbus function code definitions
# ---------------------------------------------------------------------------
WRITE_FCS = {0x05, 0x06, 0x0F, 0x10}  # FC5, FC6, FC15, FC16

FC_NAMES = {
    0x01: "Read Coils",
    0x02: "Read Discrete Inputs",
    0x03: "Read Holding Registers",
    0x04: "Read Input Registers",
    0x05: "Write Single Coil",
    0x06: "Write Single Register",
    0x0F: "Write Multiple Coils",
    0x10: "Write Multiple Registers",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def parse_args():
    p = argparse.ArgumentParser(description="Modbus FC filter proxy")
    p.add_argument("--listen-port", type=int, default=5503,
                   help="Port this proxy listens on (default: 5503)")
    p.add_argument("--upstream", default="127.0.0.1:5502",
                   help="Upstream RTU address host:port (default: 127.0.0.1:5502)")
    return p.parse_args()


def log(msg: str):
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    print(f"{ts}  {msg}", flush=True)


def build_exception_response(mbap_header: bytes, fc: int) -> bytes:
    """
    Construct a Modbus exception response.

    Exception response layout:
      Bytes 0-1  Transaction ID   (echoed from request)
      Bytes 2-3  Protocol ID      (echoed, always 0x0000)
      Bytes 4-5  Length           (3 = unit_id + error_fc + exception_code)
      Byte  6    Unit ID          (echoed from request)
      Byte  7    Error FC         (original FC | 0x80)
      Byte  8    Exception Code   (0x01 = Illegal Function)
    """
    transaction_id = mbap_header[0:2]
    protocol_id    = mbap_header[2:4]
    unit_id        = mbap_header[6:7]
    length         = struct.pack(">H", 3)   # unit_id(1) + error_fc(1) + exception(1)
    error_fc       = bytes([fc | 0x80])
    exception_code = bytes([0x01])           # 0x01 = Illegal Function

    return transaction_id + protocol_id + length + unit_id + error_fc + exception_code


# ---------------------------------------------------------------------------
# Per-connection handler
# ---------------------------------------------------------------------------
async def handle_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    upstream_host: str,
    upstream_port: int,
):
    peer = writer.get_extra_info("peername")
    client_ip = peer[0] if peer else "unknown"
    log(f"CONNECT    {client_ip}")

    # Open a persistent connection to the upstream RTU for this client session
    try:
        up_reader, up_writer = await asyncio.open_connection(upstream_host, upstream_port)
    except ConnectionRefusedError:
        log(f"ERROR      Cannot reach upstream {upstream_host}:{upstream_port} — is the server running?")
        writer.close()
        return

    try:
        while True:
            # --- Read the 7-byte Modbus TCP MBAP header ---
            # Layout: TransactionID(2) + ProtocolID(2) + Length(2) + UnitID(1)
            header = await reader.readexactly(7)

            # Length field = bytes remaining after itself = UnitID + PDU
            remaining = struct.unpack(">H", header[4:6])[0]

            # Read the rest of the request (UnitID already consumed in header byte 6)
            # `remaining` includes the UnitID byte that is already in the header,
            # so the actual PDU bytes left to read = remaining - 1
            pdu = await reader.readexactly(remaining - 1)

            full_request = header + pdu

            # Function code is the first byte of the PDU (after unit ID)
            fc = pdu[0]
            fc_name = FC_NAMES.get(fc, f"FC0x{fc:02X}")

            if fc in WRITE_FCS:
                # --- BLOCK: return Modbus exception, never touch the upstream RTU ---
                exception_resp = build_exception_response(header, fc)
                writer.write(exception_resp)
                await writer.drain()
                log(
                    f"BLOCKED    {client_ip:<15}  {fc_name} (FC{fc:02d})  "
                    f"{len(full_request)} bytes  →  exception 0x01"
                )
            else:
                # --- ALLOW: forward request to RTU and relay the response ---
                up_writer.write(full_request)
                await up_writer.drain()

                # Read upstream response header
                resp_header = await up_reader.readexactly(7)
                resp_remaining = struct.unpack(">H", resp_header[4:6])[0]
                resp_pdu = await up_reader.readexactly(resp_remaining - 1)

                writer.write(resp_header + resp_pdu)
                await writer.drain()
                log(
                    f"ALLOWED    {client_ip:<15}  {fc_name} (FC{fc:02d})  "
                    f"{len(full_request)} bytes  →  forwarded"
                )

    except asyncio.IncompleteReadError:
        pass  # Client disconnected cleanly
    except Exception as exc:
        log(f"ERROR      {client_ip}  {exc}")
    finally:
        try:
            up_writer.close()
        except Exception:
            pass
        writer.close()
        log(f"DISCONNECT {client_ip}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
async def run_proxy(listen_port: int, upstream_host: str, upstream_port: int):
    server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, upstream_host, upstream_port),
        "0.0.0.0",
        listen_port,
    )

    print()
    print("=" * 62)
    print("  Mitigation 2 — Modbus Function Code Filter Proxy")
    print(f"  Listening  :  0.0.0.0:{listen_port}")
    print(f"  Upstream   :  {upstream_host}:{upstream_port}")
    print(f"  Blocked FCs:  05 (Write Coil)  06 (Write Reg)")
    print(f"               0F (Write Coils)  10 (Write Regs)")
    print(f"  Allowed FCs:  01 02 03 04 (all reads)")
    print("=" * 62)
    print()

    async with server:
        await server.serve_forever()


def main():
    args = parse_args()
    upstream_host, upstream_port_str = args.upstream.rsplit(":", 1)
    upstream_port = int(upstream_port_str)
    asyncio.run(run_proxy(args.listen_port, upstream_host, upstream_port))


if __name__ == "__main__":
    main()
