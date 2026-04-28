#!/usr/bin/env python3
"""
Goulburn Water Treatment Plant -- Mitigation 2: FC Filter Proxy
================================================================
AquaOps Utilities | 31261 Internetworking Capstone (UTS)

CONCEPT
-------
Modbus TCP carries no authentication -- any host that can reach plc1's
TCP port can issue any function code. This proxy sits in front of plc1
and enforces a read-only allowlist: requests carrying write function codes
are rejected before they ever reach the device.

This is the software equivalent of an OT-aware deep-packet inspection
firewall (e.g. Claroty, Dragos Platform, Snort with Modbus preprocessor).

WHAT IT BLOCKS
--------------
  FC05  Write Single Coil         <- used in Scenario 2 (valve trip)
  FC06  Write Single Register
  FC15  Write Multiple Coils
  FC16  Write Multiple Registers

WHAT IT ALLOWS
--------------
  FC01  Read Coils
  FC02  Read Discrete Inputs
  FC03  Read Holding Registers    <- used in Scenario 1 (recon) and Scenario 3 (flood)
  FC04  Read Input Registers

HOW THE BLOCK WORKS
-------------------
When a blocked FC is received the proxy returns a Modbus exception response
with exception code 0x01 (Illegal Function). The attacking client sees the
write rejected at the protocol level and cannot tell whether the block came
from the device or an intermediate proxy.

ARCHITECTURE
------------
  Client -> Proxy (listen_port) -> plc1 (upstream_host:upstream_port)
  Client <- Proxy               <- plc1

USAGE -- standalone (no Mininet needed)
---------------------------------------
  # Terminal 1: start plc1 Modbus server
  python3 servers/modbus_server.py

  # Terminal 2: start the FC filter proxy
  python3 mitigations/mitigation2_fc_filter.py --listen-port 5503 --upstream 127.0.0.1:5502

  # Terminal 3: try a write (should be BLOCKED)
  python3 attacks/scenario2_command_injection.py --target 127.0.0.1 --port 5503

  # Terminal 3: try a read (should be ALLOWED)
  python3 attacks/scenario1_recon.py --target 127.0.0.1 --port 5503

USAGE -- inside Mininet
------------------------
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
WRITE_FCS = {0x05, 0x06, 0x0F, 0x10}   # FC5, FC6, FC15, FC16 -- blocked

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
                   help="Upstream plc1 address host:port (default: 127.0.0.1:5502)")
    return p.parse_args()


def log(msg):
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    print(f"{ts}  {msg}", flush=True)


def build_exception_response(mbap_header, fc):
    """
    Construct a Modbus exception response (error code 0x85, exception 0x01).

    Layout:
      Bytes 0-1  Transaction ID  (echoed from request)
      Bytes 2-3  Protocol ID     (echoed, always 0x0000)
      Bytes 4-5  Length          (3 = unit_id + error_fc + exception_code)
      Byte  6    Unit ID         (echoed from request)
      Byte  7    Error FC        (original FC | 0x80)
      Byte  8    Exception Code  (0x01 = Illegal Function)
    """
    transaction_id = mbap_header[0:2]
    protocol_id    = mbap_header[2:4]
    unit_id        = mbap_header[6:7]
    length         = struct.pack(">H", 3)
    error_fc       = bytes([fc | 0x80])
    exception_code = bytes([0x01])   # 0x01 = Illegal Function

    return transaction_id + protocol_id + length + unit_id + error_fc + exception_code


# ---------------------------------------------------------------------------
# Per-connection handler
# ---------------------------------------------------------------------------
async def handle_client(reader, writer, upstream_host, upstream_port):
    peer      = writer.get_extra_info("peername")
    client_ip = peer[0] if peer else "unknown"
    log(f"CONNECT    {client_ip}")

    try:
        up_reader, up_writer = await asyncio.open_connection(upstream_host, upstream_port)
    except ConnectionRefusedError:
        log(f"ERROR      Cannot reach upstream {upstream_host}:{upstream_port} -- is the server running?")
        writer.close()
        return

    try:
        while True:
            # Read 7-byte MBAP header: TransactionID(2) + ProtocolID(2) + Length(2) + UnitID(1)
            header    = await reader.readexactly(7)
            remaining = struct.unpack(">H", header[4:6])[0]
            pdu       = await reader.readexactly(remaining - 1)

            full_request = header + pdu
            fc           = pdu[0]
            fc_name      = FC_NAMES.get(fc, f"FC0x{fc:02X}")

            if fc in WRITE_FCS:
                # BLOCK: return exception 0x85/0x01, never touch plc1
                exception_resp = build_exception_response(header, fc)
                writer.write(exception_resp)
                await writer.drain()
                log(
                    f"BLOCKED    {client_ip:<15}  {fc_name} (FC{fc:02d})  "
                    f"{len(full_request)} bytes  ->  exception 0x01"
                )
            else:
                # ALLOW: forward to plc1 and relay response
                up_writer.write(full_request)
                await up_writer.drain()

                resp_header    = await up_reader.readexactly(7)
                resp_remaining = struct.unpack(">H", resp_header[4:6])[0]
                resp_pdu       = await up_reader.readexactly(resp_remaining - 1)

                writer.write(resp_header + resp_pdu)
                await writer.drain()
                log(
                    f"ALLOWED    {client_ip:<15}  {fc_name} (FC{fc:02d})  "
                    f"{len(full_request)} bytes  ->  forwarded"
                )

    except asyncio.IncompleteReadError:
        pass   # Client disconnected cleanly
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
async def run_proxy(listen_port, upstream_host, upstream_port):
    server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, upstream_host, upstream_port),
        "0.0.0.0",
        listen_port,
    )

    print()
    print("=" * 64)
    print("  Goulburn WTP -- Mitigation 2: FC Filter Proxy")
    print(f"  Listening  :  0.0.0.0:{listen_port}")
    print(f"  Upstream   :  {upstream_host}:{upstream_port}  (plc1 Modbus server)")
    print(f"  Blocked FCs:  05 (Write Coil)   06 (Write Reg)")
    print(f"               0F (Write Coils)  10 (Write Regs)")
    print(f"  Allowed FCs:  01 02 03 04 (all reads)")
    print("=" * 64)
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
