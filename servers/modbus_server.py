#!/usr/bin/env python3
"""
Goulburn Water Treatment Plant -- Modbus TCP Server
====================================================
Runs on plc1 (10.0.0.2), port 5502, device_id=1.
AquaOps Utilities | 31261 Internetworking Capstone (UTS)

Register map:
  Coil 0       tag: pump1-valve.closed    initial: True  (CLOSED)
  Coil 1       tag: pump2-valve.closed    initial: True  (CLOSED)
  HR 30000     tag: pump1-flow.Lps        initial: 300   (litres per second)
  HR 30001     tag: pump2-flow.Lps        initial: 185   (litres per second)
  HR 30002-30010  simulated telemetry     initial: varied

All writes are logged to stdout with timestamp and function code.
"""

import asyncio
import logging
import sys
from datetime import datetime

from pymodbus import ModbusDeviceIdentification
from pymodbus.datastore import (
    ModbusDeviceContext,
    ModbusSequentialDataBlock,
    ModbusServerContext,
)
from pymodbus.server import StartAsyncTcpServer

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Custom data block that logs writes with timestamp and function code
# ---------------------------------------------------------------------------
class LoggingDataBlock(ModbusSequentialDataBlock):
    """Extends ModbusSequentialDataBlock to log all writes to stdout."""

    def __init__(self, block_type, address, values):
        super().__init__(address, values)
        self.block_type = block_type

    def setValues(self, address, values):
        ts = datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
        for i, val in enumerate(values):
            addr = address + i
            # Map address to tag name where known
            tag = {
                "coil": {0: "pump1-valve.closed", 1: "pump2-valve.closed"},
                "holding_register": {30000: "pump1-flow.Lps", 30001: "pump2-flow.Lps"},
            }.get(self.block_type, {}).get(addr, f"addr-{addr}")
            log.info(
                "WRITE | block=%s addr=%d tag=%s value=%s | %s",
                self.block_type, addr, tag, val, ts
            )
        super().setValues(address, values)


# ---------------------------------------------------------------------------
# Build initial register state
# ---------------------------------------------------------------------------
def build_context():
    # pymodbus 3.x applies a 1-based internal offset:
    #   FC request address N --> block[N - start_addr + 1]
    # A dummy element at index 0 corrects this so that:
    #   read_coils(0)              --> values[1] = coil-0
    #   read_holding_registers(30000) --> values[1] = HR-30000

    # Coils: index 0 = dummy, index 1 = pump1-valve.closed, index 2 = pump2-valve.closed
    coil_values = [False, True, True] + [False] * 61   # 64 total
    coil_block = LoggingDataBlock("coil", 0, coil_values)

    # Discrete inputs (read-only, unused)
    di_block = ModbusSequentialDataBlock(0, [False] * 64)

    # Input registers (read-only, unused)
    ir_block = ModbusSequentialDataBlock(0, [0] * 32)

    # Holding registers:
    #   index 0  = dummy (0)
    #   index 1  = HR-30000 pump1-flow.Lps = 300
    #   index 2  = HR-30001 pump2-flow.Lps = 185
    #   index 3-11 = HR-30002..30010 telemetry
    telemetry = [220, 175, 310, 400, 130, 290, 500, 155, 445]
    hr_values = [0, 300, 185] + telemetry + [0] * (32 - 3 - len(telemetry))
    hr_block = LoggingDataBlock("holding_register", 30000, hr_values)

    slave = ModbusDeviceContext(
        di=di_block,
        co=coil_block,
        hr=hr_block,
        ir=ir_block,
    )
    return ModbusServerContext(devices=slave, single=True)


# ---------------------------------------------------------------------------
# Startup banner
# ---------------------------------------------------------------------------
def print_banner():
    telemetry = [220, 175, 310, 400, 130, 290, 500, 155, 445]
    print("=" * 62)
    print("  Goulburn Water Treatment Plant -- Modbus TCP Server")
    print("  AquaOps Utilities | PLC-PUMP1 (plc1)")
    print("  Listening: 0.0.0.0:5502  device_id=1")
    print("=" * 62)
    print("  Coil 0   [pump1-valve.closed]   = True  (CLOSED)")
    print("  Coil 1   [pump2-valve.closed]   = True  (CLOSED)")
    print("  HR 30000 [pump1-flow.Lps]        = 300")
    print("  HR 30001 [pump2-flow.Lps]        = 185")
    for i, v in enumerate(telemetry):
        print(f"  HR {30002 + i} [telemetry-{i+2}]           = {v}")
    print("=" * 62)
    print("  Writes will be logged below.")
    print("=" * 62)
    sys.stdout.flush()


# ---------------------------------------------------------------------------
# Device identification
# ---------------------------------------------------------------------------
def build_identity():
    identity = ModbusDeviceIdentification()
    identity.VendorName = "AquaOps Utilities"
    identity.ProductCode = "PLC-PUMP1"
    identity.VendorUrl = ""
    identity.ProductName = "Simulated PLC"
    identity.ModelName = "Pump1 Controller"
    identity.MajorMinorRevision = "1.0"
    return identity


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
async def main():
    context = build_context()
    identity = build_identity()

    print_banner()

    log.info("Starting Modbus TCP server on 0.0.0.0:5502 ...")

    await StartAsyncTcpServer(
        context=context,
        address=("0.0.0.0", 5502),
    )


if __name__ == "__main__":
    asyncio.run(main())
