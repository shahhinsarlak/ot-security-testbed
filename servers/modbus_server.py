#!/usr/bin/env python3
"""
OT Security Testbed — Modbus TCP Server
========================================
Runs on h2 (10.0.0.2), port 5502.

Register map:
  Coil 0       tag: line-650632.closed    initial: True  (CLOSED)
  Coil 1       tag: line-651634.closed    initial: True  (CLOSED)
  HR 30000     tag: line-650632.kW        initial: 300
  HR 30001     tag: line-651634.kW        initial: 185
  HR 30002-30010  simulated telemetry     initial: varied 100-500

All writes are logged to stdout with timestamp, FC, address, value.
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
# Custom data block that logs writes
# ---------------------------------------------------------------------------
class LoggingDataBlock(ModbusSequentialDataBlock):
    """Extends ModbusSequentialDataBlock to log all writes."""

    def __init__(self, block_type, address, values):
        super().__init__(address, values)
        self.block_type = block_type

    def setValues(self, address, values):
        ts = datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
        for i, val in enumerate(values):
            addr = address + i
            log.info(
                f"WRITE | block={self.block_type} addr={addr} value={val} | {ts}"
            )
        super().setValues(address, values)


# ---------------------------------------------------------------------------
# Build initial register state
# ---------------------------------------------------------------------------
def build_context():
    # pymodbus 3.12 applies a 1-based internal offset: FC request address N →
    # block[N - start_addr + 1].  We add a dummy element at index 0 so that
    # client.read_coils(0) returns values[1] (coil-0) and
    # client.read_holding_registers(30000) returns values[1] (HR-30000).

    # Coils: index 0 = dummy (False), index 1 = coil-0 (line-650632.closed),
    #         index 2 = coil-1 (line-651634.closed)
    coil_values = [False, True, True] + [False] * 61   # 64 total
    coil_block = LoggingDataBlock("coil", 0, coil_values)

    # Discrete inputs (read-only)
    di_block = ModbusSequentialDataBlock(0, [False] * 64)

    # Input registers (read-only)
    ir_block = ModbusSequentialDataBlock(0, [0] * 32)

    # Holding registers: block starts at 30000.
    # index 0 = dummy (0)
    # index 1 = HR-30000 (line-650632.kW  = 300)
    # index 2 = HR-30001 (line-651634.kW  = 185)
    # index 3-11 = HR-30002..30010 (telemetry)
    telemetry = [220, 175, 310, 400, 130, 290, 500, 155, 445]  # 9 values
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
    print("=" * 60)
    print("  OT Security Testbed — Modbus Server")
    print("  Listening: 0.0.0.0:5502  (device_id=1)")
    print("=" * 60)
    print("  Coil 0  [line-650632.closed]  = True  (CLOSED)")
    print("  Coil 1  [line-651634.closed]  = True  (CLOSED)")
    print("  HR 30000 [line-650632.kW]     = 300")
    print("  HR 30001 [line-651634.kW]     = 185")
    for i, v in enumerate(telemetry):
        print(f"  HR {30002 + i} [telemetry-{i+2}]       = {v}")
    print("=" * 60)
    print("  Writes will be logged below.")
    print("=" * 60)
    sys.stdout.flush()


# ---------------------------------------------------------------------------
# Device identification
# ---------------------------------------------------------------------------
def build_identity():
    identity = ModbusDeviceIdentification()
    identity.VendorName = "OT-Sim Testbed"
    identity.ProductCode = "RTU-H2"
    identity.VendorUrl = "https://github.com/patsec/ot-sim"
    identity.ProductName = "Simulated RTU"
    identity.ModelName = "Line-650632 Controller"
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
