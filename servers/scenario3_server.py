from pymodbus.server import StartTcpServer
from pymodbus.datastore import (
    ModbusSlaveContext,
    ModbusServerContext,
    ModbusSequentialDataBlock,
)

store = ModbusSlaveContext(
    hr=ModbusSequentialDataBlock(30000, [300, 185] + [0] * 13)
)
context = ModbusServerContext(slaves=store, single=True)

print("OT Testbed - Scenario 3 Modbus server (PLC-PUMP1)")
print("Listening on 10.0.0.2:5502 -- no mitigations active")
StartTcpServer(context=context, address=("10.0.0.2", 5502))
