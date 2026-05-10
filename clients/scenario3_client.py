from pymodbus.client import ModbusTcpClient
import time

HOST    = '10.0.0.2'
PORT    = 5502
TIMEOUT = 1

client = ModbusTcpClient(HOST, port=PORT, timeout=TIMEOUT)

success = 0
fail    = 0
start_time = time.time()

print("Starting Modbus client (SCADA-01 / legitimate polling)...")
print("Target: PLC-PUMP1 at 10.0.0.2:5502")
print("Press Ctrl+C to stop\n")

try:
    client.connect()

    while True:
        req_start = time.time()

        try:
            result  = client.read_holding_registers(30000, 2, device_id=1)
            elapsed = time.time() - req_start

            if result.isError():
                print(f"[{time.strftime('%H:%M:%S')}] ERROR response | Time: {elapsed:.3f}s")
                fail += 1
            else:
                print(
                    f"[{time.strftime('%H:%M:%S')}] OK "
                    f"pump1-flow={result.registers[0]} "
                    f"pump2-flow={result.registers[1]} | Time: {elapsed:.3f}s"
                )
                success += 1

        except Exception as e:
            elapsed = time.time() - req_start
            print(f"[{time.strftime('%H:%M:%S')}] EXCEPTION: {e} | Time: {elapsed:.3f}s")
            fail += 1

        if int(time.time() - start_time) % 10 == 0:
            total = success + fail
            if total > 0:
                print("\n--- STATS ---")
                print(f"Success: {success}")
                print(f"Fail: {fail}")
                print(f"Failure Rate: {(fail/total)*100:.1f}%")
                print("-------------\n")
                time.sleep(1)

        time.sleep(1)

except KeyboardInterrupt:
    print("\nStopping client...")

finally:
    client.close()
    print(f"\nFinal Stats -> Success: {success}, Fail: {fail}")
