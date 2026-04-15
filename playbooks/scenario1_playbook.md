# Scenario 1 — Modbus Register Enumeration (Reconnaissance)

**Testbed:** patsec/ot-sim layout | **Date:** 2026-04-14 | **Owner:** Oscar Reinitz
**Platform:** Ubuntu 24.04 LTS | Mininet 2.3 | pymodbus 3.12.1 | mbpoll 1.4.11

---

## 1. What the attack does at the protocol level

Modbus TCP has no authentication. Any host that can reach TCP port 5502 on the RTU can send function code requests without credentials, session tokens, or any proof of identity.

Reconnaissance sends four function code requests in sequence:

- **FC01 Read Coils** — reads digital output status (breaker positions, valve states)
- **FC02 Read Discrete Inputs** — reads digital input status (sensor signals)
- **FC03 Read Holding Registers** — reads 16-bit analogue values (power, voltage, current)
- **FC04 Read Input Registers** — reads read-only analogue telemetry

Each request specifies a starting address and count. The RTU replies with the values at those addresses. No log entry is generated on the RTU side unless the operator has deployed an external packet capture. The attacker learns the full register map without leaving any footprint on the target device.

The script also walks address ranges outside the configured data block (e.g., HR 30011-30015) and gets zeros back, confirming the active range.

---

## 2. MITRE ATT&CK for ICS mapping

| Tactic | Technique | ID |
|---|---|---|
| Collection | Point & Tag Identification | T0861 |
| Discovery | Remote System Information Discovery | T0888 |
| Collection | Monitor Process State | T0801 |

The reconnaissance output directly feeds T0855 (Unauthorized Command Message) in the next phase.

---

## 3. Exact commands run

Run from h1 (10.0.0.1) against h2 (10.0.0.2):

```
python3 attacks/scenario1_recon.py --target 10.0.0.2 --port 5502
```

Actual output captured 2026-04-14T16:33:38:

```
[+] Connected to 10.0.0.2:5502

[*] Scanning coils 0 to 9 ...
  Coil     0  =>  True   (CLOSED)
  Coil     1  =>  True   (CLOSED)
  Coil     2  =>  False  (OPEN)
  ...
  Coil     9  =>  False  (OPEN)

[*] Scanning holding registers 30000 to 30015 ...
  HR 30000  =>  300
  HR 30001  =>  185
  HR 30002  =>  220
  HR 30003  =>  175
  HR 30004  =>  310
  HR 30005  =>  400
  HR 30006  =>  130
  HR 30007  =>  290
  HR 30008  =>  500
  HR 30009  =>  155
  HR 30010  =>  445
  HR 30011  =>  0
  HR 30012  =>  0
  HR 30013  =>  0
  HR 30014  =>  0
  HR 30015  =>  0

[*] Scanning discrete inputs 0 to 9 ...
  DI 0 through DI 9: False (server returns zeros for all DI)

[*] Scanning input registers 0 to 9 ...
  IR 0 through IR 9: 0 (no input registers exposed)
```

---

## 4. Before and after register values

This scenario is read-only — no register values change. Full discovered map:

| Address | Value | Tag |
|---|---|---|
| Coil 0 | True (CLOSED) | line-650632.closed |
| Coil 1 | True (CLOSED) | line-651634.closed |
| HR 30000 | 300 | line-650632.kW |
| HR 30001 | 185 | line-651634.kW |
| HR 30002 | 220 | telemetry-2 |
| HR 30003 | 175 | telemetry-3 |
| HR 30004 | 310 | telemetry-4 |
| HR 30005 | 400 | telemetry-5 |
| HR 30006 | 130 | telemetry-6 |
| HR 30007 | 290 | telemetry-7 |
| HR 30008 | 500 | telemetry-8 |
| HR 30009 | 155 | telemetry-9 |
| HR 30010 | 445 | telemetry-10 |
| HR 30011-30015 | 0 | (unallocated) |

Discrete inputs and input registers: all zeros. The server does not expose these data types for this device.

---

## 5. What this would mean in a real substation

An attacker sitting on the OT VLAN (or having crossed the IT/OT boundary) can enumerate every data point the RTU exposes in under two seconds. With coil 0 showing CLOSED and HR 30000 showing 300 kW, they know:

- Which feeder circuits are live
- Approximate load on each feeder
- Which coil addresses to target for circuit trip commands
- The telemetry range (30000-30010) to monitor for load-shedding thresholds

In a real Modbus deployment this data is sufficient to plan a targeted attack: identify the highest-load breaker, write a trip command to its coil during peak demand, and maximise the impact.

The Modbus protocol has no concept of "read-only to untrusted hosts." Every register the RTU exposes is readable by anyone on the segment.

---

## 6. Recommended mitigations

1. **Network segmentation with default-deny ACLs.** Place RTUs behind a data diode or unidirectional gateway. Only authorised SCADA host IPs (h3 in this topology, 10.0.1.1) should be able to reach port 5502. Implement on the OT switch using ACLs or a purpose-built industrial firewall (e.g., Tofino, Claroty guard). This stops reconnaissance from any host that does not have explicit permit rules.

2. **Modbus application-layer firewall (deep packet inspection).** Deploy a proxy such as Belden Tofino or a Snort/Suricata IDS with Modbus preprocessor. Configure read-only rules: allow FC01, FC02, FC03, FC04 from SCADA hosts only, block all FC05, FC06, FC15, FC16 from any source outside the engineering workstation MAC/IP. This lets telemetry polling continue but blocks command writes from unknown sources.

3. **Continuous passieve monitoring with anomaly detection.** Deploy Dragos Platform, Claroty, or a free alternative (Zeek with Modbus scripts) on a SPAN port. Baseline normal polling intervals and register access patterns. Alert on: new source IPs accessing port 5502, coil reads from a non-SCADA IP, sequential sweeps of coil or register address ranges. The recon script's sequential sweep of addresses 0-9 then 30000-30015 is a clear signature.

---

## 7. Detection opportunities

**Suricata rule — Modbus coil sweep:**

```
alert tcp any any -> 10.0.0.2 5502 (
  msg:"MODBUS FC01 Coil Read from non-SCADA host";
  flow:to_server,established;
  content:"|00 00 00 06|";
  offset:2; depth:4;
  byte_test:1,=,1,7;
  threshold:type both, track by_src, count 5, seconds 10;
  sid:9000001; rev:1;
)
```

**Suricata rule — FC03 holding register read from unknown source:**

```
alert tcp !10.0.1.1 any -> 10.0.0.2 5502 (
  msg:"MODBUS FC03 HR Read from non-SCADA source";
  flow:to_server,established;
  byte_test:1,=,3,7;
  sid:9000002; rev:1;
)
```

**SCADA alert:** If the HMI (h3) polls on a 1-second cycle, a second Modbus session from a different source IP should trigger an operator alert within one polling cycle.

---

## 8. Issues encountered during execution

- `ModbusSlaveContext` does not exist in pymodbus 3.12. Had to replace with `ModbusDeviceContext` and `slaves=` with `devices=`. Fixed before first successful run.
- pymodbus 3.12 applies a +1 internal offset for all function codes. `ModbusSequentialDataBlock(0, [True, True, ...])` needs a dummy element at index 0 so that FC01 address 0 maps to the correct value. Discovered by running mbpoll against the test server and comparing expected vs returned values.
- `slave=1` keyword argument was removed in pymodbus 3.12; now `device_id=1`. Replaced across all scripts before the Mininet run.
- The recon scan successfully completed in approximately 1.2 seconds for all four data types.
