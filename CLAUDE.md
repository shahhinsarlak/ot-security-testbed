# Goulburn Water Treatment Plant — OT Security Testbed — CLAUDE.md

Single source of truth. Someone unfamiliar with this project should be able to get it running in under 20 minutes using only this file.

---

## Project overview

UTS 31261 Internetworking Capstone project demonstrating three Modbus TCP attack scenarios against a simulated water treatment plant OT network. The testbed uses Mininet to create virtual hosts representing the Goulburn Water Treatment Plant operated by AquaOps Utilities. Attacks are executed from a simulated engineer workstation and target a pymodbus-based PLC server.

Three scenarios:
1. Passive reconnaissance — enumerate all Modbus registers without authentication
2. Command injection — send unauthenticated FC5 write to trip the pump inlet valve (pump1-valve.closed)
3. Denial of service — threaded FC03 flood (300 threads, 150 registers each) to saturate plc1

---

## Team

| Name | Role | Scenario |
|---|---|---|
| Oscar Reinitz | Reconnaissance lead | Scenario 1 |
| Bailey Taylor | Command injection | Scenario 2 |
| Shahhin Sarlak | Command injection, integration lead | Scenario 2, overall |
| Daniel Sleiman | DoS lead | Scenario 3 |
| Johnson Huynh | DoS analysis | Scenario 3 |

---

## Environment (confirmed working 2026-04-14)

| Component | Version |
|---|---|
| OS | Ubuntu 24.04 LTS (WSL 2 on Windows 11 Pro 10.0.26200) |
| Python | 3.12.3 |
| pymodbus | 3.12.1 (pip install pymodbus) |
| Mininet | 2.3.0 (apt install mininet) |
| Open vSwitch | installed with Mininet |
| mbpoll | 1.4.11 (apt install mbpoll) |

---

## Topology

| Zone | Host | Name | IP | Role |
|------|------|------|----|------|
| IT Zone | ews01 | EWS-01 | 10.0.0.1 | Engineer workstation / primary attacker |
| IT Zone | ews02 | EWS-02 | 10.0.0.3 | Compromised laptop (Scenario 3 attacker 2) |
| IT Zone | ews03 | EWS-03 | 10.0.0.4 | Compromised laptop (Scenario 3 attacker 3) |
| OT Zone | plc1 | PLC-PUMP1 | 10.0.0.2 | Modbus TCP server, port 5502, primary target |
| OT Zone | plc2 | PLC-PUMP2 | 10.0.0.5 | Secondary PLC (idle by default) |
| Control Room | scada01 | SCADA-01 | 10.0.1.1 | SCADA polling client |
| Control Room | hist01 | HIST-01 | 10.0.1.2 | Data logger / Suricata IDS mirror port |
| Infrastructure | r1 | ROUT-BOUNDARY | 10.0.0.254 / 10.0.1.254 | IP router |
| Infrastructure | s1 | SWIT-OFFICE | — | OVS switch, IT zone |
| Infrastructure | s2 | SWIT-PLANT | — | OVS switch, OT zone |

---

## Register map (plc1 / PLC-PUMP1)

| Address | Type | Tag | Initial value |
|---|---|---|---|
| Coil 0 | Coil (FC01/FC05) | `pump1-valve.closed` | `True` (CLOSED) |
| Coil 1 | Coil (FC01/FC05) | `pump2-valve.closed` | `True` (CLOSED) |
| HR 30000 | Holding Register (FC03) | `pump1-flow.Lps` | 300 (litres/sec) |
| HR 30001 | Holding Register (FC03) | `pump2-flow.Lps` | 185 (litres/sec) |
| HR 30002–30010 | Holding Register (FC03) | Simulated telemetry | Various |

---

## Directory structure

```
ot-security-testbed/
  CLAUDE.md                  — this file
  run_scenarios.py           — automated runner: builds topology, starts server, runs all three attacks
  topology/
    mininet_topo.py          — interactive topology (use for manual testing with CLI)
  servers/
    modbus_server.py         — pymodbus 3.12 async Modbus TCP server on plc1, port 5502
  attacks/
    scenario1_recon.py       — FC01/02/03/04 register enumeration
    scenario2_command_injection.py  — FC05 coil write (pump valve trip)
    scenario3_dos_flood.py   — threaded FC03 flood (300 threads, 150 registers each)
  mitigations/
    mitigation1_ip_allowlist.py — iptables allowlist on plc1
    mitigation2_fc_filter.py    — proxy: blocks write FCs, allows reads
    mitigation3_rate_limit.py   — proxy: per-IP sliding window rate limiter
    run_mitigations_demo.py     — Mininet demo: all 3 mitigations before/after
  configs/
    suricata/
      ot-modbus.rules        — Suricata IDS rules for plc1 monitoring
  playbooks/
    scenario1_playbook.md    — full write-up: protocol, MITRE, commands, numbers, mitigations
    scenario2_playbook.md    — same structure for command injection
    scenario3_playbook.md    — same structure for DoS
  logs/
    session_log.md           — first-person technical journal of the 2026-04-14 session
  results/
    server_startup.txt       — mbpoll confirmation output from server startup
    scenario1_output.txt     — full recon output
    scenario1_register_map.txt  — formatted register map table
    scenario2_baseline.txt   — pre-attack HR read
    scenario2_output.txt     — full command injection output
    scenario2_post.txt       — post-attack HR read
    scenario3_baseline.txt   — pre-flood poll timings
    scenario3_output.txt     — full DoS output with final stats
```

---

## How to start the testbed from scratch

These steps assume you are in WSL Ubuntu. Set `REPO` to wherever you cloned the repo, e.g. `export REPO=/mnt/c/Users/$USER/ot-security-testbed`. All commands below use `$REPO` — substitute the actual path if you prefer.

**Step 1: Clean up any leftover state**

```bash
sudo mn -c
pkill -f 'python3.*modbus' 2>/dev/null || true
```

**Step 2: Check OVS is running**

```bash
sudo service openvswitch-switch start
sudo ovs-vsctl show
```

If you see existing bridges s1/s2 from a failed run, they will be removed by `mn -c` above.

**Step 3: Run the automated scenario runner**

```bash
cd $REPO
sudo python3 run_scenarios.py 2>&1 | tee results/full_run.txt
```

This will:
- Build the Mininet topology (ews01-03, plc1-2, scada01, hist01, s1, s2, r1)
- Apply OVS fail-mode and flows
- Verify ews01↔plc1 and scada01↔plc1 connectivity
- Start the Modbus server on plc1 (port 5502)
- Confirm server with mbpoll
- Run scenario 1 from ews01
- Run scenario 2 from ews01, reset pump1-valve to CLOSED
- Run 5-poll baseline, then scenario 3 from ews01 + ews02 + ews03 simultaneously for 30 seconds
- Save all results to results/
- Stop the network

Total runtime: approximately 90 seconds.

**Step 4 (optional): Interactive mode**

```bash
sudo python3 topology/mininet_topo.py
```

This opens the Mininet CLI. From the CLI you can run:

```
mininet> plc1 python3 $REPO/servers/modbus_server.py &
mininet> ews01 python3 $REPO/attacks/scenario1_recon.py --target 10.0.0.2
```

---

## How to run each attack scenario manually

All commands run from ews01 (10.0.0.1) in the Mininet CLI.

**Scenario 1 — Reconnaissance:**

```bash
python3 attacks/scenario1_recon.py --target 10.0.0.2 --port 5502
```

**Scenario 2 — Command Injection:**

```bash
# Pre-attack baseline
mbpoll -1 -a 1 -t 4 -r 30001 -c 1 10.0.0.2 -p 5502

# Attack
python3 attacks/scenario2_command_injection.py --target 10.0.0.2 --port 5502

# Post-attack confirmation
mbpoll -1 -a 1 -t 4 -r 30001 -c 1 10.0.0.2 -p 5502

# Reset pump1-valve back to CLOSED
python3 -c "
from pymodbus.client import ModbusTcpClient
c = ModbusTcpClient('10.0.0.2', port=5502)
c.connect()
c.write_coil(0, True, device_id=1)
print('pump1-valve reset to CLOSED')
c.close()
"
```

**Scenario 3 — DoS Flood:**

```bash
# From ews01 alone
python3 attacks/scenario3_dos_flood.py --target 10.0.0.2 --port 5502 --threads 300 --duration 30

# Distributed (run simultaneously from ews01, ews02, ews03):
mininet> ews01 python3 attacks/scenario3_dos_flood.py --threads 100 --duration 30 &
mininet> ews02 python3 attacks/scenario3_dos_flood.py --threads 100 --duration 30 &
mininet> ews03 python3 attacks/scenario3_dos_flood.py --threads 100 --duration 30
```

---

## Known issues and fixes

| Issue | Fix |
|---|---|
| `ModbusSlaveContext` not found in pymodbus 3.12 | Use `ModbusDeviceContext` from `pymodbus.datastore`. Import `ModbusDeviceIdentification` from `pymodbus` (top-level), not `pymodbus.device`. |
| `slave=1` keyword argument rejected by client calls | Use `device_id=1` in all `read_coils`, `write_coil`, `read_holding_registers` calls. |
| pymodbus 3.12 block address offset (+1) | `ModbusSequentialDataBlock(0, [False, True, True, ...])` — add a dummy element at index 0. For HR block: `ModbusSequentialDataBlock(30000, [0, 300, 185, ...])`. The FC request address N maps to `values[N - start + 1]`. |
| HR client address in pymodbus 3.12 | Use full Modbus address: `read_holding_registers(30000, count=1)`. Do NOT subtract 30000. |
| Server not binding when started via `plc1.cmd("... &")` | Use `plc1.popen(["python3", "server.py"], ...)` instead. The `&` inside `cmd()` doesn't reliably detach the process. |
| OVS bridges left over from failed Mininet runs | Run `sudo mn -c` before every run. |
| mbpoll coil address is 1-based | mbpoll `-r 1` reads coil 0 (FC01 address 0). mbpoll `-r 30001` reads HR 30000 (FC03 address 30000). |
| Hosts cannot ping each other | Run OVS fix manually: `sudo ovs-vsctl set-fail-mode s1 standalone && sudo ovs-ofctl add-flow s1 action=normal` (same for s2). |

---

## Completed so far (as of 2026-04-28)

- Full Mininet topology: ews01-03, plc1-2, scada01, hist01, s1, s2, r1 (Goulburn WTP / AquaOps)
- pymodbus 3.12 Modbus TCP server on plc1 with pump valve coils and flow telemetry registers
- Scenario 1 (reconnaissance): complete, output captured
- Scenario 2 (command injection): complete, pump1-valve trip confirmed, reset confirmed
- Scenario 3 (DoS): threaded flood with 300 threads, 150 registers each — distributed from ews01/02/03
- Three working mitigations with before/after demos (IP allowlist, FC filter, rate limiter)
- Suricata IDS rules in configs/suricata/ot-modbus.rules
- Three playbooks with real numbers
- Session log
- Automated runner script

---

## Still to do

- Capture tshark/Wireshark dump during scenario 2 for the A0 poster packet diagram
- Verify plc2 (PLC-PUMP2) as a second live attack target
- Write final report sections with rubric mapping
- Measure actual flood rate numbers from V2 threaded scenario 3 run

---

## Notes for the final report and A0 poster

**Key numbers to cite:**
- Scenario 2 attack time: under 1 second from connect to confirmed valve state change
- Scenario 2 frame size: 12 bytes (the smallest meaningful Modbus write)
- Scenario 3: 300 threads, 150 registers/request — cite the embedded PLC failure threshold (200-500 req/s from Dragos/Claroty research) to contextualise the real-world impact
- Scenario 3 legitimate poll result from V1 baseline: 17/17 success at 3,623 req/s (single-threaded async) — V2 threaded flood expected to significantly exceed this

**MITRE ATT&CK for ICS references:**
- T0861 (Point & Tag Identification) — scenario 1
- T0855 (Unauthorized Command Message) — scenario 2
- T0813 (Denial of Control) — scenario 3
- T0829 (Loss of View) — scenarios 2 and 3

**Protocol-level talking points for poster:**
- Modbus has no authentication, no encryption, no session layer
- FC5 Write Single Coil: 12-byte frame, immediate effect, no PLC-side logging
- The pump valve trip command is physically identical to a legitimate SCADA command — the PLC cannot distinguish them

**Real-world precedent:** Ukraine 2015 BlackEnergy attack used Modbus command injection against substations. Caused 6-hour outages for 230,000 customers. The protocol-level technique is identical to scenario 2. For water treatment context: Oldsmar Florida 2021 — attacker raised NaOH (lye) concentration 111x via SCADA before operator caught it.
