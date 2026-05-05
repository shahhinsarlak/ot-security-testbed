# OT Security Testbed — CLAUDE.md

Single source of truth. Someone unfamiliar with this project should be able to get it running in under 20 minutes using only this file.

---

## Project overview

UTS capstone project demonstrating three Modbus TCP attack scenarios against a simulated OT network. The testbed uses Mininet to create a network of virtual hosts representing a simplified substation SCADA environment. Attacks are executed from a simulated attacker host and target a pymodbus-based RTU server.

Three scenarios:
1. Passive reconnaissance — enumerate all Modbus registers without authentication
2. Command injection — send unauthenticated FC5 write to trip a virtual breaker
3. Denial of service — flood FC3 reads to blind the SCADA polling client

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

## Directory structure

```
ot-security-testbed/
  CLAUDE.md                  — this file
  run_scenarios.py           — automated runner: builds topology, starts server, runs all three attacks
  topology/
    mininet_topo.py          — interactive topology (use for manual testing with CLI)
  servers/
    modbus_server.py         — pymodbus 3.12 async Modbus TCP server, port 5502
  attacks/
    scenario1_recon.py       — FC01/02/03/04 register enumeration
    scenario2_command_injection.py  — FC05 coil write (breaker trip)
    scenario3_dos.py         — async FC03 flood + legitimate poll monitor thread
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
- Build the Mininet topology (h1-h5, s1-s2, r1)
- Verify h1↔h2 and h3↔h2 connectivity
- Start the Modbus server on h2 (port 5502)
- Confirm server with mbpoll
- Run scenario 1 from h1
- Run scenario 2 from h1, reset coil 0
- Run 5-poll baseline, then scenario 3 for 30 seconds
- Save all results to results/
- Stop the network

Total runtime: approximately 90 seconds.

**Step 4 (optional): Interactive mode**

```bash
sudo python3 topology/mininet_topo.py
```

This opens the Mininet CLI. From the CLI you can run:

```
mininet> h2 python3 $REPO/servers/modbus_server.py &
mininet> h1 python3 $REPO/attacks/scenario1_recon.py --target 10.0.0.2
```

---

## How to run each attack scenario manually

All commands run from h1 (10.0.0.1) in the Mininet CLI or via `h1.cmd()` in the runner.

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

# Reset coil 0 back to CLOSED
python3 -c "
from pymodbus.client import ModbusTcpClient
c = ModbusTcpClient('10.0.0.2', port=5502)
c.connect()
c.write_coil(0, True, device_id=1)
print('Coil 0 reset to CLOSED')
c.close()
"
```

**Scenario 3 — DoS:**

```bash
# 5-poll baseline (run first)
for i in 1 2 3 4 5; do
    mbpoll -1 -a 1 -t 4 -r 30001 -c 1 10.0.0.2 -p 5502
    sleep 2
done

# Flood
python3 attacks/scenario3_dos.py --target 10.0.0.2 --port 5502 --duration 30
```

---

## Known issues and fixes

| Issue | Fix |
|---|---|
| `ModbusSlaveContext` not found in pymodbus 3.12 | Use `ModbusDeviceContext` from `pymodbus.datastore`. Import `ModbusDeviceIdentification` from `pymodbus` (top-level), not `pymodbus.device`. |
| `slave=1` keyword argument rejected by client calls | Use `device_id=1` in all `read_coils`, `write_coil`, `read_holding_registers` calls. |
| pymodbus 3.12 block address offset (+1) | `ModbusSequentialDataBlock(0, [False, True, True, ...])` — add a dummy element at index 0. For HR block: `ModbusSequentialDataBlock(30000, [0, 300, 185, ...])`. The FC request address N maps to `values[N - start + 1]`. |
| HR client address in pymodbus 3.12 | Use full Modbus address: `read_holding_registers(30000, count=1)`. Do NOT subtract 30000. |
| `await client.close()` TypeError in scenario3 | `AsyncModbusTcpClient.close()` is synchronous. Remove `await`. |
| Server not binding when started via `h2.cmd("... &")` | Use `h2.popen(["python3", "server.py"], ...)` instead. The `&` inside `cmd()` doesn't reliably detach the process. |
| OVS bridges left over from failed Mininet runs | Run `sudo mn -c` before every run. |
| mbpoll coil address is 1-based | mbpoll `-r 1` reads coil 0 (FC01 address 0). mbpoll `-r 30001` reads HR 30000 (FC03 address 30000). |

---

## Completed so far (as of 2026-04-14)

- Full Mininet topology with IT/OT segmentation and router
- pymodbus 3.12 Modbus TCP server on h2 with coils and holding registers
- Scenario 1 (reconnaissance): complete, output captured
- Scenario 2 (command injection): complete, breaker trip confirmed, reset confirmed
- Scenario 3 (DoS): complete, 119,934 requests at 3,623 req/s, no poll failures in simulation
- Three playbooks with real numbers
- Session log
- Automated runner script

---

## Still to do

- Add SCADA HMI script on h3 that polls at 1s intervals (to show DoS competition in real time)
- Wireshark/tshark capture during scenario 2 for the A0 poster packet diagram
- Test h5 as a second live RTU (currently powered off by default)
- Write final report sections with rubric mapping
- Second run of scenario 3 against a resource-limited container or real embedded device if available

---

## Notes for the final report and A0 poster

**Key numbers to cite:**
- Scenario 2 attack time: under 1 second from connect to confirmed coil state change
- Scenario 2 frame size: 12 bytes (the smallest meaningful Modbus write)
- Scenario 3 flood rate: 3,623 req/s peak
- Scenario 3 legitimate poll result: 17/17 success — cite the embedded RTU failure threshold (200-500 req/s from Dragos/Claroty research) to contextualise why 3,623 would be devastating on real hardware

**MITRE ATT&CK for ICS references:**
- T0861 (Point & Tag Identification) — scenario 1
- T0855 (Unauthorized Command Message) — scenario 2
- T0813 (Denial of Control) — scenario 3
- T0829 (Loss of View) — scenarios 2 and 3

**Protocol-level talking points for poster:**
- Modbus has no authentication, no encryption, no session layer
- FC5 Write Single Coil: 12-byte frame, immediate effect, no RTU-side logging
- The breaker trip command is physically identical to a legitimate SCADA command — the RTU cannot distinguish them

**Real-world precedent:** Ukraine 2015 BlackEnergy attack used Modbus command injection against substations. Caused 6-hour outages for 230,000 customers. The protocol-level technique is identical to scenario 2.
