# Goulburn Water Treatment Plant -- OT Security Testbed

An educational Modbus TCP attack testbed built on [Mininet](http://mininet.org/) and [pymodbus](https://pymodbus.readthedocs.io/).
Simulates the Goulburn Water Treatment Plant operated by **AquaOps Utilities**, demonstrating three classic ICS/OT attack scenarios against a simulated PLC -- no hardware required.

**Subject:** 31261 Internetworking Capstone, University of Technology Sydney (UTS)

> **For educational and research use only.** Run against your own local testbed. Never target systems you do not own or have explicit written permission to test.

---

## What you get

Three self-contained attack scenarios executed from a virtual attacker workstation against a virtual PLC over Modbus TCP:

| # | Scenario | Function Codes | MITRE ATT&CK |
|---|----------|----------------|--------------|
| 1 | **Passive reconnaissance** -- enumerate all registers without credentials | FC01 FC02 FC03 FC04 | T0861, T0888 |
| 2 | **Command injection** -- unauthenticated pump valve trip via coil write | FC05 | T0855 |
| 3 | **Denial of service** -- threaded flood that prevents SCADA polling | FC03 | T0813, T0829 |

---

## Topology

```
  IT Zone (Office Network)         OT Zone (Plant Floor)
  10.0.0.0/24 -- SWIT-OFFICE      10.0.0.0/24 -- SWIT-PLANT
  +----------+                     +-----------+
  | ews01    |                     | plc1      |
  | EWS-01   |                     | PLC-PUMP1 |
  | 10.0.0.1 |                     | 10.0.0.2  |  <-- Modbus TCP port 5502
  +----------+                     +-----------+
  | ews02    |                     | plc2      |
  | EWS-02   |                     | PLC-PUMP2 |
  | 10.0.0.3 |                     | 10.0.0.5  |  (idle)
  +----------+                     +-----------+
  | ews03    |
  | EWS-03   |
  | 10.0.0.4 |
  +----+-----+
       |  s1 (SWIT-OFFICE)        s2 (SWIT-PLANT)
       +------ peer trunk ---------+
              |                   |
              r1 (ROUT-BOUNDARY)
              10.0.0.254 / 10.0.1.254
              |
       Control Room (10.0.1.0/24)
       +----------+   +---------+
       | scada01  |   | hist01  |
       | SCADA-01 |   | HIST-01 |
       | 10.0.1.1 |   |10.0.1.2 |
       +----------+   +---------+
```

### Host table

| Zone | Host | Name | IP | Role |
|------|------|------|----|------|
| IT Zone | ews01 | EWS-01 | 10.0.0.1 | Engineer workstation / primary attacker |
| IT Zone | ews02 | EWS-02 | 10.0.0.3 | Compromised laptop (Scenario 3 attacker 2) |
| IT Zone | ews03 | EWS-03 | 10.0.0.4 | Compromised laptop (Scenario 3 attacker 3) |
| OT Zone | plc1 | PLC-PUMP1 | 10.0.0.2 | Modbus TCP server, port 5502, primary target |
| OT Zone | plc2 | PLC-PUMP2 | 10.0.0.5 | Secondary PLC (idle by default) |
| Control Room | scada01 | SCADA-01 | 10.0.1.1 | SCADA polling client |
| Control Room | hist01 | HIST-01 | 10.0.1.2 | Data logger / Suricata IDS mirror port |
| Infrastructure | r1 | ROUT-BOUNDARY | 10.0.0.254 / 10.0.1.254 | IP router, ip_forward=1 |
| Infrastructure | s1 | SWIT-OFFICE | -- | OVS switch, IT zone |
| Infrastructure | s2 | SWIT-PLANT | -- | OVS switch, OT zone |

---

## Register map (PLC-PUMP1 / plc1)

| Address | Type | Tag | Initial value |
|---------|------|-----|---------------|
| Coil 0 | Coil (FC01/FC05) | `pump1-valve.closed` | `True` (CLOSED) |
| Coil 1 | Coil (FC01/FC05) | `pump2-valve.closed` | `True` (CLOSED) |
| HR 30000 | Holding Register (FC03) | `pump1-flow.Lps` | 300 (litres/sec) |
| HR 30001 | Holding Register (FC03) | `pump2-flow.Lps` | 185 (litres/sec) |
| HR 30002-30010 | Holding Register (FC03) | Simulated telemetry | Various |

---

## Prerequisites

### System (Linux or WSL 2 on Windows)

```bash
sudo apt update
sudo apt install -y mininet openvswitch-switch mbpoll python3-pip xterm x11-xserver-utils
```

> **WSL 2 users:** Ubuntu 24.04 LTS on WSL 2 is confirmed working.
> Start OVS before each session: `sudo service openvswitch-switch start`
> Set display: `export DISPLAY=:0`

### Python

```bash
pip install pymodbus>=3.12
```

Or with the requirements file:

```bash
pip install -r requirements.txt
```

### Verify the install

```bash
sudo mn --version      # should print Mininet 2.x.x
python3 -c "import pymodbus; print(pymodbus.__version__)"   # should print 3.12.x
```

---

## OVS fix (run this if switches do not forward traffic)

These four commands are run automatically on startup, but you can run them manually if needed:

```bash
sudo ovs-vsctl set-fail-mode s1 standalone
sudo ovs-vsctl set-fail-mode s2 standalone
sudo ovs-ofctl add-flow s1 action=normal
sudo ovs-ofctl add-flow s2 action=normal
```

---

## Quick start -- automated runner

Runs all three scenarios end-to-end and saves output to `results/`:

```bash
# Clean up any leftover Mininet state first
sudo mn -c

# Run all scenarios (~90 seconds total)
sudo python3 run_scenarios.py 2>&1 | tee results/full_run.txt
```

The runner will:
1. Build the Mininet topology (ews01-03, plc1-2, scada01, hist01, s1, s2, r1)
2. Apply the OVS fix automatically
3. Start the Modbus server on plc1
4. Confirm with mbpoll
5. Run Scenario 1 from ews01
6. Run Scenario 2 from ews01, then reset the valve
7. Run a 5-poll timing baseline, then Scenario 3 from ews01 + ews02 + ews03 simultaneously for 30 seconds
8. Save all results to `results/`
9. Tear down the network

---

## Manual usage -- interactive mode

Start the topology and get a Mininet CLI:

```bash
sudo mn -c
sudo python3 topology/mininet_topo.py
```

From the CLI, start the server and run scenarios by hand:

```
mininet> plc1 python3 servers/modbus_server.py &
mininet> ews01 mbpoll -1 -a 1 -t 4 -r 30001 -c 1 10.0.0.2 -p 5502
```

### Scenario 1 -- Reconnaissance

```
mininet> ews01 python3 attacks/scenario1_recon.py --target 10.0.0.2 --port 5502
```

Sweeps FC01 coils 0-9, FC03 HRs 30000-30015, FC02 discrete inputs 0-9, FC04 input registers 0-9.
Outputs a full register map with tag names. Reports total sweep time in ms.

### Scenario 2 -- Command Injection

```
mininet> ews01 python3 attacks/scenario2_command_injection.py --target 10.0.0.2 --port 5502
```

Reads pre-attack state, prints the full 12-byte Modbus TCP ADU breakdown, sends FC5 Write Coil 0 = False (OPEN), reads post-attack state, and prints a before/after comparison with real-world impact description.

Reset the valve after the attack:

```
mininet> ews01 python3 -c "
from pymodbus.client import ModbusTcpClient
c = ModbusTcpClient('10.0.0.2', port=5502)
c.connect()
c.write_coil(0, True, device_id=1)
print('pump1-valve reset: CLOSED')
c.close()
"
```

### Scenario 3 -- DoS Flood

```
mininet> ews01 python3 attacks/scenario3_dos_flood.py --target 10.0.0.2 --port 5502 --threads 300 --duration 30
```

Launches 300 threads, each sending FC03 reads of 150 registers in a tight loop. Prints a live counter of requests sent and errors every 2 seconds. On connection error, each thread reconnects automatically.

For a distributed DoS, launch from multiple hosts simultaneously:

```
mininet> ews01 python3 attacks/scenario3_dos_flood.py --threads 100 --duration 30 &
mininet> ews02 python3 attacks/scenario3_dos_flood.py --threads 100 --duration 30 &
mininet> ews03 python3 attacks/scenario3_dos_flood.py --threads 100 --duration 30
```

---

## Mitigations

The `mitigations/` directory contains working defences against each attack scenario.

| # | Mitigation | File | Technique | Stops |
|---|-----------|------|-----------|-------|
| 1 | IP Allowlisting | `mitigation1_ip_allowlist.py` | iptables on plc1 | Unauthorised hosts reaching port 5502 |
| 2 | Function Code Filter | `mitigation2_fc_filter.py` | Modbus proxy inspects FC byte | Write commands (FC05/06/0F/10) |
| 3 | Rate Limiting | `mitigation3_rate_limit.py` | Per-IP sliding window + timeout | DoS floods exceeding N req/s |

### Run all three demos end-to-end

```bash
sudo mn -c
sudo python3 mitigations/run_mitigations_demo.py 2>&1 | tee results/mitigations/full_run.txt
```

### Mitigation 1 -- IP Allowlisting

```
mininet> plc1 python3 mitigations/mitigation1_ip_allowlist.py --apply
```

Only scada01 (10.0.1.1) can reach port 5502. All other connections are silently dropped.

```
mininet> plc1 python3 mitigations/mitigation1_ip_allowlist.py --remove
```

### Mitigation 2 -- Function Code Filter Proxy (standalone)

```bash
# Terminal 1 -- plc1 Modbus server
python3 servers/modbus_server.py

# Terminal 2 -- FC filter proxy
python3 mitigations/mitigation2_fc_filter.py --listen-port 5503 --upstream 127.0.0.1:5502

# Terminal 3 -- attack through the proxy (FC05 blocked)
python3 attacks/scenario2_command_injection.py --target 127.0.0.1 --port 5503
```

### Mitigation 3 -- Rate-Limiting Proxy (standalone)

```bash
# Terminal 1 -- plc1 Modbus server
python3 servers/modbus_server.py

# Terminal 2 -- rate-limit proxy (100 req/s per IP, 20s timeout)
python3 mitigations/mitigation3_rate_limit.py \
    --listen-port 5503 --upstream 127.0.0.1:5502 \
    --threshold 100 --timeout 20

# Terminal 3 -- flood through proxy (will be throttled)
python3 attacks/scenario3_dos_flood.py --target 127.0.0.1 --port 5503 --threads 50
```

---

## Suricata IDS rules

Rules for monitoring Modbus traffic to plc1 are in `configs/suricata/ot-modbus.rules`.
Deploy on hist01 (10.0.1.2) configured as a mirror port.

| SID | Description | MITRE |
|-----|-------------|-------|
| 9000010 | Modbus TCP connection to PLC-PUMP1 | T0861 |
| 9000011 | Modbus write FC detected (pump1-valve.closed at risk) | T0855 |
| 9000012 | Modbus request flood detected (pump1-flow.Lps monitoring at risk) | T0813, T0829 |

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `mn: command not found` | `sudo apt install mininet` |
| OVS bridges left from a failed run | `sudo mn -c` before running |
| `ModbusSlaveContext not found` | Use `ModbusDeviceContext` from `pymodbus.datastore` (pymodbus 3.x) |
| `slave=` keyword rejected | pymodbus 3.x renamed it to `device_id=` |
| Server not binding with `plc1.cmd("... &")` | Use `plc1.popen(["python3", ...])` instead |
| `mbpoll -r 30001` to read HR 30000 | mbpoll uses 1-based addressing: `-r N` reads PDU address `N-1` |
| WSL 2: OVS bridge errors on startup | `sudo service openvswitch-switch start` then `sudo mn -c` |
| Hosts cannot ping each other | Run the OVS fix commands manually (see section above) |

---

## Project structure

```
ot-security-testbed/
+-- run_scenarios.py              Automated end-to-end runner (all 3 attacks)
+-- topology/
|   +-- mininet_topo.py           Mininet topology (interactive CLI mode)
+-- servers/
|   +-- modbus_server.py          pymodbus 3.12 async Modbus TCP server (plc1)
+-- attacks/
|   +-- scenario1_recon.py        FC01/02/03/04 register enumeration
|   +-- scenario2_command_injection.py  FC05 pump valve write
|   +-- scenario3_dos_flood.py    Threaded FC03 flood (300 threads default)
+-- mitigations/
|   +-- mitigation1_ip_allowlist.py  iptables allowlist on plc1
|   +-- mitigation2_fc_filter.py     Proxy: blocks write FCs, allows reads
|   +-- mitigation3_rate_limit.py    Proxy: per-IP sliding window rate limiter
|   +-- run_mitigations_demo.py      Mininet demo: all 3 mitigations before/after
+-- configs/
|   +-- suricata/
|       +-- ot-modbus.rules       Suricata IDS rules for plc1 monitoring
+-- playbooks/
|   +-- scenario1_playbook.md
|   +-- scenario2_playbook.md
|   +-- scenario3_playbook.md
+-- results/                      Sample output from a confirmed run
```

---

## Disclaimer

This testbed is for **educational and research purposes only**. All attacks run against a locally simulated network with no connection to real infrastructure. The authors do not condone unauthorised access to any computer system. Understand your local laws before running any security tools.

---

## License

MIT -- see [LICENSE](LICENSE) for details.
