# OT Security Testbed

An educational Modbus TCP attack testbed built on [Mininet](http://mininet.org/) and [pymodbus](https://pymodbus.readthedocs.io/). Demonstrates three classic ICS/OT attack scenarios against a simulated substation RTU — no hardware required.

> **For educational and research use only.** Run against your own local testbed. Never target systems you do not own or have explicit written permission to test.

---

## What you get

Three self-contained attack scenarios executed from a virtual attacker host against a virtual RTU over Modbus TCP:

| # | Scenario | Function Codes | MITRE ATT&CK |
|---|----------|---------------|--------------|
| 1 | **Passive reconnaissance** — enumerate all registers without credentials | FC01 FC02 FC03 FC04 | T0861, T0888 |
| 2 | **Command injection** — unauthenticated breaker trip via coil write | FC05 | T0855 |
| 3 | **Denial of service** — async flood that blinds the SCADA polling client | FC03 | T0813, T0829 |

Each scenario has a matching playbook in `playbooks/` with a protocol-level breakdown, MITRE mapping, exact commands, before/after data, real-world impact analysis, and mitigations.

---

## Topology

```
  IT network (10.0.1.0/24)           OT network (10.0.0.0/24)
  ┌──────────┐  ┌──────────┐         ┌──────────┐  ┌──────────┐  ┌──────────┐
  │  h3      │  │  h4      │         │  h1      │  │  h2      │  │  h5      │
  │ SCADA/HMI│  │ Historian│         │ Attacker │  │ RTU/PLC  │  │ RTU #2   │
  │10.0.1.1  │  │10.0.1.2  │         │10.0.0.1  │  │10.0.0.2  │  │10.0.0.5  │
  └────┬─────┘  └────┬─────┘         └────┬─────┘  └────┬─────┘  └────┬─────┘
       │              │                   │              │              │
       └──────┬────────┘                  └──────┬───────┘──────────────┘
           [ s1 ]                              [ s2 ]
        IT-side OVS                         OT-side OVS
              │                                  │
              └──────────── [ r1 ] ───────────────┘
                          10.0.1.254 / 10.0.0.254
```

- **h2** runs the Modbus TCP server on port 5502, simulating an RTU with coils (breaker states) and holding registers (power telemetry).
- **h1** is the attacker — all three scenario scripts run from here.
- **h3** and **h4** represent the IT-side SCADA/historian, connected via the router.
- **h5** is a second RTU stub (powered off by default).

---

## Register map

| Address | Type | Tag | Initial value |
|---------|------|-----|---------------|
| Coil 0 | Coil (FC01/FC05) | `line-650632.closed` | `True` (CLOSED) |
| Coil 1 | Coil (FC01/FC05) | `line-651634.closed` | `True` (CLOSED) |
| HR 30000 | Holding Register (FC03) | `line-650632.kW` | 300 |
| HR 30001 | Holding Register (FC03) | `line-651634.kW` | 185 |
| HR 30002–30010 | Holding Register (FC03) | Simulated telemetry | Various |

---

## Prerequisites

### System (Linux or WSL 2 on Windows)

```bash
sudo apt update
sudo apt install -y mininet openvswitch-switch mbpoll python3-pip xterm x11-xserver-utils
```

> **WSL 2 users:** Ubuntu 24.04 LTS on WSL 2 is confirmed working. Start OVS manually before each session: `sudo service openvswitch-switch start`. Also set your display before running Mininet: `export DISPLAY=:0`

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
sudo mn --version     # should print Mininet 2.x.x
python3 -c "import pymodbus; print(pymodbus.__version__)"  # should print 3.12.x
```

---

## Quick start — automated runner

Runs all three scenarios end-to-end and saves output to `results/`:

```bash
# Clean up any leftover Mininet state first
sudo mn -c

# Run all scenarios (~90 seconds total)
sudo python3 run_scenarios.py 2>&1 | tee results/full_run.txt
```

The runner will:
1. Build the Mininet topology (h1–h5, s1–s2, r1)
2. Start the Modbus server on h2
3. Confirm with mbpoll
4. Run scenario 1 from h1
5. Run scenario 2 from h1, then reset the coil
6. Run a 5-poll timing baseline, then scenario 3 for 30 seconds
7. Save all results to `results/`
8. Tear down the network

---

## Manual usage — interactive mode

Start the topology and get a Mininet CLI:

```bash
sudo mn -c  # clean up first
sudo python3 topology/mininet_topo.py
```

From the CLI, start the server and run scenarios by hand:

```
mininet> h2 python3 servers/modbus_server.py &
mininet> h1 mbpoll -1 -a 1 -t 4 -r 30001 -c 1 10.0.0.2 -p 5502
```

### Scenario 1 — Reconnaissance

```
mininet> h1 python3 attacks/scenario1_recon.py --target 10.0.0.2 --port 5502
```

Outputs a full register map. No writes, no trace left on the RTU.

### Scenario 2 — Command Injection

```
mininet> h1 python3 attacks/scenario2_command_injection.py --target 10.0.0.2 --port 5502
```

Reads the pre-attack coil state, prints the raw FC5 frame breakdown byte-by-byte, sends the write, confirms the coil flipped, and prints a before/after comparison.

Reset the breaker after:

```
mininet> h1 python3 -c "
from pymodbus.client import ModbusTcpClient
c = ModbusTcpClient('10.0.0.2', port=5502)
c.connect()
c.write_coil(0, True, device_id=1)
print('Coil 0 reset: CLOSED')
c.close()
"
```

### Scenario 3 — Denial of Service

```
mininet> h1 python3 attacks/scenario3_dos.py --target 10.0.0.2 --port 5502 --duration 30
```

Runs an async FC03 flood for 30 seconds while a monitoring thread measures legitimate poll response times. Prints requests/sec and poll success rate at the end.

---

## Sample results

From a confirmed run on Ubuntu 24.04 LTS (WSL 2):

**Scenario 1:** All coils and holding registers enumerated in under 2 seconds. No credentials required, no log entry on the RTU.

**Scenario 2:** Coil 0 flipped from `True (CLOSED)` to `False (OPEN)` in under 1 second. Attack frame is 12 bytes — the minimum possible Modbus write.

**Scenario 3:** 119,934 requests at **3,623 req/s** peak. In simulation (pymodbus server), legitimate polls continued to succeed. On embedded RTUs, Dragos/Claroty research documents failure at 200–500 req/s.

Full output is in `results/`.

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `mn: command not found` | `sudo apt install mininet` |
| OVS bridges left from a failed run | `sudo mn -c` before running anything |
| `ModbusSlaveContext not found` | You are on pymodbus 3.x — use `ModbusDeviceContext` from `pymodbus.datastore` |
| `slave=` keyword rejected | pymodbus 3.x renamed it to `device_id=` |
| Server not binding when started with `h2.cmd("... &")` | Use `h2.popen(["python3", ...])` instead |
| `mbpoll -r 30001` to read HR 30000 | mbpoll uses 1-based addressing: `-r N` reads PDU address `N-1` |
| WSL 2: OVS bridge errors on startup | `sudo service openvswitch-switch start` then `sudo mn -c` |

---

## Mitigations

The `mitigations/` directory contains working defenses against each attack scenario. Each mitigation runs the attack twice — once without protection to confirm it works, then again with the mitigation applied to confirm it is blocked or limited.

| Mitigation | File | Technique | Stops |
|---|---|---|---|
| IP Allowlisting | `run_mitigations_demo.py` | iptables on h2 | Unauthorized hosts reaching the RTU |
| Function Code Filter | `mitigation2_fc_filter.py` | Modbus proxy that inspects FC byte | Write commands (FC05/06/0F/10) |
| Rate Limiting | `mitigation3_rate_limit.py` | Sliding-window proxy per source IP | DoS floods exceeding N req/s |

**Run all three demos end-to-end:**

```bash
sudo mn -c
sudo python3 mitigations/run_mitigations_demo.py 2>&1 | tee results/mitigations/full_run.txt
```

**Run the proxies standalone (no Mininet):**

```bash
# Terminal 1 — RTU
python3 servers/modbus_server.py

# Terminal 2 — pick one proxy
python3 mitigations/mitigation2_fc_filter.py --listen-port 5503 --upstream 127.0.0.1:5502
# or
python3 mitigations/mitigation3_rate_limit.py --listen-port 5503 --upstream 127.0.0.1:5502 --max-rps 20

# Terminal 3 — attack through the proxy
python3 attacks/scenario2_command_injection.py --target 127.0.0.1 --port 5503
```

See `mitigations/README.md` for a full explanation of each approach, the exact proxy output to expect, and real-world product equivalents.

---

## Real-world attack vectors

How would these attacks happen outside of a lab? See [`docs/real-world-attack-vectors.md`](docs/real-world-attack-vectors.md) for a full breakdown covering:

- Why physical access to the RTU is rarely required
- The five routes attackers use to reach OT networks (IT pivot, VPN, internet-exposed devices, supply chain, physical)
- How each scenario maps to a real attack stage
- Real incidents: Ukraine 2015 BlackEnergy, Oldsmar water plant, Industroyer/Crashoverride

---

## Playbooks

Detailed write-ups are in `playbooks/`:

- `scenario1_playbook.md` — Passive reconnaissance
- `scenario2_playbook.md` — Command injection
- `scenario3_playbook.md` — Denial of service

Each playbook covers: protocol mechanics, MITRE ATT&CK mapping, exact commands run, before/after data, real-world impact analysis, and three recommended mitigations.

---

## Project structure

```
ot-security-testbed/
├── run_scenarios.py              Automated end-to-end runner (all 3 attacks)
├── topology/
│   └── mininet_topo.py           Mininet topology (interactive CLI mode)
├── servers/
│   └── modbus_server.py          pymodbus 3.12 async Modbus TCP server
├── attacks/
│   ├── scenario1_recon.py        FC01/02/03/04 register enumeration
│   ├── scenario2_command_injection.py  FC05 coil write (breaker trip)
│   └── scenario3_dos.py          Async FC03 flood with poll monitor
├── mitigations/
│   ├── README.md                 Explanation of each mitigation + real-world equivalents
│   ├── mitigation2_fc_filter.py  Proxy: blocks write FCs, allows reads
│   ├── mitigation3_rate_limit.py Proxy: per-IP sliding window rate limiter
│   └── run_mitigations_demo.py   Mininet demo: all 3 mitigations before/after
├── playbooks/
│   ├── scenario1_playbook.md
│   ├── scenario2_playbook.md
│   └── scenario3_playbook.md
└── results/                      Sample output from a confirmed run
```

---

## Disclaimer

This testbed is for **educational and research purposes only**. All attacks run against a locally simulated network with no connection to real infrastructure. The authors do not condone unauthorized access to any computer system. Understand your local laws before running any security tools.

---

## License

MIT — see [LICENSE](LICENSE) for details.
