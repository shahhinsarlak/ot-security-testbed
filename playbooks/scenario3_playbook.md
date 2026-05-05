# Scenario 3 — Modbus TCP Denial of Service (Threaded FC03 Flood)

**Testbed:** Goulburn WTP — AquaOps Utilities (UTS 31261 Internetworking Capstone) | **Date:** 2026-04-14 | **Owner:** Daniel Sleiman and Johnson Huynh
**Platform:** Ubuntu 24.04 LTS | Mininet 2.3 | pymodbus 3.12.1 | mbpoll 1.4.11
**Attackers:** ews01 (10.0.0.1) + ews02 (10.0.0.3) + ews03 (10.0.0.4) | **Target:** plc1 (PLC-PUMP1, 10.0.0.2, port 5502)

---

## 1. What the attack does at the protocol level

This attack launches 300 threads from ews01 (and optionally ews02 + ews03 simultaneously for a distributed attack), each maintaining a persistent Modbus TCP connection to plc1 and firing **FC03 Read Holding Registers** requests (150 registers per request) in a tight loop.

FC03 is used because it is always valid (no write access needed) and causes the server to do real work — look up register values and build a response — for every request. Unlike a SYN flood, this attack completes the TCP handshake and operates entirely within a legitimate protocol. Requesting 150 registers per read (instead of 1) maximises the server processing cost per request.

The attack runs for 30 seconds. Each thread reconnects automatically on connection error. A live reporter prints requests-sent and error counts every 2 seconds.

The intent is to saturate the PLC's ability to process Modbus requests, causing legitimate SCADA polls from scada01 to time out and lose visibility into pump valve states and flow telemetry. Real PLCs often run on 32-bit embedded processors with limited TCP stack resources. A distributed flood from three hosts can exhaust connection tables, causing SCADA to lose all view of the plant.

---

## 2. MITRE ATT&CK for ICS mapping

| Tactic | Technique | ID |
|---|---|---|
| Inhibit Response Function | Service Stop | T0881 |
| Inhibit Response Function | Denial of Control | T0813 |
| Impact | Loss of View | T0829 |
| Impact | Loss of Availability | T0826 |

Loss of view (T0829) is particularly relevant: if the SCADA HMI cannot poll the RTU, operators have no visibility into the current state of the substation. They cannot see if a breaker is open or closed, whether a fault exists, or what the load is. Operating blind in a substation is a safety risk.

---

## 3. Exact commands run

**Baseline (5 polls from runner before flood):**

```
Poll 1: 22.1ms
Poll 2: 22.3ms
Poll 3: 22.4ms
Poll 4: 22.2ms
Poll 5: 22.8ms
```

Note: the 22ms baseline reflects Mininet's inter-namespace loopback latency (not a real Ethernet link). In production environments baseline is typically 1-5ms over LAN.

**Attack run (from ews01 — single host):**

```
python3 attacks/scenario3_dos_flood.py --target 10.0.0.2 --port 5502 --threads 300 --duration 30
```

**Distributed attack (ews01 + ews02 + ews03 simultaneously):**

```
mininet> ews01 python3 attacks/scenario3_dos_flood.py --threads 100 --duration 30 &
mininet> ews02 python3 attacks/scenario3_dos_flood.py --threads 100 --duration 30 &
mininet> ews03 python3 attacks/scenario3_dos_flood.py --threads 100 --duration 30
```

V1 reference output from 2026-04-14T16:33:58 (single async client — new threaded version expected to significantly exceed these numbers):

```
[*] Measuring 3-sample baseline (pre-flood)...
    Pre-flood poll 1: 0.5ms  (ok)
    Pre-flood poll 2: 0.4ms  (ok)
    Pre-flood poll 3: 0.3ms  (ok)
    Baseline avg: 0.4ms

  [  8.0s / 30s]  Flood:   19963 sent     2491 req/s  |  Poll: 5/5 ok (100%)  avg 0ms
  [ 13.0s / 30s]  Flood:   39833 sent     3059 req/s  |  Poll: 7/7 ok (100%)  avg 0ms
  [ 18.0s / 30s]  Flood:   59589 sent     3305 req/s  |  Poll: 10/10 ok (100%)  avg 0ms
  [ 23.0s / 30s]  Flood:   79990 sent     3472 req/s  |  Poll: 12/12 ok (100%)  avg 0ms
  [ 28.0s / 30s]  Flood:   99843 sent     3560 req/s  |  Poll: 15/15 ok (100%)  avg 0ms

  FINAL RESULTS
  Duration:                  33.1s
  Total flood requests sent: 119934
  Flood errors:              0
  Peak request rate:         3623 req/s

  Legitimate polls sent:     17
  Polls succeeded:           17
  Polls failed:              0
  Poll success rate:         100.0%

  Baseline response avg:     0.4ms
  During-attack avg:         0.3ms
  Response degradation:      -0.1ms
  First poll failure at:     No failures observed during test
```

---

## 4. Before and after register values

This scenario does not write any values. Register state is unchanged throughout:

| Address | Value | Tag | Changed? |
|---|---|---|---|
| Coil 0 | True (CLOSED) | pump1-valve.closed | No |
| Coil 1 | True (CLOSED) | pump2-valve.closed | No |
| HR 30000 | 300 | pump1-flow.Lps | No |
| HR 30001 | 185 | pump2-flow.Lps | No |

Flood peak rate: 3,623 requests/second. All 17 legitimate poll checks succeeded with 0ms degradation.

---

## 5. What this would mean in a real water treatment plant

**Testbed result vs real-world expectation:**

The Mininet simulation showed no poll degradation in V1 at 3,623 req/s (single async client). The V2 threaded flood (300 threads × 150 registers each from 3 hosts) is expected to generate a significantly higher request rate. In simulation this still may not degrade a Python asyncio server running on the same physical CPU — the loopback path and shared kernel bypass real Ethernet hardware limits.

In a real water treatment plant PLC the result would be very different:

- Embedded PLCs (e.g., Modicon M340, Allen-Bradley MicroLogix, Siemens S7-1200) have small TCP connection tables (often 4-16 simultaneous connections). 300 threads × 3 hosts = up to 900 simultaneous connections — far exceeding typical PLC limits.
- Even without connection exhaustion, a flood increases CPU utilisation on the embedded processor. At some threshold the PLC cannot respond within the SCADA polling timeout (commonly 1-3 seconds). scada01 marks plc1 as "Communication Lost" and operators have no visibility into pump valve states or flow telemetry.
- If the PLC also handles protection logic (over-pressure shutoffs, chemical dosing interlocks), CPU saturation can delay those calculations, causing safety system failures during a concurrent fault condition.
- Real packet-capture data from Dragos and Claroty researchers shows that resource-constrained PLCs begin dropping legitimate polls at sustained flood rates above 200-500 req/s over real Ethernet — well below what this attack achieves.

The DoS is particularly effective as a distraction: flood plc1's Modbus port to blind SCADA while simultaneously issuing a valve trip command from a fourth connection. The operator cannot see the state change because the HMI has lost comms. This combined attack (scenario 3 + scenario 2) is the highest-impact vector in this testbed.

---

## 6. Recommended mitigations

1. **Rate-limit Modbus connections per source IP at the network level.** Deploy an OT firewall (Tofino, FortiGate with ICS license, or pfSense with Snort) that limits any single source IP to a maximum of 10 Modbus TCP connections per second to the PLC. This is far above any legitimate SCADA polling rate (1 connection/second or slower) but far below a flood attack. Rate limiting at the network layer does not require PLC firmware changes. The `mitigation3_rate_limit.py` proxy in this testbed implements a per-IP sliding window rate limiter.

2. **Configure the PLC's TCP stack connection limit and backlog.** Where the PLC firmware allows it, set maximum simultaneous Modbus connections to 4-8 (the legitimate minimum needed for SCADA + historian + engineering workstation). Excess connection attempts are dropped at the TCP layer, reducing CPU load on the PLC. This is an often-overlooked configuration item on PLCs that have web UIs with network settings.

3. **Deploy out-of-band SCADA polling path.** For critical plant equipment, configure a secondary Modbus polling connection over a separate network path (serial RS-485 fallback, or a second NIC on plc1). If the primary Modbus TCP path is flooded and polls from scada01 fail, the SCADA automatically switches to the fallback path. This ensures operators retain visibility into pump valve states and flow telemetry during a network-layer attack — which is the primary impact this scenario demonstrates.

---

## 7. Detection opportunities

**Suricata rule — high-rate Modbus connections from a single source:**

```
alert tcp any any -> 10.0.0.2 5502 (
  msg:"MODBUS DoS - High Rate Connection from Single Host";
  flow:to_server;
  threshold:type both, track by_src, count 50, seconds 1;
  sid:9000020; rev:1;
)
```

**Suricata rule — sustained FC03 flood (more than 100 requests in 5 seconds):**

```
alert tcp any any -> 10.0.0.2 5502 (
  msg:"MODBUS FC03 Flood - Possible DoS";
  flow:to_server,established;
  byte_test:1,=,3,7;
  threshold:type both, track by_src, count 100, seconds 5;
  sid:9000021; rev:1;
)
```

**SCADA alert:** Configure scada01 to trigger a Priority 1 alert if the plc1 poll response time exceeds 2x the baseline (i.e., >44ms in this testbed, >10ms in a real LAN deployment). Sustained timeouts should escalate to a "Communication Lost" alarm. This is the primary observable indicator — the attacker's flood appears as a comms outage from the operator's perspective.

**Zeek/Bro script:** The Modbus Zeek package (`bro-pkg install modbus`) logs all Modbus transactions. A query for source IPs with more than 500 Modbus transactions in 60 seconds will identify the flooding host. Deploy on hist01 (10.0.1.2) configured as a SPAN/mirror port off s2 (SWIT-PLANT).

---

## 8. Issues encountered during execution

- V1 used a single async client (`scenario3_dos.py`). V2 replaced with a threaded implementation (`scenario3_dos_flood.py`, 300 threads, 150 registers/request) for much higher throughput and distributed capability across ews01/02/03.
- The 30-second flood in V1 produced no measurable poll degradation in Mininet. This is a known limitation of the simulation environment (loopback, same physical CPU, Python asyncio server with no resource constraints). V2 numbers pending a fresh run.
- The pre-flood baseline measured 22.1-22.8ms in the runner (which used mbpoll via Mininet's cmd() interface) but 0.3-0.5ms in the scenario3 script (which used a direct pymodbus client). The discrepancy is due to mbpoll subprocess overhead. The script baseline of 0.4ms is the more accurate figure for within-namespace Modbus latency.
- The runner baseline loop was simplified from a complex inline Python lambda chain to a direct `time.time()` loop around mbpoll calls for reliability.
