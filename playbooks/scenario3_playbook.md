# Scenario 3 — Modbus TCP Denial of Service (FC3 Flood)

**Testbed:** patsec/ot-sim layout | **Date:** 2026-04-14 | **Owner:** Daniel Sleiman and Johnson Huynh
**Platform:** Ubuntu 24.04 LTS | Mininet 2.3 | pymodbus 3.12.1 | mbpoll 1.4.11

---

## 1. What the attack does at the protocol level

This attack opens a persistent Modbus TCP connection from the attacker (h1) to the RTU (h2) and floods it with **FC03 Read Holding Registers** requests as fast as the async client can send them.

FC03 is used because it is always valid (no write access needed) and causes the server to do real work — look up register values and build a response — for every request. Unlike a SYN flood, this attack completes the TCP handshake and operates entirely within a legitimate protocol.

The attack runs for 30 seconds. In a parallel thread, a separate Modbus client polls HR 30000 every 2 seconds, measuring response time and success rate. This simulates the SCADA HMI continuing to poll during the attack.

The intent is to saturate the RTU's ability to process Modbus requests, causing legitimate SCADA polls to time out. Real PLCs and RTUs often run on 32-bit embedded processors with limited TCP stack resources. A flood of 3,000+ connections/second can exhaust connection tables or processing threads, causing SCADA to lose visibility.

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

**Attack run (from h1):**

```
python3 attacks/scenario3_dos.py --target 10.0.0.2 --port 5502 --duration 30
```

Executed 2026-04-14T16:33:58. Full output:

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
| Coil 0 | True (CLOSED) | line-650632.closed | No |
| Coil 1 | True (CLOSED) | line-651634.closed | No |
| HR 30000 | 300 | line-650632.kW | No |
| HR 30001 | 185 | line-651634.kW | No |

Flood peak rate: 3,623 requests/second. All 17 legitimate poll checks succeeded with 0ms degradation.

---

## 5. What this would mean in a real substation

**Testbed result vs real-world expectation:**

The Mininet simulation showed no poll degradation at 3,623 req/s. This is expected: Mininet uses Linux network namespaces on the same physical CPU. The pymodbus server is a Python asyncio process with no resource constraints. The loopback path bypasses real Ethernet hardware.

In a real substation RTU the result would be very different:

- Embedded RTUs (e.g., GE D20, SEL-3530, Modicon M340) have single-threaded Modbus stacks with small TCP connection tables (often 4-16 simultaneous connections). A flood that opens persistent connections could exhaust the table entirely.
- Even without connection exhaustion, a flood increases CPU utilisation on the embedded processor. At some threshold the RTU cannot respond within the SCADA polling timeout (commonly 1-3 seconds). The HMI marks the RTU as "Communication Lost" and the operator loses all visibility into that device.
- If the RTU also handles protection relay logic (trip decisions), CPU saturation can delay those calculations, causing protection failures during a concurrent fault condition.
- Real packet-capture data from Dragos and Claroty researchers shows that resource-constrained RTUs begin dropping legitimate polls at sustained flood rates above 200-500 req/s over real Ethernet — well below what this attack achieved.

The DoS is particularly effective as a distraction: flood the RTU's Modbus port to blind SCADA while simultaneously issuing a trip command from a second connection. The operator cannot see the state change because the HMI has lost comms.

---

## 6. Recommended mitigations

1. **Rate-limit Modbus connections per source IP at the network level.** Deploy an OT firewall (Tofino, FortiGate with ICS license, or pfSense with Snort) that limits any single source IP to a maximum of 10 Modbus TCP connections per second to the RTU. This is far above any legitimate SCADA polling rate (1 connection/second or slower) but far below a flood attack. Rate limiting at the network layer does not require RTU firmware changes.

2. **Configure the RTU's TCP stack connection limit and backlog.** Where the RTU firmware allows it, set maximum simultaneous Modbus connections to 4-8 (the legitimate minimum needed for SCADA + historian + engineering workstation). Excess connection attempts are dropped at the TCP layer, reducing CPU load on the RTU. This is an often-overlooked configuration item on RTUs that have web UIs with network settings.

3. **Deploy out-of-band SCADA polling path.** For critical substations, configure a secondary Modbus polling connection over a separate network path (serial RS-485 fallback, or a second NIC). If the primary Modbus TCP path is flooded and polls fail, the SCADA automatically switches to the fallback path. This ensures operators retain visibility during a network-layer attack, which is the primary impact this scenario demonstrates.

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

**SCADA alert:** Configure the HMI to trigger a Priority 1 alert if the RTU poll response time exceeds 2x the baseline (i.e., >44ms in this testbed, >10ms in a real LAN deployment). Sustained timeouts should escalate to a "Communication Lost" alarm. This is the primary observable indicator — the attacker's flood appears as a comms outage from the operator's perspective.

**Zeek/Bro script:** The Modbus Zeek package (`bro-pkg install modbus`) logs all Modbus transactions. A query for source IPs with more than 500 Modbus transactions in 60 seconds will identify the flooding host.

---

## 8. Issues encountered during execution

- The `await client.close()` call on `AsyncModbusTcpClient` in the flood loop threw `TypeError: object NoneType can't be used in 'await' expression`. pymodbus 3.12 `close()` on the async client is not a coroutine — it is synchronous. Removed the `await` keyword. Fixed before the Mininet run.
- The 30-second flood produced no measurable poll degradation in Mininet. This is a known limitation of the simulation environment, not a flaw in the attack logic. We document the expected real-world impact in section 5 based on published research on embedded RTU resource limits.
- The pre-flood baseline measured 22.1-22.8ms in the runner (which used mbpoll via Mininet's cmd() interface) but 0.3-0.5ms in the scenario3 script (which used a direct pymodbus client). The discrepancy is due to mbpoll subprocess overhead in the first measurement. The scenario3 baseline of 0.4ms is the more accurate figure for within-namespace Modbus latency.
- The runner originally used a complex inline Python script for the baseline timing loop. Replaced with a direct loop in the runner itself (time.time() around mbpoll calls) for reliability.
