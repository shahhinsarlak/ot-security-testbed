# Mitigations

This directory demonstrates three practical defenses against the attacks in this testbed. Each mitigation shows **both sides**: the attack succeeding without protection, then being blocked or limited with protection applied.

---

## Why these three?

OT security uses a defense-in-depth model. No single control stops everything; layers overlap so that if one fails the next still holds. These three mitigations map to different layers of the stack:

| Layer | Mitigation | Stops |
|-------|-----------|-------|
| Network | IP Allowlisting | Unauthorized hosts reaching the RTU at all |
| Application | Function Code Filter | Write commands from hosts that *can* reach the RTU |
| Transport | Rate Limiting | Floods that exhaust the RTU without issuing writes |

A well-hardened OT network uses all three simultaneously. In practice, these are implemented in dedicated products (Claroty, Dragos, Waterfall unidirectional gateways), but the proxy scripts here give you the same behaviour at the protocol level so you can see exactly what happens packet by packet.

---

## Mitigation 1 — IP Allowlisting

**File:** `mitigation1_ip_allowlist.py` (run via `run_mitigations_demo.py`)

**How it works**

`iptables` rules on h2 (the RTU) enforce that only the known SCADA host (h3, `10.0.1.1`) may open TCP connections to port 5502. Packets from any other source are silently dropped at the kernel before the application ever sees them.

```
h1 (attacker)   10.0.0.1  ──► h2:5502   DROP  (attacker IP not on allowlist)
h3 (SCADA)      10.0.1.1  ──► h2:5502   ACCEPT
```

**iptables rules applied**

```bash
# Accept Modbus connections from the SCADA host only
iptables -A INPUT -p tcp --dport 5502 -s 10.0.1.1 -j ACCEPT

# Drop everything else targeting port 5502
iptables -A INPUT -p tcp --dport 5502 -j DROP
```

**What the attacker sees**

```
Connected: False
```

The TCP connection never completes. From the attacker's perspective it looks like the device is offline.

**Limitations**

IP allowlisting alone is insufficient against a compromised SCADA host or an attacker who has spoofed an allowed IP. It is most effective when combined with 802.1X port authentication on the OT network switch to bind IP addresses to physical ports.

---

## Mitigation 2 — Function Code Filter Proxy

**File:** `mitigation2_fc_filter.py`

**How it works**

A transparent TCP proxy parses every Modbus TCP request at the application layer and checks the Function Code byte before forwarding it upstream. Write function codes are rejected with a Modbus exception response; read function codes are forwarded normally.

```
Client → Proxy (5503) → RTU (5502)
             │
             ├── FC01/02/03/04 (reads)  → FORWARD
             └── FC05/06/0F/10 (writes) → BLOCK (Modbus exception 0x01)
```

The RTU never receives blocked requests. From the attacker's perspective, the write looks like it was rejected by the device itself.

**Run standalone (no Mininet)**

```bash
# Terminal 1 — RTU server
python3 servers/modbus_server.py

# Terminal 2 — FC filter proxy (forwards :5503 → :5502)
python3 mitigations/mitigation2_fc_filter.py \
    --listen-port 5503 \
    --upstream 127.0.0.1:5502

# Terminal 3 — try the command injection attack (should be BLOCKED)
python3 attacks/scenario2_command_injection.py --target 127.0.0.1 --port 5503

# Terminal 3 — try reconnaissance (should be ALLOWED)
python3 attacks/scenario1_recon.py --target 127.0.0.1 --port 5503
```

**Expected proxy output**

```
12:34:01.234  CONNECT    127.0.0.1
12:34:01.238  BLOCKED    127.0.0.1        Write Single Coil (FC05)  12 bytes  → exception 0x01
12:34:01.241  DISCONNECT 127.0.0.1

12:34:05.100  CONNECT    127.0.0.1
12:34:05.104  ALLOWED    127.0.0.1        Read Coils (FC01)         12 bytes  → forwarded
12:34:05.107  ALLOWED    127.0.0.1        Read Holding Registers (FC03)  12 bytes  → forwarded
```

**The Modbus exception frame explained**

When the proxy blocks FC05, it constructs and returns this response:

```
Byte  0-1   Transaction ID   (echoed from request)
Byte  2-3   Protocol ID      0x0000
Byte  4-5   Length           0x0003
Byte  6     Unit ID          (echoed from request)
Byte  7     Error FC         0x85  (0x05 | 0x80 = original FC with error bit set)
Byte  8     Exception Code   0x01  (Illegal Function)
```

The attacking client sees a valid Modbus exception — indistinguishable from the RTU refusing the command.

**Limitations**

Stops opportunistic writes and scenario-2-style attacks. Does not stop reconnaissance (scenario 1 still completes because reads are allowed through by design). Real-world variants add allowlisted source IPs for each function code, so only the engineering workstation's IP may issue any write function codes.

---

## Mitigation 3 — Rate-Limiting Proxy

**File:** `mitigation3_rate_limit.py`

**How it works**

A TCP proxy tracks how many Modbus requests each source IP has made in the last second (sliding window). When a source exceeds the per-IP cap, the proxy closes the connection. The flood client must reconnect from scratch, burning time on TCP handshakes. Legitimate polling clients — using a completely separate IP bucket — are unaffected.

```
h1 (flood, 3,600 req/s)   → proxy → RATE LIMITED (connection closed at >20 req/s)
h3 (poll,  0.5  req/s)    → proxy → FORWARDED    (well below 20 req/s)
```

**Run standalone (no Mininet)**

```bash
# Terminal 1 — RTU server
python3 servers/modbus_server.py

# Terminal 2 — rate-limit proxy (20 req/s per source IP)
python3 mitigations/mitigation3_rate_limit.py \
    --listen-port 5503 \
    --upstream 127.0.0.1:5502 \
    --max-rps 20

# Terminal 3 — flood (throttled to 20 req/s)
python3 attacks/scenario3_dos.py --target 127.0.0.1 --port 5503 --duration 15

# Terminal 4 — legitimate poll (should succeed throughout)
for i in $(seq 1 5); do
    mbpoll -1 -a 1 -t 4 -r 30001 -c 1 127.0.0.1 -p 5503
    sleep 2
done
```

**Expected proxy output (flood scenario)**

```
12:35:00.001  RATE-LIMIT 127.0.0.1        >20 req/s (current ~3580/s)  → connection closed  [total blocked: 1]
12:35:00.002  RATE-LIMIT 127.0.0.1        >20 req/s (current ~3580/s)  → connection closed  [total blocked: 2]
...
12:35:05.000  STATS      allowed=102  blocked=53847  limit=20 req/s per IP
```

**The sliding window algorithm**

```python
def is_allowed(self, ip: str) -> bool:
    now = time.monotonic()
    window = self._windows[ip]          # deque of past request timestamps

    # remove timestamps older than 1 second
    while window and window[0] < now - 1.0:
        window.popleft()

    if len(window) >= self.max_rps:
        return False                    # over the limit

    window.append(now)
    return True                         # within the limit
```

Each source IP has its own window, so a flood from h1 has no effect on h3's bucket.

**Limitations**

Does not prevent reconnaissance or command injection — only volume attacks. An attacker can stay under the rate limit and still issue a single FC05 write. Combine with the function code filter (mitigation 2) for full protection. Real-world RTUs also benefit from a per-connection connection-count limit so the flood cannot exhaust the device's TCP connection table.

---

## Running all three demos end-to-end

```bash
sudo mn -c
sudo python3 mitigations/run_mitigations_demo.py 2>&1 | tee results/mitigations/full_run.txt
```

Results are saved to `results/mitigations/`:
- `demo1_ip_allowlist.txt`
- `demo2_fc_filter.txt`
- `demo3_rate_limit.txt`
- `server.log`
- `demo2_proxy.log`
- `demo3_proxy.log`

---

## Real-world equivalents

| This testbed | Real-world product |
|---|---|
| `iptables` allowlist | Managed OT switch ACLs, Purdue Model zone enforcement |
| FC filter proxy | Claroty Continuous Threat Detection, Dragos Platform, Schneider Electric EcoStruxure inline filtering |
| Rate-limit proxy | QoS shaping on the OT LAN switch, Cisco IOS rate-limit ACL |
| All three combined | Waterfall Security Unidirectional Gateway (hardware data diode + application proxy) |
