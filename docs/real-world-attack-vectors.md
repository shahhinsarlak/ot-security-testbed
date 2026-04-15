# Real-World Attack Vectors

The attacks in this testbed send Modbus TCP packets from one host to another. In the lab that is trivial — both hosts are on the same virtual network. In the real world, the hard part is not sending the packet; it is getting network access to the OT segment in the first place.

This document explains how attackers realistically reach OT devices, whether physical access is required, and where each scenario sits in a real attack chain.

---

## The short answer: physical access is rarely required

Modbus TCP runs over standard TCP/IP. Once an attacker has **network-layer reachability** to the RTU's IP address and port, the attack is entirely remote — no hands on hardware needed. The challenge is getting that network access, which is where the real-world complexity lies.

---

## The attack chain

Real OT attacks almost never start at the RTU. They start somewhere attackers can more easily reach — an internet-facing system, a phishing email, a third-party contractor — and work inward toward the OT network. This is called **lateral movement**.

```
[Internet]
    │
    ▼
[Initial access]          e.g. phishing email, exposed VPN, vendor portal
    │
    ▼
[IT foothold]             compromised workstation, Active Directory account
    │
    ▼
[IT → OT pivot]           flat network, historian with dual NIC, VPN tunnel
    │
    ▼
[OT network access]       attacker now has TCP reachability to RTU port 5502
    │
    ▼
[Modbus attack]           scenario 1 / 2 / 3 — this is what the testbed demonstrates
```

The Modbus commands in this testbed represent the **final step** of a much longer intrusion. The attacker does not need to be anywhere near the physical equipment.

---

## How attackers reach the OT network

### Route 1 — IT/OT network convergence (most common)

Modern OT environments connect to corporate IT networks for data historians, remote monitoring, and business integration. If the firewall between IT and OT is misconfigured or absent, an attacker who compromises any IT machine can pivot directly into the OT network.

**Example path:**
1. Attacker phishes an engineer's email, installs malware on their Windows workstation.
2. The workstation is on the IT LAN, which has a route to the OT VLAN for SCADA data.
3. Attacker uses the workstation as a jump host to scan and reach RTUs on 10.0.0.0/24.
4. From there, all three scenarios are possible over the network.

This is the most common vector in documented ICS incidents. It requires **zero physical access**.

### Route 2 — Remote access / VPN

OT vendors and operators commonly use VPNs or remote desktop solutions for remote maintenance. If these are poorly secured (weak passwords, no MFA, shared credentials), they become a direct tunnel into the OT network from the internet.

**Example path:**
1. Attacker finds an internet-facing VPN portal via Shodan or certificate transparency logs.
2. Credential stuffing or password spray attack succeeds against a vendor account.
3. VPN session places attacker directly on the OT subnet.
4. Modbus attacks proceed remotely.

**Real incident:** The 2021 Oldsmar water treatment plant attack. An attacker used TeamViewer remote access software to connect to a SCADA workstation and changed sodium hydroxide dosing levels. No physical access — entirely remote via a legitimate remote access tool.

### Route 3 — Exposed internet-facing devices

Some Modbus devices are directly internet-accessible, either by misconfiguration or because the operator does not realise the device has a public IP. Shodan (a search engine for internet-connected devices) indexes thousands of exposed Modbus TCP endpoints.

**Example path:**
1. Attacker runs a Shodan query: `port:502 modbus`.
2. Finds an RTU with a public IP.
3. Connects directly from their laptop anywhere in the world.
4. No IT network, no pivot required — straight to the Modbus attack.

This is the simplest possible path and requires **no physical presence whatsoever**. It is also the most preventable: OT devices should never be directly internet-facing.

### Route 4 — Compromised vendor / supply chain

OT vendors — engineering firms, integrators, hardware suppliers — often have trusted remote access to their customers' systems for support. Compromising the vendor gives the attacker inherited trust.

**Example path:**
1. Attacker compromises a SCADA software vendor's update server.
2. Malicious update is pushed to all customer sites running that software.
3. Malware establishes a reverse shell from each customer's engineering workstation.
4. Attacker selects a target and pivots to their OT network.

**Real incident:** The 2020 SolarWinds attack used this exact supply-chain model, though it targeted IT networks. The ICS equivalent is the 2017 Triton/Trisis attack, where malware was deployed to a safety instrumented system via a compromised engineering workstation.

### Route 5 — Physical access to a network port

This is the scenario that requires someone to be on-site. An attacker (or insider) plugs a laptop or Raspberry Pi into an unguarded OT network port — on a switch in a substation cabinet, a panel in a factory, or a network jack in an accessible equipment room.

**Example path:**
1. Attacker gains physical access to a substation (social engineering, stolen ID, unsecured perimeter).
2. Plugs a laptop into an OT switch port.
3. Receives a DHCP address on the OT subnet.
4. Runs all three scenarios locally.

Physical access is the **least likely** vector for a sophisticated attacker because it is noisy, risky, and leaves physical evidence. It is more likely in insider threat scenarios.

---

## Per-scenario breakdown

### Scenario 1 — Reconnaissance (passive read)

| Question | Answer |
|----------|--------|
| Requires physical access? | No |
| Minimum requirement | Network-layer reachability to RTU port |
| Leaves a trace on the RTU? | No — Modbus has no read logging |
| Leaves a trace on the network? | Only in pcap/IDS logs if monitoring is in place |
| Typical attacker stage | Early — attacker is mapping the environment before acting |

Reconnaissance is often performed **months before** any destructive action. The attacker silently enumerates register maps, identifies what coils map to what physical assets, and builds a picture of the process. Because Modbus has no authentication and no read logging, this is completely invisible to the operator.

In the 2015 Ukraine BlackEnergy attack, attackers spent **months** in the IT network conducting reconnaissance before issuing any commands to field devices.

---

### Scenario 2 — Command Injection (breaker trip)

| Question | Answer |
|----------|--------|
| Requires physical access? | No |
| Minimum requirement | Network-layer reachability to RTU port |
| Time to execute once network access is established | Under 1 second |
| Operator visibility | None at protocol level — appears identical to a legitimate SCADA command |
| Recovery | May require manual field dispatch to physically inspect and re-close the breaker |

This is the most impactful scenario. The Modbus write that trips the breaker is a **12-byte TCP payload** — it is physically and logically identical to a command the SCADA system sends during normal operations. The RTU cannot distinguish the attacker's write from the engineer's write.

**Ukraine 2015 — BlackEnergy / Sandworm**
Attackers sent unauthorized breaker open commands over ICS protocols to substations operated by three Ukrainian distribution companies. The result was simultaneous outages affecting approximately 230,000 customers for up to 6 hours. Attackers also overwrote firmware on serial-to-Ethernet converters to prevent remote recovery, forcing operators to drive to each substation manually.

Entry vector: spear-phishing emails to employees, followed by months of lateral movement through the IT network before pivoting to OT.

---

### Scenario 3 — Denial of Service (FC03 flood)

| Question | Answer |
|----------|--------|
| Requires physical access? | No |
| Minimum requirement | Network-layer reachability to RTU port |
| Effect on real embedded RTU | Failure at ~200–500 req/s (Dragos/Claroty field data); this testbed floods at ~3,600 req/s |
| SCADA operator experience | Poll timeouts, stale data, alarms — loss of visibility into the physical process |
| Can be combined with? | Scenario 2 — flood SCADA polling while simultaneously issuing a coil write |

A DoS against an RTU is rarely the end goal on its own. It is most dangerous when used to **blind the operator** while a physical sabotage action is carried out, or to suppress alarms while scenario 2 runs. An operator staring at a screen full of poll timeout alarms is less likely to notice a single breaker state change in the noise.

**Industroyer / Crashoverride (Ukraine 2016)**
More sophisticated than BlackEnergy, Industroyer contained a purpose-built DoS module designed to flood protection relays with traffic, preventing them from responding and causing them to operate in a fail-safe (open) state — effectively achieving a breaker trip through exhaustion rather than a direct write command.

---

## Summary

| Vector | Physical access required | Sophistication | Real-world prevalence |
|--------|------------------------|----------------|----------------------|
| IT/OT network pivot | No | Medium | High |
| Compromised VPN/remote access | No | Low–Medium | High |
| Internet-exposed device | No | Low | Medium |
| Supply chain compromise | No | High | Low–Medium |
| Physical network port | Yes | Low | Low (insider threat) |

The common thread across all vectors: **the Modbus protocol itself provides no defense**. It has no authentication, no encryption, and no logging. Every layer of protection must come from the network and systems around it — which is exactly what the mitigations in this testbed demonstrate.

---

## Further reading

- [CISA ICS Advisory — Ukraine Power Grid Attack (2016)](https://www.cisa.gov/uscert/ics)
- [Dragos Year in Review — ICS/OT Threat Report](https://www.dragos.com/year-in-review/)
- [MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/)
- [Shodan — Industrial Control Systems](https://www.shodan.io/explore/category/industrial-control-systems)
- [NIST SP 800-82 — Guide to OT Security](https://csrc.nist.gov/publications/detail/sp/800-82/rev-3/final)
