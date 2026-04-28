#!/usr/bin/env python3
"""
Goulburn Water Treatment Plant -- OT Security Testbed
======================================================
Mininet topology for 31261 Internetworking Capstone (UTS)
Operator: AquaOps Utilities

Zone layout
-----------
IT Zone (Office Network) -- s1 (SWIT-OFFICE)
  ews01  EWS-01    10.0.0.1  Engineer workstation / primary attacker
  ews02  EWS-02    10.0.0.3  Compromised laptop (Scenario 3 attacker 2)
  ews03  EWS-03    10.0.0.4  Compromised laptop (Scenario 3 attacker 3)

OT Zone (Plant Floor) -- s2 (SWIT-PLANT)
  plc1   PLC-PUMP1 10.0.0.2  Modbus TCP server, port 5502 (primary target)
  plc2   PLC-PUMP2 10.0.0.5  Secondary PLC (idle by default)

Control Room -- routed via r1
  scada01 SCADA-01  10.0.1.1  SCADA polling client
  hist01  HIST-01   10.0.1.2  Data logger / Suricata IDS mirror port

Infrastructure
  s1  SWIT-OFFICE   OVS switch, IT zone
  s2  SWIT-PLANT    OVS switch, OT zone
  r1  ROUT-BOUNDARY 10.0.0.254 (OT/IT side) / 10.0.1.254 (control room)
  c0  SDN-CTRL      OVSController

Physical links
  ews01, ews02, ews03, scada01, hist01 --> s1
  plc1, plc2 --> s2
  s1 <--> s2  (peer trunk, same-subnet L2 for 10.0.0.x)
  r1-eth0 (10.0.0.254) --> s2
  r1-eth1 (10.0.1.254) --> s1  (control room gateway)
"""

import os
import sys
import time

from mininet.net import Mininet
from mininet.node import OVSSwitch, Host
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from mininet.cli import CLI


# ---------------------------------------------------------------------------
# Root check
# ---------------------------------------------------------------------------
def check_root():
    if os.geteuid() != 0:
        print("[ERROR] This script must be run as root.")
        print("        Run: sudo python3 topology/mininet_topo.py")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Topology builder
# ---------------------------------------------------------------------------
class GoulburnTopo:
    """Builds the Goulburn WTP testbed topology."""

    def __init__(self):
        self.net = Mininet(switch=OVSSwitch, link=TCLink, controller=None)

    def build(self):
        net = self.net
        info("*** Adding hosts\n")

        # IT Zone -- Engineer workstations / attackers
        ews01 = net.addHost("ews01", ip=None)   # EWS-01, 10.0.0.1
        ews02 = net.addHost("ews02", ip=None)   # EWS-02, 10.0.0.3
        ews03 = net.addHost("ews03", ip=None)   # EWS-03, 10.0.0.4

        # OT Zone -- PLCs
        plc1  = net.addHost("plc1",  ip=None)   # PLC-PUMP1, 10.0.0.2
        plc2  = net.addHost("plc2",  ip=None)   # PLC-PUMP2, 10.0.0.5

        # Control Room -- SCADA and historian (10.0.1.x, fixed after build)
        scada01 = net.addHost("scada01", ip=None)
        hist01  = net.addHost("hist01",  ip=None)

        # Router
        r1 = net.addHost("r1", ip=None)

        info("*** Adding switches\n")
        s1 = net.addSwitch("s1", failMode="standalone")  # SWIT-OFFICE
        s2 = net.addSwitch("s2", failMode="standalone")  # SWIT-PLANT

        info("*** Adding links\n")
        # IT Zone hosts --> s1
        net.addLink(ews01,   s1)
        net.addLink(ews02,   s1)
        net.addLink(ews03,   s1)
        # Control room hosts also attach to s1 (r1-eth1 is on s1)
        net.addLink(scada01, s1)
        net.addLink(hist01,  s1)

        # OT Zone hosts --> s2
        net.addLink(plc1, s2)
        net.addLink(plc2, s2)

        # Router: eth0 faces s2 (10.0.0.254), eth1 faces s1 (10.0.1.254)
        net.addLink(r1, s2)   # r1-eth0
        net.addLink(r1, s1)   # r1-eth1

        # Peer trunk between s1 and s2 for same-subnet 10.0.0.x L2 traffic
        net.addLink(s1, s2)

        return net, ews01, ews02, ews03, plc1, plc2, scada01, hist01, r1, s1, s2


# ---------------------------------------------------------------------------
# OVS configuration (os.system as required)
# ---------------------------------------------------------------------------
def configure_ovs():
    """Apply fail-mode standalone and normal forwarding on both switches."""
    info("*** Configuring OVS switches\n")
    os.system("ovs-vsctl set-fail-mode s1 standalone")
    os.system("ovs-vsctl set-fail-mode s2 standalone")
    os.system("ovs-ofctl add-flow s1 action=normal")
    os.system("ovs-ofctl add-flow s2 action=normal")
    info("    OVS: fail-mode=standalone + action=normal applied on s1, s2\n")


# ---------------------------------------------------------------------------
# Router configuration
# ---------------------------------------------------------------------------
def configure_router(r1):
    """Assign IPs on both router interfaces and enable IP forwarding."""
    info("*** Configuring router r1 (ROUT-BOUNDARY)\n")
    # r1-eth0 faces s2 (OT/IT 10.0.0.x), r1-eth1 faces s1 (control room 10.0.1.x)
    r1.cmd("ip addr flush dev r1-eth0")
    r1.cmd("ip addr flush dev r1-eth1")
    r1.cmd("ip addr add 10.0.0.254/24 dev r1-eth0")
    r1.cmd("ip addr add 10.0.1.254/24 dev r1-eth1")
    r1.cmd("ip link set r1-eth0 up")
    r1.cmd("ip link set r1-eth1 up")
    r1.cmd("sysctl -w net.ipv4.ip_forward=1")
    info("    r1-eth0: 10.0.0.254/24 (plant/office side)\n")
    info("    r1-eth1: 10.0.1.254/24 (control room side)\n")
    info("    ip_forward: ON\n")


# ---------------------------------------------------------------------------
# Host address and route configuration
# ---------------------------------------------------------------------------
def configure_hosts(ews01, ews02, ews03, plc1, plc2, scada01, hist01):
    """Set interface addresses, masks, and default gateways on all hosts."""
    info("*** Configuring host addresses and routes\n")

    # IT Zone and OT Zone hosts share 10.0.0.0/24
    it_ot_hosts = [
        (ews01,  "ews01-eth0",   "10.0.0.1"),
        (ews02,  "ews02-eth0",   "10.0.0.3"),
        (ews03,  "ews03-eth0",   "10.0.0.4"),
        (plc1,   "plc1-eth0",    "10.0.0.2"),
        (plc2,   "plc2-eth0",    "10.0.0.5"),
    ]
    for host, iface, addr in it_ot_hosts:
        host.cmd(f"ip addr flush dev {iface}")
        host.cmd(f"ip addr add {addr}/24 dev {iface}")
        host.cmd(f"ip link set {iface} up")
        host.cmd("ip route add default via 10.0.0.254")

    # Control room hosts use 10.0.1.0/24 (fixed after net.build())
    ctrl_hosts = [
        (scada01, "scada01-eth0", "10.0.1.1"),
        (hist01,  "hist01-eth0",  "10.0.1.2"),
    ]
    for host, iface, addr in ctrl_hosts:
        host.cmd(f"ip addr flush dev {iface}")
        host.cmd(f"ip addr add {addr}/24 dev {iface}")
        host.cmd(f"ip link set {iface} up")
        host.cmd("ip route add default via 10.0.1.254")

    info("    All host addresses and default routes configured\n")


# ---------------------------------------------------------------------------
# Connectivity verification
# ---------------------------------------------------------------------------
def verify_connectivity(net):
    """Ping key paths and report PASS/FAIL. Attempt OVS recovery if needed."""
    import subprocess
    info("\n*** Verifying connectivity\n")

    ews01   = net.get("ews01")
    plc1    = net.get("plc1")
    scada01 = net.get("scada01")

    checks = [
        ("ews01",   ews01,   "10.0.0.2", "ews01 -> plc1"),
        ("scada01", scada01, "10.0.0.2", "scada01 -> plc1"),
    ]

    results = {}
    for label, src, dst, desc in checks:
        out = src.cmd(f"ping -c 3 -W 2 {dst}")
        ok = "100% packet loss" not in out
        results[desc] = "PASS" if ok else "FAIL"
        info(f"    {desc}: {results[desc]}\n")

    if "FAIL" in results.values():
        info("*** WARNING: connectivity check failed -- retrying OVS flows\n")
        for sw in ["s1", "s2"]:
            subprocess.run(["ovs-ofctl", "del-flows", sw], check=False)
            subprocess.run(["ovs-ofctl", "add-flow", sw, "action=normal"], check=False)
        time.sleep(1)
        out = ews01.cmd("ping -c 3 -W 2 10.0.0.2")
        ok = "100% packet loss" not in out
        results["ews01 -> plc1 (retry)"] = "PASS" if ok else "FAIL"
        info(f"    ews01 -> plc1 retry: {results['ews01 -> plc1 (retry)']}\n")

    return results


# ---------------------------------------------------------------------------
# Startup banner
# ---------------------------------------------------------------------------
def print_banner():
    w = 64
    sep = "=" * w
    thin = "-" * w
    print(sep)
    print("  Goulburn Water Treatment Plant -- OT Security Testbed")
    print("  AquaOps Utilities | 31261 Internetworking Capstone (UTS)")
    print(sep)
    print(f"  {'Zone':<14} {'Host':<9} {'Name':<13} {'IP':<13} Role")
    print(thin)
    rows = [
        ("IT Zone",       "ews01",   "EWS-01",       "10.0.0.1",  "Engineer workstation / attacker"),
        ("IT Zone",       "ews02",   "EWS-02",       "10.0.0.3",  "Compromised laptop (Scenario 3)"),
        ("IT Zone",       "ews03",   "EWS-03",       "10.0.0.4",  "Compromised laptop (Scenario 3)"),
        ("OT Zone",       "plc1",    "PLC-PUMP1",    "10.0.0.2",  "Modbus TCP server port 5502"),
        ("OT Zone",       "plc2",    "PLC-PUMP2",    "10.0.0.5",  "Secondary PLC (idle)"),
        ("Control Room",  "scada01", "SCADA-01",     "10.0.1.1",  "SCADA polling client"),
        ("Control Room",  "hist01",  "HIST-01",      "10.0.1.2",  "Data logger / Suricata IDS"),
    ]
    for zone, host, name, ip, role in rows:
        print(f"  {zone:<14} {host:<9} {name:<13} {ip:<13} {role}")
    print(thin)
    print("  Router r1 (ROUT-BOUNDARY): 10.0.0.254 / 10.0.1.254")
    print("  Switch s1 (SWIT-OFFICE):   IT Zone")
    print("  Switch s2 (SWIT-PLANT):    OT Zone")
    print(sep)
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    srv = os.path.join(base, "servers", "modbus_server.py")
    print(f"  To start Modbus server:  plc1 python3 {srv} &")
    print(sep)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def run():
    check_root()
    setLogLevel("info")

    topo = GoulburnTopo()
    net, ews01, ews02, ews03, plc1, plc2, scada01, hist01, r1, s1, s2 = topo.build()

    info("*** Starting network\n")
    net.start()

    # OVS must be configured after net.start() so bridges exist
    configure_ovs()
    configure_router(r1)
    configure_hosts(ews01, ews02, ews03, plc1, plc2, scada01, hist01)

    time.sleep(1)
    verify_connectivity(net)

    print_banner()

    info("\n*** Topology ready. Starting CLI.\n")
    CLI(net)

    info("*** Stopping network\n")
    net.stop()


if __name__ == "__main__":
    run()
