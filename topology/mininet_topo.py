#!/usr/bin/env python3
"""
OT Security Testbed — Mininet Topology
=======================================
Topology:
  h1  10.0.0.1   Attacker / engineering workstation
  h2  10.0.0.2   RTU/PLC — Modbus server on port 5502
  h3  10.0.0.3   SCADA/HMI — legitimate polling client
  h4  10.0.0.4   Historian — passive listener
  h5  10.0.0.5   Second RTU (powered off by default)

  s1  OVS — IT-side (h3, h4)
  s2  OVS — OT-side (h1, h2, h5)
  r1  router host bridging s1 and s2
      s1-side: 10.0.1.254
      s2-side: 10.0.0.254

Links: h3--s1, h4--s1, s1--r1, r1--s2, h1--s2, h2--s2, h5--s2
"""

import subprocess
import sys
import time

from mininet.net import Mininet
from mininet.node import OVSSwitch, Host
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from mininet.cli import CLI


class OTTestbedTopo:
    """Builds the OT testbed topology manually for full control."""

    def __init__(self):
        self.net = Mininet(switch=OVSSwitch, link=TCLink, controller=None)

    def build(self):
        net = self.net
        info("*** Adding hosts\n")

        # OT-side hosts
        h1 = net.addHost("h1", ip="10.0.0.1/24")   # Attacker
        h2 = net.addHost("h2", ip="10.0.0.2/24")   # RTU/PLC
        h5 = net.addHost("h5", ip="10.0.0.5/24")   # Second RTU (off)

        # IT-side hosts
        h3 = net.addHost("h3", ip="10.0.1.1/24")   # SCADA/HMI
        h4 = net.addHost("h4", ip="10.0.1.2/24")   # Historian

        info("*** Adding switches\n")
        s1 = net.addSwitch("s1", failMode="standalone")  # IT-side
        s2 = net.addSwitch("s2", failMode="standalone")  # OT-side

        info("*** Adding router\n")
        # r1 is a regular host with two interfaces; we enable ip_forward
        r1 = net.addHost("r1", ip=None)

        info("*** Adding links\n")
        # IT-side
        net.addLink(h3, s1)
        net.addLink(h4, s1)

        # Router to s1 (IT-side)
        net.addLink(r1, s1)

        # Router to s2 (OT-side)
        net.addLink(r1, s2)

        # OT-side
        net.addLink(h1, s2)
        net.addLink(h2, s2)
        net.addLink(h5, s2)

        return net, h1, h2, h3, h4, h5, r1, s1, s2


def configure_ovs(s1, s2):
    """Apply fail-mode standalone and normal forwarding flows."""
    info("*** Configuring OVS switches\n")
    for switch_name in ["s1", "s2"]:
        subprocess.run(
            ["ovs-vsctl", "set-fail-mode", switch_name, "standalone"],
            check=False,
        )
        subprocess.run(
            ["ovs-ofctl", "add-flow", switch_name, "action=normal"],
            check=False,
        )
    info("    OVS fail-mode=standalone and action=normal set on s1, s2\n")


def configure_router(r1):
    """Assign IPs on both router interfaces and enable IP forwarding."""
    info("*** Configuring router r1\n")
    # r1-eth0 faces s1 (IT-side), r1-eth1 faces s2 (OT-side)
    r1.cmd("ip addr flush dev r1-eth0")
    r1.cmd("ip addr flush dev r1-eth1")
    r1.cmd("ip addr add 10.0.1.254/24 dev r1-eth0")
    r1.cmd("ip addr add 10.0.0.254/24 dev r1-eth1")
    r1.cmd("ip link set r1-eth0 up")
    r1.cmd("ip link set r1-eth1 up")
    r1.cmd("sysctl -w net.ipv4.ip_forward=1")
    info("    r1: 10.0.1.254 (IT-side), 10.0.0.254 (OT-side), forwarding ON\n")


def configure_hosts(h1, h2, h3, h4, h5, r1):
    """Set default gateways on all hosts."""
    info("*** Configuring host routes\n")
    # OT-side hosts reach IT via r1's OT-side IP
    for host in [h1, h2, h5]:
        host.cmd("ip route add default via 10.0.0.254")
    # IT-side hosts reach OT via r1's IT-side IP
    for host in [h3, h4]:
        host.cmd("ip route add default via 10.0.1.254")
    info("    Default routes configured on all hosts\n")


def verify_connectivity(net):
    """Ping h1->h2 and h3->h2. Print PASS/FAIL."""
    info("\n*** Verifying connectivity\n")
    h1 = net.get("h1")
    h2 = net.get("h2")
    h3 = net.get("h3")

    results = {}

    out = h1.cmd("ping -c 3 -W 2 10.0.0.2")
    loss = "100% packet loss" in out
    results["h1 -> h2"] = "FAIL" if loss else "PASS"
    info(f"    h1 -> h2: {results['h1 -> h2']}\n")

    out = h3.cmd("ping -c 3 -W 2 10.0.0.2")
    loss = "100% packet loss" in out
    results["h3 -> h2"] = "FAIL" if loss else "PASS"
    info(f"    h3 -> h2: {results['h3 -> h2']}\n")

    if "FAIL" in results.values():
        info("*** WARNING: connectivity check failed — check OVS config\n")
        # Attempt OVS recovery
        info("*** Attempting OVS recovery (delete/re-add flows)\n")
        for sw in ["s1", "s2"]:
            subprocess.run(["ovs-ofctl", "del-flows", sw], check=False)
            subprocess.run(
                ["ovs-ofctl", "add-flow", sw, "action=normal"], check=False
            )
        time.sleep(1)
        out = h1.cmd("ping -c 3 -W 2 10.0.0.2")
        results["h1 -> h2 (retry)"] = (
            "FAIL" if "100% packet loss" in out else "PASS"
        )
        info(f"    h1 -> h2 retry: {results['h1 -> h2 (retry)']}\n")

    return results


def run():
    setLogLevel("info")

    topo = OTTestbedTopo()
    net, h1, h2, h3, h4, h5, r1, s1, s2 = topo.build()

    info("*** Starting network\n")
    net.start()

    # Must happen after net.start() so OVS bridges exist
    configure_ovs(s1, s2)
    configure_router(r1)
    configure_hosts(h1, h2, h3, h4, h5, r1)

    # Give OVS a moment to settle
    time.sleep(1)

    verify_connectivity(net)

    info("\n*** Topology ready. Starting CLI.\n")
    info("    h1=10.0.0.1 (attacker)  h2=10.0.0.2 (RTU/Modbus)\n")
    info("    h3=10.0.1.1 (SCADA/HMI) h4=10.0.1.2 (Historian)\n")
    info("    r1: 10.0.1.254 (IT) / 10.0.0.254 (OT)\n")
    import os as _os
    _base = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
    info(f"    Launch Modbus server: h2 python3 {_os.path.join(_base, 'servers', 'modbus_server.py')} &\n")

    CLI(net)

    info("*** Stopping network\n")
    net.stop()


if __name__ == "__main__":
    run()
