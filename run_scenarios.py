#!/usr/bin/env python3
"""
Goulburn Water Treatment Plant -- Automated Scenario Runner
===========================================================
AquaOps Utilities | 31261 Internetworking Capstone (UTS)

Builds the Mininet topology and executes all three attack scenarios
non-interactively, saving results to results/.

Run as root:
    sudo mn -c
    sudo python3 run_scenarios.py
"""

import os
import subprocess
import sys
import time
from datetime import datetime

from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel, info

# Base dir -- this script lives at the project root
BASE    = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.join(BASE, "results")
SERVERS = os.path.join(BASE, "servers")
ATTACKS = os.path.join(BASE, "attacks")


# ---------------------------------------------------------------------------
# Root check
# ---------------------------------------------------------------------------
def check_root():
    if os.geteuid() != 0:
        print("[ERROR] Must run as root. Use: sudo python3 run_scenarios.py")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Network build
# ---------------------------------------------------------------------------
def build_network():
    net = Mininet(switch=OVSSwitch, link=TCLink, controller=None)

    # IT Zone hosts (Office Network)
    ews01 = net.addHost("ews01", ip=None)   # EWS-01 10.0.0.1 attacker
    ews02 = net.addHost("ews02", ip=None)   # EWS-02 10.0.0.3 Scenario 3 attacker 2
    ews03 = net.addHost("ews03", ip=None)   # EWS-03 10.0.0.4 Scenario 3 attacker 3

    # OT Zone hosts (Plant Floor)
    plc1  = net.addHost("plc1",  ip=None)   # PLC-PUMP1 10.0.0.2 Modbus server
    plc2  = net.addHost("plc2",  ip=None)   # PLC-PUMP2 10.0.0.5 idle

    # Control Room (10.0.1.x, fixed after build)
    scada01 = net.addHost("scada01", ip=None)  # SCADA-01 10.0.1.1
    hist01  = net.addHost("hist01",  ip=None)  # HIST-01  10.0.1.2

    # Router
    r1 = net.addHost("r1", ip=None)

    # Switches
    s1 = net.addSwitch("s1", failMode="standalone")   # SWIT-OFFICE
    s2 = net.addSwitch("s2", failMode="standalone")   # SWIT-PLANT

    # Links -- IT Zone and control room hosts to s1
    net.addLink(ews01,   s1)
    net.addLink(ews02,   s1)
    net.addLink(ews03,   s1)
    net.addLink(scada01, s1)
    net.addLink(hist01,  s1)

    # Links -- OT Zone hosts to s2
    net.addLink(plc1, s2)
    net.addLink(plc2, s2)

    # Router: eth0 -> s2 (10.0.0.254), eth1 -> s1 (10.0.1.254)
    net.addLink(r1, s2)
    net.addLink(r1, s1)

    # Peer trunk between s1 and s2 for same-subnet 10.0.0.x L2 traffic
    net.addLink(s1, s2)

    return net


# ---------------------------------------------------------------------------
# Network configuration
# ---------------------------------------------------------------------------
def configure_ovs():
    """Apply fail-mode standalone and normal forwarding via os.system."""
    os.system("ovs-vsctl set-fail-mode s1 standalone")
    os.system("ovs-vsctl set-fail-mode s2 standalone")
    os.system("ovs-ofctl add-flow s1 action=normal")
    os.system("ovs-ofctl add-flow s2 action=normal")
    info("OVS: fail-mode=standalone + action=normal applied on s1, s2\n")


def configure_router(r1):
    r1.cmd("ip addr flush dev r1-eth0")
    r1.cmd("ip addr flush dev r1-eth1")
    r1.cmd("ip addr add 10.0.0.254/24 dev r1-eth0")
    r1.cmd("ip addr add 10.0.1.254/24 dev r1-eth1")
    r1.cmd("ip link set r1-eth0 up")
    r1.cmd("ip link set r1-eth1 up")
    r1.cmd("sysctl -w net.ipv4.ip_forward=1")


def configure_hosts(net):
    it_ot = [
        ("ews01",   "ews01-eth0",   "10.0.0.1"),
        ("ews02",   "ews02-eth0",   "10.0.0.3"),
        ("ews03",   "ews03-eth0",   "10.0.0.4"),
        ("plc1",    "plc1-eth0",    "10.0.0.2"),
        ("plc2",    "plc2-eth0",    "10.0.0.5"),
    ]
    for name, iface, addr in it_ot:
        h = net.get(name)
        h.cmd(f"ip addr flush dev {iface}")
        h.cmd(f"ip addr add {addr}/24 dev {iface}")
        h.cmd(f"ip link set {iface} up")
        h.cmd("ip route add default via 10.0.0.254")

    ctrl = [
        ("scada01", "scada01-eth0", "10.0.1.1"),
        ("hist01",  "hist01-eth0",  "10.0.1.2"),
    ]
    for name, iface, addr in ctrl:
        h = net.get(name)
        h.cmd(f"ip addr flush dev {iface}")
        h.cmd(f"ip addr add {addr}/24 dev {iface}")
        h.cmd(f"ip link set {iface} up")
        h.cmd("ip route add default via 10.0.1.254")


def verify_connectivity(net):
    ews01   = net.get("ews01")
    scada01 = net.get("scada01")

    out1 = ews01.cmd("ping -c 3 -W 2 10.0.0.2")
    out3 = scada01.cmd("ping -c 3 -W 2 10.0.0.2")

    ok1 = "100% packet loss" not in out1
    ok3 = "100% packet loss" not in out3

    info(f"ews01->plc1: {'PASS' if ok1 else 'FAIL'}\n")
    info(f"scada01->plc1: {'PASS' if ok3 else 'FAIL'}\n")

    if not ok1 or not ok3:
        info("Retrying OVS flow config...\n")
        for sw in ["s1", "s2"]:
            subprocess.run(["ovs-ofctl", "del-flows", sw], check=False)
            subprocess.run(["ovs-ofctl", "add-flow", sw, "action=normal"], check=False)
        time.sleep(2)
        out1 = ews01.cmd("ping -c 3 -W 2 10.0.0.2")
        ok1  = "100% packet loss" not in out1
        info(f"ews01->plc1 retry: {'PASS' if ok1 else 'FAIL'}\n")

    return ok1


def save_file(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------
def run():
    check_root()
    setLogLevel("info")

    info("=== Goulburn WTP -- Automated Scenario Runner ===\n")
    info(f"Started: {datetime.now().strftime('%Y-%m-%dT%H:%M:%S')}\n")

    net = build_network()
    info("Starting network...\n")
    net.start()
    time.sleep(1)

    configure_ovs()
    configure_router(net.get("r1"))
    configure_hosts(net)
    time.sleep(1)

    ok = verify_connectivity(net)
    if not ok:
        info("WARNING: connectivity check failed. Continuing anyway.\n")

    ews01 = net.get("ews01")
    plc1  = net.get("plc1")

    # -----------------------------------------------------------------------
    # Start Modbus server on plc1
    # -----------------------------------------------------------------------
    server_script = os.path.join(SERVERS, "modbus_server.py")
    server_log    = os.path.join(RESULTS, "server_startup.txt")
    info("\n=== Starting Modbus server on plc1 (PLC-PUMP1) ===\n")

    import subprocess as sp
    server_proc = plc1.popen(
        ["python3", server_script],
        stdout=open(server_log, "w"),
        stderr=sp.STDOUT,
    )
    info(f"Server PID {server_proc.pid} started on plc1. Waiting 4s to bind...\n")
    time.sleep(4)

    # Confirm with mbpoll
    info("Confirming server with mbpoll (coils 0-1)...\n")
    mbpoll_coils = ews01.cmd(
        "mbpoll -1 -a 1 -t 0 -r 1 -c 2 10.0.0.2 -p 5502 2>&1"
    )
    info(f"mbpoll coils:\n{mbpoll_coils}\n")

    mbpoll_hr = ews01.cmd(
        "mbpoll -1 -a 1 -t 4 -r 30001 -c 2 10.0.0.2 -p 5502 2>&1"
    )
    info(f"mbpoll holding registers:\n{mbpoll_hr}\n")

    with open(server_log, "a") as f:
        f.write("\n--- mbpoll coil confirmation ---\n")
        f.write(mbpoll_coils)
        f.write("\n--- mbpoll HR confirmation ---\n")
        f.write(mbpoll_hr)

    # -----------------------------------------------------------------------
    # Scenario 1 -- Reconnaissance
    # -----------------------------------------------------------------------
    info("\n=== Scenario 1: Reconnaissance ===\n")
    s1_script   = os.path.join(ATTACKS, "scenario1_recon.py")
    s1_out_path = os.path.join(RESULTS, "scenario1_output.txt")

    s1_output = ews01.cmd(
        f"python3 {s1_script} --target 10.0.0.2 --port 5502 2>&1"
    )
    save_file(s1_out_path, s1_output)
    info(f"Scenario 1 output saved to {s1_out_path}\n")
    print(s1_output)

    # -----------------------------------------------------------------------
    # Scenario 2 -- Command Injection
    # -----------------------------------------------------------------------
    info("\n=== Scenario 2: Command Injection ===\n")

    # Baseline read
    s2_baseline = ews01.cmd(
        "mbpoll -1 -a 1 -t 4 -r 30001 -c 2 10.0.0.2 -p 5502 2>&1"
    )
    save_file(os.path.join(RESULTS, "scenario2_baseline.txt"), s2_baseline)

    s2_script   = os.path.join(ATTACKS, "scenario2_command_injection.py")
    s2_out_path = os.path.join(RESULTS, "scenario2_output.txt")
    s2_output   = ews01.cmd(
        f"python3 {s2_script} --target 10.0.0.2 --port 5502 2>&1"
    )
    save_file(s2_out_path, s2_output)
    info(f"Scenario 2 output saved to {s2_out_path}\n")
    print(s2_output)

    # Post-attack read
    s2_post = ews01.cmd("mbpoll -1 -a 1 -t 4 -r 30001 -c 2 10.0.0.2 -p 5502 2>&1")
    save_file(os.path.join(RESULTS, "scenario2_post.txt"), s2_post)

    # Reset coil 0 back to True (CLOSED) after attack
    info("Resetting pump1-valve (coil 0) back to CLOSED...\n")
    reset_out = ews01.cmd(
        "python3 -c \""
        "from pymodbus.client import ModbusTcpClient; "
        "c=ModbusTcpClient('10.0.0.2',port=5502); "
        "c.connect(); "
        "r=c.write_coil(0,True,device_id=1); "
        "print('pump1-valve reset to CLOSED, result:', r); "
        "c.close()"
        "\" 2>&1"
    )
    info(f"Reset result: {reset_out}\n")

    # -----------------------------------------------------------------------
    # Scenario 3 -- DoS Flood (ews01 primary, ews02/ews03 join simultaneously)
    # -----------------------------------------------------------------------
    info("\n=== Scenario 3: DoS Flood ===\n")

    # 5-poll timing baseline before flood
    s3_baseline_lines = []
    for i in range(5):
        t0 = time.time()
        r  = ews01.cmd("mbpoll -1 -a 1 -t 4 -r 30001 -c 1 10.0.0.2 -p 5502 2>&1")
        ms = (time.time() - t0) * 1000
        line = f"Poll {i+1}: {ms:.1f}ms"
        s3_baseline_lines.append(line)
        info(f"  {line}\n")
        if i < 4:
            time.sleep(2)

    baseline_ms_vals = []
    for ln in s3_baseline_lines:
        try:
            baseline_ms_vals.append(float(ln.split(":")[1].strip().replace("ms", "")))
        except Exception:
            pass
    if baseline_ms_vals:
        avg_b = sum(baseline_ms_vals) / len(baseline_ms_vals)
        s3_baseline_lines.append(f"Avg baseline: {avg_b:.1f}ms")

    save_file(
        os.path.join(RESULTS, "scenario3_baseline.txt"),
        "\n".join(s3_baseline_lines) + "\n",
    )

    s3_script   = os.path.join(ATTACKS, "scenario3_dos_flood.py")
    s3_out_path = os.path.join(RESULTS, "scenario3_output.txt")
    info("Running DoS flood for 30 seconds from ews01, ews02, ews03...\n")

    ews02 = net.get("ews02")
    ews03 = net.get("ews03")

    # Launch floods from all three attacker hosts simultaneously
    flood_cmd = f"python3 {s3_script} --target 10.0.0.2 --port 5502 --threads 100 --duration 30 2>&1"

    p2 = ews02.popen(flood_cmd, shell=True, stdout=sp.PIPE, stderr=sp.STDOUT)
    p3 = ews03.popen(flood_cmd, shell=True, stdout=sp.PIPE, stderr=sp.STDOUT)

    # Primary flood (blocking) from ews01
    s3_output = ews01.cmd(
        f"python3 {s3_script} --target 10.0.0.2 --port 5502 --threads 100 --duration 30 2>&1"
    )

    # Collect ews02/ews03 output
    p2_out, _ = p2.communicate()
    p3_out, _ = p3.communicate()

    combined = (
        "=== ews01 (EWS-01) ===\n" + s3_output + "\n"
        + "=== ews02 (EWS-02) ===\n" + (p2_out.decode(errors="replace") if p2_out else "") + "\n"
        + "=== ews03 (EWS-03) ===\n" + (p3_out.decode(errors="replace") if p3_out else "") + "\n"
    )
    save_file(s3_out_path, combined)
    info(f"Scenario 3 output saved to {s3_out_path}\n")
    print(s3_output)

    info("\n=== All scenarios complete. ===\n")
    info(f"Finished: {datetime.now().strftime('%Y-%m-%dT%H:%M:%S')}\n")

    net.stop()


if __name__ == "__main__":
    run()
