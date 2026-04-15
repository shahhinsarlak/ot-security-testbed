#!/usr/bin/env python3
"""
OT Security Testbed — Automated Scenario Runner
================================================
Builds the Mininet topology and executes all three attack scenarios
non-interactively, saving results to results/.

Run as root:
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

# Base dir — this script lives at the project root
BASE = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.join(BASE, "results")
SERVERS = os.path.join(BASE, "servers")
ATTACKS = os.path.join(BASE, "attacks")


def build_network():
    net = Mininet(switch=OVSSwitch, link=TCLink, controller=None)

    h1 = net.addHost("h1", ip="10.0.0.1/24")
    h2 = net.addHost("h2", ip="10.0.0.2/24")
    h3 = net.addHost("h3", ip="10.0.1.1/24")
    h4 = net.addHost("h4", ip="10.0.1.2/24")
    h5 = net.addHost("h5", ip="10.0.0.5/24")

    s1 = net.addSwitch("s1", failMode="standalone")
    s2 = net.addSwitch("s2", failMode="standalone")
    r1 = net.addHost("r1", ip=None)

    net.addLink(h3, s1)
    net.addLink(h4, s1)
    net.addLink(r1, s1)
    net.addLink(r1, s2)
    net.addLink(h1, s2)
    net.addLink(h2, s2)
    net.addLink(h5, s2)

    return net


def configure_ovs():
    for sw in ["s1", "s2"]:
        subprocess.run(["ovs-vsctl", "set-fail-mode", sw, "standalone"], check=False)
        subprocess.run(["ovs-ofctl", "add-flow", sw, "action=normal"], check=False)
    info("OVS: fail-mode=standalone + action=normal applied\n")


def configure_router(r1):
    r1.cmd("ip addr flush dev r1-eth0")
    r1.cmd("ip addr flush dev r1-eth1")
    r1.cmd("ip addr add 10.0.1.254/24 dev r1-eth0")
    r1.cmd("ip addr add 10.0.0.254/24 dev r1-eth1")
    r1.cmd("ip link set r1-eth0 up")
    r1.cmd("ip link set r1-eth1 up")
    r1.cmd("sysctl -w net.ipv4.ip_forward=1")


def configure_hosts(net):
    for name in ["h1", "h2", "h5"]:
        net.get(name).cmd("ip route add default via 10.0.0.254")
    for name in ["h3", "h4"]:
        net.get(name).cmd("ip route add default via 10.0.1.254")


def verify_connectivity(net):
    h1 = net.get("h1")
    h2 = net.get("h2")
    h3 = net.get("h3")

    out1 = h1.cmd("ping -c 3 -W 2 10.0.0.2")
    out3 = h3.cmd("ping -c 3 -W 2 10.0.0.2")

    ok1 = "100% packet loss" not in out1
    ok3 = "100% packet loss" not in out3

    info(f"h1->h2: {'PASS' if ok1 else 'FAIL'}\n")
    info(f"h3->h2: {'PASS' if ok3 else 'FAIL'}\n")

    if not ok1 or not ok3:
        info("Retrying OVS flow config...\n")
        for sw in ["s1", "s2"]:
            subprocess.run(["ovs-ofctl", "del-flows", sw], check=False)
            subprocess.run(["ovs-ofctl", "add-flow", sw, "action=normal"], check=False)
        time.sleep(2)
        out1 = h1.cmd("ping -c 3 -W 2 10.0.0.2")
        ok1 = "100% packet loss" not in out1
        info(f"h1->h2 retry: {'PASS' if ok1 else 'FAIL'}\n")

    return ok1


def save_file(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)


def run():
    setLogLevel("info")

    info("=== OT Security Testbed — Automated Scenario Runner ===\n")
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

    h1 = net.get("h1")
    h2 = net.get("h2")

    # -------------------------------------------------------------------------
    # Phase 2: Start Modbus server on h2
    # -------------------------------------------------------------------------
    server_script = os.path.join(SERVERS, "modbus_server.py")
    server_log = os.path.join(RESULTS, "server_startup.txt")
    info(f"\n=== Starting Modbus server on h2 ===\n")

    # Use popen() so the process truly runs in h2's namespace detached
    import subprocess as sp
    server_proc = h2.popen(
        ["python3", server_script],
        stdout=open(server_log, "w"),
        stderr=sp.STDOUT,
    )
    info(f"Server PID {server_proc.pid} started on h2. Waiting 4s to bind...\n")
    time.sleep(4)

    # Confirm with mbpoll
    info("Confirming server with mbpoll (coils 0-1)...\n")
    mbpoll_coils = h1.cmd(
        "mbpoll -1 -a 1 -t 0 -r 1 -c 2 10.0.0.2 -p 5502 2>&1"
    )
    info(f"mbpoll coils:\n{mbpoll_coils}\n")

    mbpoll_hr = h1.cmd(
        "mbpoll -1 -a 1 -t 4 -r 30001 -c 3 10.0.0.2 -p 5502 2>&1"
    )
    info(f"mbpoll holding registers:\n{mbpoll_hr}\n")

    # Append confirmation to server_startup.txt
    with open(server_log, "a") as f:
        f.write("\n--- mbpoll coil confirmation ---\n")
        f.write(mbpoll_coils)
        f.write("\n--- mbpoll HR confirmation ---\n")
        f.write(mbpoll_hr)

    info(f"Server startup saved to {server_log}\n")

    # -------------------------------------------------------------------------
    # Phase 3: Scenario 1 — Reconnaissance
    # -------------------------------------------------------------------------
    info("\n=== Scenario 1: Reconnaissance ===\n")
    s1_script = os.path.join(ATTACKS, "scenario1_recon.py")
    s1_out_path = os.path.join(RESULTS, "scenario1_output.txt")

    s1_output = h1.cmd(
        f"python3 {s1_script} --target 10.0.0.2 --port 5502 2>&1"
    )
    save_file(s1_out_path, s1_output)
    info(f"Scenario 1 output saved to {s1_out_path}\n")
    print(s1_output)

    # -------------------------------------------------------------------------
    # Phase 4: Scenario 2 — Command Injection
    # -------------------------------------------------------------------------
    info("\n=== Scenario 2: Command Injection ===\n")

    # Baseline
    s2_baseline = h1.cmd(
        "mbpoll -1 -a 1 -t 4 -r 30001 -c 1 10.0.0.2 -p 5502 2>&1"
    )
    save_file(os.path.join(RESULTS, "scenario2_baseline.txt"), s2_baseline)

    s2_script = os.path.join(ATTACKS, "scenario2_command_injection.py")
    s2_out_path = os.path.join(RESULTS, "scenario2_output.txt")
    s2_output = h1.cmd(
        f"python3 {s2_script} --target 10.0.0.2 --port 5502 2>&1"
    )
    save_file(s2_out_path, s2_output)
    info(f"Scenario 2 output saved to {s2_out_path}\n")
    print(s2_output)

    # Post-attack confirmation
    s2_post = h1.cmd("mbpoll -1 -a 1 -t 4 -r 30001 -c 1 10.0.0.2 -p 5502 2>&1")
    save_file(os.path.join(RESULTS, "scenario2_post.txt"), s2_post)

    # Reset coil 0 back to True (CLOSED)
    info("Resetting coil 0 back to CLOSED...\n")
    reset_out = h1.cmd(
        "python3 -c \""
        "from pymodbus.client import ModbusTcpClient; "
        "c=ModbusTcpClient('10.0.0.2',port=5502); "
        "c.connect(); "
        "r=c.write_coil(0,True,device_id=1); "
        "print('Coil 0 reset to CLOSED, result:', r); "
        "c.close()"
        "\" 2>&1"
    )
    info(f"Reset result: {reset_out}\n")

    # -------------------------------------------------------------------------
    # Phase 5: Scenario 3 — DoS
    # -------------------------------------------------------------------------
    info("\n=== Scenario 3: Denial of Service ===\n")

    # Baseline timing
    s3_baseline_script = (
        "import time, subprocess; results = []\n"
        "for i in range(5):\n"
        "    t = time.time()\n"
        "    subprocess.run(['mbpoll','-1','-a','1','-t','4','-r','30001','-c','1','10.0.0.2','-p','5502'], capture_output=True)\n"
        "    ms = (time.time()-t)*1000\n"
        "    results.append(ms)\n"
        "    print(f'Poll {i+1}: {ms:.1f}ms')\n"
        "    time.sleep(2)\n"
        "print(f'Avg baseline: {sum(results)/len(results):.1f}ms')\n"
    )
    s3_baseline = h1.cmd(
        f"python3 -c \"{s3_baseline_script.replace(chr(10), ';')}\" 2>&1"
    )

    # Simpler approach for baseline
    s3_baseline = h1.cmd(
        "python3 -c \""
        "import time, subprocess; results = []\n"
        "[results.append((lambda: (t:=time.time(), subprocess.run(['mbpoll','-1','-a','1','-t','4','-r','30001','-c','1','10.0.0.2','-p','5502'], capture_output=True), (time.time()-t)*1000))()[-1]) or time.sleep(2) for _ in range(5)]\n"
        "print('Polls done')\n"
        "\" 2>&1"
    )

    # Actually run baseline inline simpler
    s3_baseline_lines = []
    for i in range(5):
        t0 = time.time()
        r = h1.cmd("mbpoll -1 -a 1 -t 4 -r 30001 -c 1 10.0.0.2 -p 5502 2>&1")
        ms = (time.time() - t0) * 1000
        line = f"Poll {i+1}: {ms:.1f}ms"
        s3_baseline_lines.append(line)
        info(f"  {line}\n")
        if i < 4:
            time.sleep(2)

    baseline_ms_vals = []
    for ln in s3_baseline_lines:
        try:
            val = float(ln.split(":")[1].strip().replace("ms", ""))
            baseline_ms_vals.append(val)
        except Exception:
            pass
    if baseline_ms_vals:
        avg_b = sum(baseline_ms_vals) / len(baseline_ms_vals)
        s3_baseline_lines.append(f"Avg baseline: {avg_b:.1f}ms")

    s3_baseline_text = "\n".join(s3_baseline_lines) + "\n"
    save_file(os.path.join(RESULTS, "scenario3_baseline.txt"), s3_baseline_text)
    info(f"Baseline saved.\n")

    s3_script = os.path.join(ATTACKS, "scenario3_dos.py")
    s3_out_path = os.path.join(RESULTS, "scenario3_output.txt")
    info("Running DoS for 30 seconds...\n")
    s3_output = h1.cmd(
        f"python3 {s3_script} --target 10.0.0.2 --port 5502 --duration 30 2>&1"
    )
    save_file(s3_out_path, s3_output)
    info(f"Scenario 3 output saved to {s3_out_path}\n")
    print(s3_output)

    info("\n=== All scenarios complete. ===\n")
    info(f"Finished: {datetime.now().strftime('%Y-%m-%dT%H:%M:%S')}\n")

    net.stop()


if __name__ == "__main__":
    run()
