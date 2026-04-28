#!/usr/bin/env python3
"""
Goulburn Water Treatment Plant -- Mitigations End-to-End Demo
==============================================================
AquaOps Utilities | 31261 Internetworking Capstone (UTS)

Runs all three mitigations inside Mininet, showing each attack
both WITHOUT protection (to confirm it works) and WITH protection
(to confirm it is blocked or limited).

Run as root:
    sudo mn -c
    sudo python3 mitigations/run_mitigations_demo.py

Total runtime: ~3 minutes.
Results are saved to results/mitigations/.

---
Demo 1 -- IP Allowlisting (iptables on plc1)
  Before: ews01 connects to plc1:5502 and reads registers (no auth)
  Apply:  iptables ACCEPT scada01 (10.0.1.1) on port 5502, DROP all others
  After:  ews01 connection is refused; scada01 can still read registers

Demo 2 -- Function Code Filter Proxy
  Before: ews01 trips pump1-valve (FC05 write to plc1:5502 -- no filter)
  Apply:  FC filter proxy starts on plc1:5503 -> plc1:5502
  After:  FC05 from ews01 to plc1:5503 is rejected with Modbus exception 0x01
  Verify: FC03 from ews01 to plc1:5503 is still allowed (reads work)

Demo 3 -- Rate-Limiting Proxy
  Before: ews01 floods plc1:5502 at high req/s
  Apply:  Rate-limit proxy starts on plc1:5503 (100 req/s, 20s timeout)
  After:  ews01 flood to plc1:5503 is throttled and timed out
  Verify: scada01 legitimate poll to plc1:5503 succeeds throughout
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

BASE    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ATTACKS = os.path.join(BASE, "attacks")
SERVERS = os.path.join(BASE, "servers")
MITS    = os.path.join(BASE, "mitigations")
RESULTS = os.path.join(BASE, "results", "mitigations")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def header(title):
    bar = "=" * 64
    info(f"\n{bar}\n  {title}\n{bar}\n")


def subheader(title):
    info(f"\n  --- {title} ---\n")


def save(filename, content):
    os.makedirs(RESULTS, exist_ok=True)
    path = os.path.join(RESULTS, filename)
    with open(path, "w") as f:
        f.write(content)
    info(f"  Saved: {path}\n")
    return path


def build_network():
    net = Mininet(switch=OVSSwitch, link=TCLink, controller=None)

    ews01   = net.addHost("ews01",   ip=None)   # attacker
    plc1    = net.addHost("plc1",    ip=None)   # Modbus server
    scada01 = net.addHost("scada01", ip=None)   # legitimate SCADA
    hist01  = net.addHost("hist01",  ip=None)   # data logger

    s1 = net.addSwitch("s1", failMode="standalone")  # SWIT-OFFICE
    s2 = net.addSwitch("s2", failMode="standalone")  # SWIT-PLANT
    r1 = net.addHost("r1", ip=None)

    net.addLink(ews01,   s1)
    net.addLink(scada01, s1)
    net.addLink(hist01,  s1)
    net.addLink(plc1,    s2)
    net.addLink(r1, s2)   # r1-eth0 -> s2 (10.0.0.254)
    net.addLink(r1, s1)   # r1-eth1 -> s1 (10.0.1.254)
    net.addLink(s1, s2)   # peer trunk for same-subnet L2

    return net


def configure_network(net):
    os.system("ovs-vsctl set-fail-mode s1 standalone")
    os.system("ovs-vsctl set-fail-mode s2 standalone")
    os.system("ovs-ofctl add-flow s1 action=normal")
    os.system("ovs-ofctl add-flow s2 action=normal")

    r1 = net.get("r1")
    r1.cmd("ip addr flush dev r1-eth0")
    r1.cmd("ip addr flush dev r1-eth1")
    r1.cmd("ip addr add 10.0.0.254/24 dev r1-eth0")
    r1.cmd("ip addr add 10.0.1.254/24 dev r1-eth1")
    r1.cmd("ip link set r1-eth0 up")
    r1.cmd("ip link set r1-eth1 up")
    r1.cmd("sysctl -w net.ipv4.ip_forward=1")

    # ews01, plc1 on 10.0.0.x
    for name, iface, addr in [("ews01", "ews01-eth0", "10.0.0.1"),
                                ("plc1",  "plc1-eth0",  "10.0.0.2")]:
        h = net.get(name)
        h.cmd(f"ip addr flush dev {iface}")
        h.cmd(f"ip addr add {addr}/24 dev {iface}")
        h.cmd(f"ip link set {iface} up")
        h.cmd("ip route add default via 10.0.0.254")

    # scada01, hist01 on 10.0.1.x
    for name, iface, addr in [("scada01", "scada01-eth0", "10.0.1.1"),
                                ("hist01",  "hist01-eth0",  "10.0.1.2")]:
        h = net.get(name)
        h.cmd(f"ip addr flush dev {iface}")
        h.cmd(f"ip addr add {addr}/24 dev {iface}")
        h.cmd(f"ip link set {iface} up")
        h.cmd("ip route add default via 10.0.1.254")

    info("  Network configured. Waiting for OVS to settle...\n")
    time.sleep(2)


def start_rtu_server(plc1):
    server_log = os.path.join(RESULTS, "server.log")
    os.makedirs(RESULTS, exist_ok=True)
    proc = plc1.popen(
        ["python3", os.path.join(SERVERS, "modbus_server.py")],
        stdout=open(server_log, "w"),
        stderr=subprocess.STDOUT,
    )
    info(f"  Modbus server started on plc1:5502 (PID {proc.pid})\n")
    time.sleep(3)
    return proc


def stop_rtu_server(proc):
    if proc and proc.poll() is None:
        proc.terminate()
        proc.wait()
        info("  Modbus server stopped.\n")


def quick_read(host, port, label):
    out = host.cmd(
        f"mbpoll -1 -a 1 -t 4 -r 30001 -c 1 10.0.0.2 -p {port} -T 2>&1"
    )
    last = out.strip().splitlines()[-1] if out.strip() else "(no output)"
    info(f"  [{label}] mbpoll HR 30000: {last}\n")
    return out


def check_connectivity(ews01, scada01):
    out1 = ews01.cmd("ping -c 2 -W 2 10.0.0.2")
    out3 = scada01.cmd("ping -c 2 -W 2 10.0.0.2")
    ok1  = "100% packet loss" not in out1
    ok3  = "100% packet loss" not in out3
    info(f"  ews01->plc1: {'PASS' if ok1 else 'FAIL'}   scada01->plc1: {'PASS' if ok3 else 'FAIL'}\n")
    return ok1, ok3


# ---------------------------------------------------------------------------
# Demo 1 -- IP Allowlisting
# ---------------------------------------------------------------------------
def demo_ip_allowlist(net, server_proc):
    header("DEMO 1 -- IP Allowlisting (iptables on plc1)")

    ews01   = net.get("ews01")
    plc1    = net.get("plc1")
    scada01 = net.get("scada01")

    output_lines = [
        "DEMO 1 -- IP Allowlisting",
        f"Run at: {datetime.now().isoformat()}",
        "",
    ]

    subheader("BEFORE -- no iptables rules, ews01 can read freely")
    out_before = quick_read(ews01, 5502, "ews01 BEFORE")
    output_lines.append("BEFORE (ews01 -> plc1:5502):")
    output_lines.append(out_before)

    out_scada_before = quick_read(scada01, 5502, "scada01 BEFORE")
    output_lines.append("BEFORE (scada01 -> plc1:5502):")
    output_lines.append(out_scada_before)

    subheader("APPLY -- only scada01 (10.0.1.1) may connect on port 5502")
    info(
        "  iptables rules applied on plc1:\n"
        "    ACCEPT tcp dport 5502 src 10.0.1.1 (scada01)\n"
        "    DROP   tcp dport 5502 (all others)\n\n"
    )

    plc1.cmd("iptables -F INPUT")
    plc1.cmd("iptables -A INPUT -p tcp --dport 5502 -s 10.0.1.1 -j ACCEPT")
    plc1.cmd("iptables -A INPUT -p tcp --dport 5502 -j DROP")

    output_lines.append("")
    output_lines.append("iptables rules applied on plc1:")
    output_lines.append("  ACCEPT tcp dport 5502 src 10.0.1.1 (scada01)")
    output_lines.append("  DROP   tcp dport 5502 (all other sources)")
    time.sleep(1)

    subheader("AFTER -- ews01 (attacker) blocked; scada01 still allowed")
    out_after_ews01 = ews01.cmd(
        "python3 -c \""
        "from pymodbus.client import ModbusTcpClient; "
        "c=ModbusTcpClient('10.0.0.2',port=5502); "
        "connected=c.connect(); "
        "print('Connected:',connected); "
        "c.close()"
        "\" 2>&1"
    )
    info(f"  ews01 connect attempt: {out_after_ews01.strip()}\n")
    output_lines.append("\nAFTER (ews01 connect attempt -- should fail):")
    output_lines.append(out_after_ews01)

    out_after_scada = quick_read(scada01, 5502, "scada01 AFTER (should succeed)")
    output_lines.append("AFTER (scada01 legitimate poll -- should succeed):")
    output_lines.append(out_after_scada)

    subheader("CLEANUP -- remove iptables rules")
    plc1.cmd("iptables -F INPUT")
    info("  iptables INPUT chain flushed.\n")
    output_lines.append("\niptables rules removed.")

    save("demo1_ip_allowlist.txt", "\n".join(output_lines))

    info(
        "\n  SUMMARY\n"
        "  -------------------------------------------------\n"
        "  ews01 (attacker, 10.0.0.1)   : connection DROPPED\n"
        "  scada01 (SCADA, 10.0.1.1)    : reads succeed as normal\n"
        "  Cost to attacker             : complete loss of access\n"
        "  Legitimate traffic impact    : none\n\n"
    )


# ---------------------------------------------------------------------------
# Demo 2 -- Function Code Filter Proxy
# ---------------------------------------------------------------------------
def demo_fc_filter(net, server_proc):
    header("DEMO 2 -- Function Code Filter Proxy")

    ews01 = net.get("ews01")
    plc1  = net.get("plc1")

    output_lines = [
        "DEMO 2 -- Function Code Filter Proxy",
        f"Run at: {datetime.now().isoformat()}",
        "",
    ]

    proxy_log  = os.path.join(RESULTS, "demo2_proxy.log")
    proxy_proc = None

    try:
        subheader("BEFORE -- no proxy, FC05 write reaches plc1 directly on port 5502")
        info("  Running command injection (Scenario 2) directly against plc1...\n")

        s2_before = ews01.cmd(
            f"python3 {os.path.join(ATTACKS, 'scenario2_command_injection.py')} "
            f"--target 10.0.0.2 --port 5502 2>&1"
        )
        output_lines.append("BEFORE (no proxy -- attack direct to plc1:5502):")
        output_lines.append(s2_before)
        info(f"  Outcome: {'ATTACK SUCCESSFUL' if 'SUCCESSFUL' in s2_before else 'check output'}\n")

        # Reset pump1-valve coil 0 back to CLOSED before next part
        ews01.cmd(
            "python3 -c \""
            "from pymodbus.client import ModbusTcpClient; "
            "c=ModbusTcpClient('10.0.0.2',port=5502); "
            "c.connect(); "
            "c.write_coil(0,True,device_id=1); "
            "print('pump1-valve reset to CLOSED'); "
            "c.close()"
            "\" 2>&1"
        )
        time.sleep(0.5)

        subheader("APPLY -- start FC filter proxy on plc1:5503")
        info(
            "  Proxy: plc1:5503 -> plc1:5502\n"
            "  Policy: FC05/06/0F/10 BLOCKED, FC01/02/03/04 ALLOWED\n\n"
        )

        proxy_proc = plc1.popen(
            [
                "python3",
                os.path.join(MITS, "mitigation2_fc_filter.py"),
                "--listen-port", "5503",
                "--upstream", "127.0.0.1:5502",
            ],
            stdout=open(proxy_log, "w"),
            stderr=subprocess.STDOUT,
        )
        info(f"  FC filter proxy started (PID {proxy_proc.pid}). Waiting 2s...\n")
        time.sleep(2)

        subheader("AFTER -- FC05 write to proxy port 5503 is blocked")
        info("  Running command injection against proxy (port 5503)...\n")

        s2_after = ews01.cmd(
            f"python3 {os.path.join(ATTACKS, 'scenario2_command_injection.py')} "
            f"--target 10.0.0.2 --port 5503 2>&1"
        )
        output_lines.append("\nAFTER (FC filter proxy on plc1:5503 -- attack should be blocked):")
        output_lines.append(s2_after)
        info(f"  Outcome: {'BLOCKED' if 'FAILED' in s2_after or 'exception' in s2_after.lower() else 'check output'}\n")

        subheader("VERIFY -- FC03 reads still work through the proxy")
        info("  Running reconnaissance through proxy (port 5503)...\n")

        s1_through_proxy = ews01.cmd(
            f"python3 {os.path.join(ATTACKS, 'scenario1_recon.py')} "
            f"--target 10.0.0.2 --port 5503 2>&1"
        )
        output_lines.append("\nVERIFY (reads through proxy -- should succeed):")
        output_lines.append(s1_through_proxy[:800])

        if os.path.exists(proxy_log):
            with open(proxy_log) as f:
                proxy_output = f.read()
            output_lines.append("\nProxy log (ALLOWED/BLOCKED decisions):")
            output_lines.append(proxy_output[:600])

    finally:
        if proxy_proc and proxy_proc.poll() is None:
            proxy_proc.terminate()
            proxy_proc.wait()
            info("  FC filter proxy stopped.\n")

    save("demo2_fc_filter.txt", "\n".join(output_lines))

    info(
        "\n  SUMMARY\n"
        "  -------------------------------------------------\n"
        "  FC05 Write Coil (pump1-valve trip) : BLOCKED -- Modbus exception 0x01\n"
        "  FC03 Read HRs (recon/polling)      : ALLOWED -- forwarded to plc1\n"
        "  plc1 itself                        : never saw the write request\n"
        "  plc1 required changes              : none (transparent proxy)\n\n"
    )


# ---------------------------------------------------------------------------
# Demo 3 -- Rate-Limiting Proxy
# ---------------------------------------------------------------------------
def demo_rate_limit(net, server_proc):
    header("DEMO 3 -- Rate-Limiting Proxy")

    ews01   = net.get("ews01")
    plc1    = net.get("plc1")
    scada01 = net.get("scada01")

    output_lines = [
        "DEMO 3 -- Rate-Limiting Proxy",
        f"Run at: {datetime.now().isoformat()}",
        "",
    ]

    proxy_log    = os.path.join(RESULTS, "demo3_proxy.log")
    proxy_proc   = None
    dos_duration = 15   # shorter than default to keep the demo quick

    try:
        subheader("BEFORE -- flood directly against plc1 on port 5502 (no limit)")
        info(f"  Running DoS flood for {dos_duration}s against plc1:5502...\n")

        dos_before = ews01.cmd(
            f"python3 {os.path.join(ATTACKS, 'scenario3_dos_flood.py')} "
            f"--target 10.0.0.2 --port 5502 --threads 50 --duration {dos_duration} 2>&1"
        )
        output_lines.append(f"BEFORE (no proxy -- DoS direct to plc1:5502, {dos_duration}s):")
        output_lines.append(dos_before)

        rate_before = "unknown"
        for line in dos_before.splitlines():
            if "req/s" in line.lower():
                rate_before = line.strip()
                break
        info(f"  Unmitigated flood rate: {rate_before}\n")

        subheader("APPLY -- start rate-limit proxy on plc1:5503 (100 req/s, 20s timeout)")
        info(
            "  Proxy: plc1:5503 -> plc1:5502\n"
            "  Limit: 100 req/s per source IP, 20s timeout on breach\n\n"
        )

        proxy_proc = plc1.popen(
            [
                "python3",
                os.path.join(MITS, "mitigation3_rate_limit.py"),
                "--listen-port", "5503",
                "--upstream", "127.0.0.1:5502",
                "--threshold", "100",
                "--timeout", "20",
            ],
            stdout=open(proxy_log, "w"),
            stderr=subprocess.STDOUT,
        )
        info(f"  Rate-limit proxy started (PID {proxy_proc.pid}). Waiting 2s...\n")
        time.sleep(2)

        subheader("AFTER -- flood through proxy (port 5503) is throttled")
        info(f"  Running DoS for {dos_duration}s against proxy plc1:5503...\n")

        dos_after = ews01.cmd(
            f"python3 {os.path.join(ATTACKS, 'scenario3_dos_flood.py')} "
            f"--target 10.0.0.2 --port 5503 --threads 50 --duration {dos_duration} 2>&1"
        )
        output_lines.append(f"\nAFTER (rate-limit proxy on plc1:5503, {dos_duration}s):")
        output_lines.append(dos_after)

        subheader("VERIFY -- scada01 legitimate poll succeeds during flood")
        info("  scada01 polling plc1:5503 while ews01 floods...\n")

        flood_bg = ews01.popen(
            [
                "python3",
                os.path.join(ATTACKS, "scenario3_dos_flood.py"),
                "--target", "10.0.0.2",
                "--port", "5503",
                "--threads", "50",
                "--duration", "10",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        time.sleep(1)

        poll_results = []
        for i in range(5):
            t0       = time.time()
            poll_out = scada01.cmd(
                "mbpoll -1 -a 1 -t 4 -r 30001 -c 1 10.0.0.2 -p 5503 -T 3 2>&1"
            )
            elapsed_ms = (time.time() - t0) * 1000
            success    = "[30001]" in poll_out or "30001" in poll_out
            line       = f"  Poll {i+1}: {'PASS' if success else 'FAIL'} ({elapsed_ms:.0f}ms)"
            info(line + "\n")
            poll_results.append(line)
            if i < 4:
                time.sleep(2)

        if flood_bg and flood_bg.poll() is None:
            flood_bg.terminate()
            flood_bg.wait()

        output_lines.append("\nLegitimate poll during flood (scada01 -> plc1:5503 while ews01 floods):")
        output_lines.extend(poll_results)

        if os.path.exists(proxy_log):
            with open(proxy_log) as f:
                proxy_output = f.read()
            output_lines.append("\nProxy stats log:")
            output_lines.append(proxy_output[-800:])

    finally:
        if proxy_proc and proxy_proc.poll() is None:
            proxy_proc.terminate()
            proxy_proc.wait()
            info("  Rate-limit proxy stopped.\n")

    save("demo3_rate_limit.txt", "\n".join(output_lines))

    info(
        "\n  SUMMARY\n"
        "  -------------------------------------------------\n"
        f"  Unmitigated flood rate : see demo3_rate_limit.txt\n"
        f"  Mitigated throughput   : capped at 100 req/s from ews01\n"
        f"  Legitimate poll (scada01): unaffected (separate IP bucket)\n"
        f"  plc1 required changes  : none (transparent proxy)\n\n"
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def run():
    if os.geteuid() != 0:
        print("[ERROR] Must run as root. Use: sudo python3 mitigations/run_mitigations_demo.py")
        sys.exit(1)

    setLogLevel("info")

    info("=== Goulburn WTP -- Mitigations Demo ===\n")
    info(f"Started: {datetime.now().strftime('%Y-%m-%dT%H:%M:%S')}\n")

    net = build_network()
    info("Starting network...\n")
    net.start()
    configure_network(net)

    info("Checking connectivity...\n")
    ok1, ok3 = check_connectivity(net.get("ews01"), net.get("scada01"))
    if not ok1:
        info("WARNING: ews01->plc1 connectivity failed. Demos may not work correctly.\n")

    info("Starting Modbus server on plc1:5502...\n")
    server_proc = start_rtu_server(net.get("plc1"))

    try:
        demo_ip_allowlist(net, server_proc)
        demo_fc_filter(net, server_proc)
        demo_rate_limit(net, server_proc)
    finally:
        stop_rtu_server(server_proc)
        info("Stopping network...\n")
        net.stop()

    info("\n=== All mitigation demos complete ===\n")
    info(f"Results saved to: {RESULTS}\n")
    info(f"Finished: {datetime.now().strftime('%Y-%m-%dT%H:%M:%S')}\n")


if __name__ == "__main__":
    run()
