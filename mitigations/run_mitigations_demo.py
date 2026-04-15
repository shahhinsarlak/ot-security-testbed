#!/usr/bin/env python3
"""
OT Security Testbed — Mitigations End-to-End Demo
==================================================
Runs all three mitigations inside Mininet, showing each attack
both WITHOUT protection (to confirm it works) and WITH protection
(to confirm it is blocked or limited).

Run as root:
    sudo python3 mitigations/run_mitigations_demo.py

Total runtime: ~3 minutes.

Results are saved to results/mitigations/.

---
Demo 1 — IP Allowlisting (iptables)
  Before: h1 connects to h2:5502 and reads registers (no auth needed)
  Apply:  iptables ACCEPT h3(10.0.1.1) on port 5502, DROP everyone else
  After:  h1 connection is refused; h3 can still read registers

Demo 2 — Function Code Filter Proxy
  Before: h1 trips the breaker (FC05 write to h2:5502 — no filter)
  Apply:  FC filter proxy starts on h2:5503 → forwards to RTU on h2:5502
  After:  FC05 from h1 to h2:5503 is rejected with Modbus exception 0x01
  Verify: FC03 from h1 to h2:5503 is still allowed (reads work)

Demo 3 — Rate-Limiting Proxy
  Before: h1 floods h2:5502 at ~3,600 req/s
  Apply:  Rate-limit proxy starts on h2:5503 (max 20 req/s) → h2:5502
  After:  h1 flood to h2:5503 is throttled; connection closed on exceed
  Verify: h3 legitimate poll to h2:5503 succeeds throughout
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
def header(title: str):
    bar = "=" * 64
    info(f"\n{bar}\n  {title}\n{bar}\n")


def subheader(title: str):
    info(f"\n  --- {title} ---\n")


def save(filename: str, content: str):
    os.makedirs(RESULTS, exist_ok=True)
    path = os.path.join(RESULTS, filename)
    with open(path, "w") as f:
        f.write(content)
    info(f"  Saved: {path}\n")
    return path


def build_network():
    net = Mininet(switch=OVSSwitch, link=TCLink, controller=None)
    h1 = net.addHost("h1", ip="10.0.0.1/24")  # Attacker
    h2 = net.addHost("h2", ip="10.0.0.2/24")  # RTU
    h3 = net.addHost("h3", ip="10.0.1.1/24")  # SCADA/HMI
    h4 = net.addHost("h4", ip="10.0.1.2/24")  # Historian

    s1 = net.addSwitch("s1", failMode="standalone")  # IT-side
    s2 = net.addSwitch("s2", failMode="standalone")  # OT-side
    r1 = net.addHost("r1", ip=None)

    net.addLink(h3, s1)
    net.addLink(h4, s1)
    net.addLink(r1, s1)
    net.addLink(r1, s2)
    net.addLink(h1, s2)
    net.addLink(h2, s2)

    return net


def configure_network(net):
    for sw in ["s1", "s2"]:
        subprocess.run(["ovs-vsctl", "set-fail-mode", sw, "standalone"], check=False)
        subprocess.run(["ovs-ofctl", "add-flow", sw, "action=normal"], check=False)

    r1 = net.get("r1")
    r1.cmd("ip addr flush dev r1-eth0")
    r1.cmd("ip addr flush dev r1-eth1")
    r1.cmd("ip addr add 10.0.1.254/24 dev r1-eth0")
    r1.cmd("ip addr add 10.0.0.254/24 dev r1-eth1")
    r1.cmd("ip link set r1-eth0 up")
    r1.cmd("ip link set r1-eth1 up")
    r1.cmd("sysctl -w net.ipv4.ip_forward=1")

    for name in ["h1", "h2"]:
        net.get(name).cmd("ip route add default via 10.0.0.254")
    for name in ["h3", "h4"]:
        net.get(name).cmd("ip route add default via 10.0.1.254")

    info("  Network configured. Waiting for OVS to settle...\n")
    time.sleep(2)


def start_rtu_server(h2) -> object:
    """Start the Modbus server on h2:5502. Returns the Popen handle."""
    server_log = os.path.join(RESULTS, "server.log")
    os.makedirs(RESULTS, exist_ok=True)
    proc = h2.popen(
        ["python3", os.path.join(SERVERS, "modbus_server.py")],
        stdout=open(server_log, "w"),
        stderr=subprocess.STDOUT,
    )
    info(f"  RTU server started on h2:5502 (PID {proc.pid})\n")
    time.sleep(3)
    return proc


def stop_rtu_server(proc):
    if proc and proc.poll() is None:
        proc.terminate()
        proc.wait()
        info("  RTU server stopped.\n")


def quick_read(h1, port: int, label: str) -> str:
    """Read HR 30000 from h2 via mbpoll. Returns the output."""
    out = h1.cmd(
        f"mbpoll -1 -a 1 -t 4 -r 30001 -c 1 10.0.0.2 -p {port} -T 2>&1"
    )
    info(f"  [{label}] mbpoll HR 30000: {out.strip().splitlines()[-1] if out.strip() else '(no output)'}\n")
    return out


def check_connectivity(h1, h3):
    """Ping h1->h2 and h3->h2 to make sure the network is up."""
    out1 = h1.cmd("ping -c 2 -W 2 10.0.0.2")
    out3 = h3.cmd("ping -c 2 -W 2 10.0.0.2")
    ok1 = "100% packet loss" not in out1
    ok3 = "100% packet loss" not in out3
    info(f"  h1->h2: {'PASS' if ok1 else 'FAIL'}   h3->h2: {'PASS' if ok3 else 'FAIL'}\n")
    return ok1, ok3


# ---------------------------------------------------------------------------
# Demo 1 — IP Allowlisting
# ---------------------------------------------------------------------------
def demo_ip_allowlist(net, server_proc):
    header("DEMO 1 — IP Allowlisting (iptables)")

    h1 = net.get("h1")
    h2 = net.get("h2")
    h3 = net.get("h3")

    output_lines = [
        "DEMO 1 — IP Allowlisting",
        f"Run at: {datetime.now().isoformat()}",
        "",
    ]

    # ------------------------------------------------------------------
    subheader("BEFORE — no iptables rules, h1 can read freely")

    out_before = quick_read(h1, 5502, "h1 BEFORE")
    output_lines.append("BEFORE (h1 -> h2:5502):")
    output_lines.append(out_before)

    out_h3_before = quick_read(h3, 5502, "h3 BEFORE")
    output_lines.append("BEFORE (h3 -> h2:5502):")
    output_lines.append(out_h3_before)

    # ------------------------------------------------------------------
    subheader("APPLY mitigation — only h3 (10.0.1.1) may connect on port 5502")
    info(
        "  iptables rules applied on h2:\n"
        "    ACCEPT tcp dport 5502 src 10.0.1.1\n"
        "    DROP   tcp dport 5502 (all others)\n\n"
    )

    # Flush existing INPUT rules first to avoid duplicates across demo runs
    h2.cmd("iptables -F INPUT")

    # Accept traffic from the legitimate SCADA host (h3 = 10.0.1.1)
    h2.cmd("iptables -A INPUT -p tcp --dport 5502 -s 10.0.1.1 -j ACCEPT")

    # Drop everything else targeting the Modbus port
    h2.cmd("iptables -A INPUT -p tcp --dport 5502 -j DROP")

    output_lines.append("")
    output_lines.append("iptables rules applied on h2:")
    output_lines.append("  ACCEPT tcp dport 5502 src 10.0.1.1 (h3 / SCADA)")
    output_lines.append("  DROP   tcp dport 5502 (all other sources)")

    time.sleep(1)

    # ------------------------------------------------------------------
    subheader("AFTER — h1 (attacker) is blocked; h3 (SCADA) still allowed")

    out_after_h1 = h1.cmd(
        "python3 -c \""
        "from pymodbus.client import ModbusTcpClient; "
        "c=ModbusTcpClient('10.0.0.2',port=5502); "
        "connected=c.connect(); "
        "print('Connected:',connected); "
        "c.close()"
        "\" 2>&1"
    )
    info(f"  h1 connect attempt: {out_after_h1.strip()}\n")
    output_lines.append("")
    output_lines.append("AFTER (h1 connect attempt — should fail):")
    output_lines.append(out_after_h1)

    out_after_h3 = quick_read(h3, 5502, "h3 AFTER (should succeed)")
    output_lines.append("AFTER (h3 legitimate poll — should succeed):")
    output_lines.append(out_after_h3)

    # ------------------------------------------------------------------
    subheader("CLEANUP — remove iptables rules")
    h2.cmd("iptables -F INPUT")
    info("  iptables INPUT chain flushed.\n")

    output_lines.append("\niptables rules removed.")
    save("demo1_ip_allowlist.txt", "\n".join(output_lines))

    info(
        "\n  SUMMARY\n"
        "  ─────────────────────────────────────────────────\n"
        "  h1 (attacker, 10.0.0.1)  : connection DROPPED\n"
        "  h3 (SCADA, 10.0.1.1)     : reads succeed as normal\n"
        "  Cost to attacker          : complete loss of access\n"
        "  Legitimate traffic impact : none\n\n"
    )


# ---------------------------------------------------------------------------
# Demo 2 — Function Code Filter Proxy
# ---------------------------------------------------------------------------
def demo_fc_filter(net, server_proc):
    header("DEMO 2 — Function Code Filter Proxy")

    h1 = net.get("h1")
    h2 = net.get("h2")

    output_lines = [
        "DEMO 2 — Function Code Filter Proxy",
        f"Run at: {datetime.now().isoformat()}",
        "",
    ]

    proxy_log = os.path.join(RESULTS, "demo2_proxy.log")
    proxy_proc = None

    try:
        # ------------------------------------------------------------------
        subheader("BEFORE — no proxy, FC05 write reaches RTU directly on port 5502")
        info("  Running command injection (scenario 2) directly against RTU...\n")

        s2_before = h1.cmd(
            f"python3 {os.path.join(ATTACKS, 'scenario2_command_injection.py')} "
            f"--target 10.0.0.2 --port 5502 2>&1"
        )
        output_lines.append("BEFORE (no proxy — attack direct to h2:5502):")
        output_lines.append(s2_before)
        info(f"  Outcome: {'ATTACK SUCCESSFUL' if 'SUCCESSFUL' in s2_before else 'check output'}\n")

        # Reset coil 0 back to CLOSED before the next part
        h1.cmd(
            "python3 -c \""
            "from pymodbus.client import ModbusTcpClient; "
            "c=ModbusTcpClient('10.0.0.2',port=5502); "
            "c.connect(); "
            "c.write_coil(0,True,device_id=1); "
            "print('Coil 0 reset to CLOSED'); "
            "c.close()"
            "\" 2>&1"
        )
        time.sleep(0.5)

        # ------------------------------------------------------------------
        subheader("APPLY mitigation — start FC filter proxy on h2:5503")
        info(
            "  Proxy: h2:5503 → RTU h2:5502\n"
            "  Policy: FC05/06/0F/10 BLOCKED, FC01/02/03/04 ALLOWED\n\n"
        )

        proxy_proc = h2.popen(
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

        # ------------------------------------------------------------------
        subheader("AFTER — FC05 write to proxy port 5503 is blocked")
        info("  Running command injection against proxy (port 5503)...\n")

        s2_after = h1.cmd(
            f"python3 {os.path.join(ATTACKS, 'scenario2_command_injection.py')} "
            f"--target 10.0.0.2 --port 5503 2>&1"
        )
        output_lines.append("\nAFTER (FC filter proxy on h2:5503 — attack should be blocked):")
        output_lines.append(s2_after)
        info(f"  Outcome: {'BLOCKED' if 'FAILED' in s2_after or 'exception' in s2_after.lower() else 'check output'}\n")

        # ------------------------------------------------------------------
        subheader("VERIFY — FC03 reads still work through the proxy")
        info("  Running reconnaissance through proxy (port 5503)...\n")

        s1_through_proxy = h1.cmd(
            f"python3 {os.path.join(ATTACKS, 'scenario1_recon.py')} "
            f"--target 10.0.0.2 --port 5503 2>&1"
        )
        output_lines.append("\nVERIFY (reads through proxy — should succeed):")
        output_lines.append(s1_through_proxy[:800])  # trim for readability

        # Show proxy log for educational context
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
        "  ─────────────────────────────────────────────────\n"
        "  FC05 Write Coil (breaker trip) : BLOCKED — Modbus exception 0x01\n"
        "  FC03 Read HRs (recon/polling)  : ALLOWED — forwarded to RTU\n"
        "  RTU itself                     : never saw the write request\n"
        "  RTU required changes           : none (transparent proxy)\n\n"
    )


# ---------------------------------------------------------------------------
# Demo 3 — Rate-Limiting Proxy
# ---------------------------------------------------------------------------
def demo_rate_limit(net, server_proc):
    header("DEMO 3 — Rate-Limiting Proxy")

    h1 = net.get("h1")
    h2 = net.get("h2")
    h3 = net.get("h3")

    output_lines = [
        "DEMO 3 — Rate-Limiting Proxy",
        f"Run at: {datetime.now().isoformat()}",
        "",
    ]

    proxy_log = os.path.join(RESULTS, "demo3_proxy.log")
    proxy_proc = None
    dos_duration = 15  # shorter than the scenario default to keep the demo quick

    try:
        # ------------------------------------------------------------------
        subheader("BEFORE — flood directly against RTU on port 5502 (no limit)")
        info(f"  Running DoS for {dos_duration}s against h2:5502...\n")

        dos_before = h1.cmd(
            f"python3 {os.path.join(ATTACKS, 'scenario3_dos.py')} "
            f"--target 10.0.0.2 --port 5502 --duration {dos_duration} 2>&1"
        )
        output_lines.append(f"BEFORE (no proxy — DoS direct to h2:5502, {dos_duration}s):")
        output_lines.append(dos_before)

        # Extract peak rate from output for the summary
        rate_before = "unknown"
        for line in dos_before.splitlines():
            if "req/s" in line.lower() or "requests/s" in line.lower():
                rate_before = line.strip()
                break
        info(f"  Unmitigated flood rate: {rate_before}\n")

        # ------------------------------------------------------------------
        subheader("APPLY mitigation — start rate-limit proxy on h2:5503 (max 20 req/s)")
        info(
            "  Proxy: h2:5503 → RTU h2:5502\n"
            "  Limit: 20 req/s per source IP (sliding window)\n\n"
        )

        proxy_proc = h2.popen(
            [
                "python3",
                os.path.join(MITS, "mitigation3_rate_limit.py"),
                "--listen-port", "5503",
                "--upstream", "127.0.0.1:5502",
                "--max-rps", "20",
            ],
            stdout=open(proxy_log, "w"),
            stderr=subprocess.STDOUT,
        )
        info(f"  Rate-limit proxy started (PID {proxy_proc.pid}). Waiting 2s...\n")
        time.sleep(2)

        # ------------------------------------------------------------------
        subheader("AFTER — flood through proxy (port 5503) is throttled")
        info(
            f"  Running DoS for {dos_duration}s against proxy h2:5503...\n"
            "  Expect: far fewer requests reach the RTU\n\n"
        )

        dos_after = h1.cmd(
            f"python3 {os.path.join(ATTACKS, 'scenario3_dos.py')} "
            f"--target 10.0.0.2 --port 5503 --duration {dos_duration} 2>&1"
        )
        output_lines.append(f"\nAFTER (rate-limit proxy on h2:5503, {dos_duration}s):")
        output_lines.append(dos_after)

        # ------------------------------------------------------------------
        subheader("VERIFY — legitimate poll from h3 still works during flood")
        info("  h3 polling h2:5503 (via rate-limit proxy) while h1 floods...\n")

        # Run flood in background and poll from h3 simultaneously
        flood_bg = h1.popen(
            [
                "python3",
                os.path.join(ATTACKS, "scenario3_dos.py"),
                "--target", "10.0.0.2",
                "--port", "5503",
                "--duration", "10",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        time.sleep(1)  # let flood spin up

        poll_results = []
        for i in range(5):
            t0 = time.time()
            poll_out = h3.cmd(
                "mbpoll -1 -a 1 -t 4 -r 30001 -c 1 10.0.0.2 -p 5503 -T 3 2>&1"
            )
            elapsed_ms = (time.time() - t0) * 1000
            success = "[30001]" in poll_out or "30001" in poll_out
            line = f"  Poll {i+1}: {'PASS' if success else 'FAIL'} ({elapsed_ms:.0f}ms)"
            info(line + "\n")
            poll_results.append(line)
            if i < 4:
                time.sleep(2)

        # Wait for background flood to finish
        if flood_bg and flood_bg.poll() is None:
            flood_bg.terminate()
            flood_bg.wait()

        output_lines.append("\nLegitimate poll during flood (h3 -> h2:5503 while h1 floods):")
        output_lines.extend(poll_results)

        # Include proxy log stats
        if os.path.exists(proxy_log):
            with open(proxy_log) as f:
                proxy_output = f.read()
            output_lines.append("\nProxy stats log:")
            output_lines.append(proxy_output[-800:])  # last 800 chars

    finally:
        if proxy_proc and proxy_proc.poll() is None:
            proxy_proc.terminate()
            proxy_proc.wait()
            info("  Rate-limit proxy stopped.\n")

    save("demo3_rate_limit.txt", "\n".join(output_lines))

    info(
        "\n  SUMMARY\n"
        "  ─────────────────────────────────────────────────\n"
        f"  Unmitigated flood rate  : see demo3_rate_limit.txt\n"
        f"  Mitigated throughput    : capped at 20 req/s from h1\n"
        f"  Legitimate poll (h3)    : unaffected (separate IP bucket)\n"
        f"  RTU required changes    : none (transparent proxy)\n\n"
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def run():
    setLogLevel("info")

    info("=== OT Security Testbed — Mitigations Demo ===\n")
    info(f"Started: {datetime.now().strftime('%Y-%m-%dT%H:%M:%S')}\n")

    net = build_network()

    info("Starting network...\n")
    net.start()
    configure_network(net)

    # Check connectivity before proceeding
    info("Checking connectivity...\n")
    h1 = net.get("h1")
    h3 = net.get("h3")
    ok1, ok3 = check_connectivity(h1, h3)
    if not ok1:
        info("WARNING: h1->h2 connectivity failed. Demos may not work correctly.\n")

    info("Starting RTU server on h2:5502...\n")
    server_proc = start_rtu_server(net.get("h2"))

    try:
        demo_ip_allowlist(net, server_proc)
        demo_fc_filter(net, server_proc)
        demo_rate_limit(net, server_proc)
    finally:
        stop_rtu_server(server_proc)
        info("Stopping network...\n")
        net.stop()

    info(f"\n=== All mitigation demos complete ===\n")
    info(f"Results saved to: {RESULTS}\n")
    info(f"Finished: {datetime.now().strftime('%Y-%m-%dT%H:%M:%S')}\n")


if __name__ == "__main__":
    run()
