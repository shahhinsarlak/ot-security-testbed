#!/usr/bin/env python3
"""
Goulburn Water Treatment Plant -- Mitigation 1: IP Allowlist
=============================================================
AquaOps Utilities | 31261 Internetworking Capstone (UTS)

CONCEPT
-------
Modbus TCP carries no authentication -- any host that can reach port 5502
on plc1 can read or write any register. An iptables allowlist restricts
access to a single trusted source IP, closing off all unauthorised hosts.

POLICY APPLIED ON plc1 (10.0.0.2)
-----------------------------------
  ACCEPT  TCP dport 5502  src 10.0.1.1  (scada01 / legitimate SCADA)
  DROP    TCP dport 5502  (all other sources)

HOW TO RUN
----------
Run this script on the plc1 host inside Mininet:

  mininet> plc1 python3 mitigations/mitigation1_ip_allowlist.py --apply

To remove the rules:

  mininet> plc1 python3 mitigations/mitigation1_ip_allowlist.py --remove

To check current rules:

  mininet> plc1 python3 mitigations/mitigation1_ip_allowlist.py --status

EFFECT
------
  ews01 (attacker, 10.0.0.1)  : TCP to port 5502 silently DROPPED
  scada01 (10.0.1.1)          : TCP to port 5502 ACCEPTED as normal
"""

import argparse
import os
import subprocess
import sys

ALLOWED_SRC  = "10.0.1.1"   # scada01 -- legitimate SCADA client
MODBUS_PORT  = "5502"


def parse_args():
    parser = argparse.ArgumentParser(description="Modbus IP allowlist via iptables")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--apply",  action="store_true", help="Apply allowlist rules")
    group.add_argument("--remove", action="store_true", help="Remove allowlist rules (flush INPUT)")
    group.add_argument("--status", action="store_true", help="Print current iptables INPUT rules")
    return parser.parse_args()


def run(cmd):
    """Run a shell command, print it, return (returncode, stdout+stderr)."""
    print(f"  $ {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    combined = (result.stdout + result.stderr).strip()
    if combined:
        print(f"    {combined}")
    return result.returncode


def apply_rules():
    print("=" * 60)
    print("  Mitigation 1 -- IP Allowlist (iptables)")
    print(f"  Allow: {ALLOWED_SRC} -> port {MODBUS_PORT}")
    print(f"  Drop:  all other sources -> port {MODBUS_PORT}")
    print("=" * 60)

    # Flush INPUT to avoid duplicate rules from previous runs
    run("iptables -F INPUT")

    # Accept traffic from the legitimate SCADA host (scada01 = 10.0.1.1)
    run(
        f"iptables -A INPUT -p tcp --dport {MODBUS_PORT} "
        f"-s {ALLOWED_SRC} -j ACCEPT"
    )

    # Drop everything else targeting the Modbus port
    run(f"iptables -A INPUT -p tcp --dport {MODBUS_PORT} -j DROP")

    print("\n[+] Allowlist applied.")
    print(f"    Only {ALLOWED_SRC} may reach port {MODBUS_PORT}.")
    print("    All other connections will be silently dropped.\n")


def remove_rules():
    print("=" * 60)
    print("  Mitigation 1 -- Removing IP Allowlist")
    print("=" * 60)
    run("iptables -F INPUT")
    print("\n[+] iptables INPUT chain flushed. All connections to port 5502 now allowed.\n")


def show_status():
    print("=" * 60)
    print("  Mitigation 1 -- Current iptables INPUT rules")
    print("=" * 60)
    run("iptables -L INPUT -n --line-numbers -v")


def main():
    if os.geteuid() != 0:
        print("[ERROR] This script must be run as root (or inside Mininet as plc1).")
        sys.exit(1)

    args = parse_args()

    if args.apply:
        apply_rules()
    elif args.remove:
        remove_rules()
    elif args.status:
        show_status()


if __name__ == "__main__":
    main()
