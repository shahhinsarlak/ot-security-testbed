from pymodbus.server import StartTcpServer
from pymodbus.datastore import (
    ModbusSlaveContext,
    ModbusServerContext,
    ModbusSequentialDataBlock,
)
import subprocess
import os

# Update ALLOWED_MACS each session -- MAC addresses change on every Mininet restart.
# Run: mininet> scada01 ip link show scada01-eth0
# and copy the MAC from the link/ether line below.
ALLOWED_IPS  = ['10.0.1.1']
ALLOWED_MACS = {
    '10.0.1.1': 'aa:bb:cc:dd:ee:ff'   # <-- replace with actual MAC before running
}

SERVER_IP   = '10.0.0.2'
SERVER_PORT = 5502


def get_mac_from_arp(ip):
    try:
        result = subprocess.check_output(['arp', '-n', ip]).decode()
        for line in result.splitlines():
            if ip in line and 'incomplete' not in line:
                for part in line.split():
                    if ':' in part and len(part) == 17:
                        return part.lower()
    except:
        pass
    return None


def populate_arp_cache():
    print('Populating ARP cache...')
    for ip in ALLOWED_IPS:
        os.system(f'ping -c 2 {ip} > /dev/null 2>&1')
        mac = get_mac_from_arp(ip)
        if mac:
            print(f'  [ARP LEARNED] {ip} -> {mac}')
        else:
            print(f'  [ARP FAILED] Could not learn MAC for {ip}')
    print()


def apply_whitelist():
    print('Applying IP + MAC whitelist via iptables...')
    os.system('iptables -F INPUT')
    os.system('iptables -A INPUT -i lo -j ACCEPT')

    for ip, mac in ALLOWED_MACS.items():
        actual_mac = get_mac_from_arp(ip)
        if actual_mac is None:
            print(f'  [ERROR] Could not resolve MAC for {ip}')
            os.system(f'iptables -A INPUT -p tcp --dport {SERVER_PORT} -j DROP')
            return
        if actual_mac.lower() != mac.lower():
            print(f'  [MAC MISMATCH] {ip}')
            print(f'    Expected : {mac}')
            print(f'    Actual   : {actual_mac}')
            print(f'  [BLOCKING] {ip} - MAC does not match whitelist')
        else:
            os.system(
                f'iptables -A INPUT -p tcp --dport {SERVER_PORT} '
                f'-s {ip} -m mac --mac-source {mac} -j ACCEPT'
            )
            print(f'  [ALLOWED] {ip} with MAC {mac}')

    os.system(f'iptables -A INPUT -p tcp --dport {SERVER_PORT} -j DROP')
    print(f'  [BLOCKED] all other IPs and MACs -> port {SERVER_PORT}')
    print('Whitelist applied\n')


populate_arp_cache()
apply_whitelist()

store = ModbusSlaveContext(
    co=ModbusSequentialDataBlock(0,     [1, 1] + [0] * 8),
    hr=ModbusSequentialDataBlock(30000, [300, 185] + [0] * 13),
)
context = ModbusServerContext(slaves=store, single=True)

print('OT Testbed - Modbus server (PLC-PUMP1) -- IP + MAC whitelist active')
print(f'Listening on {SERVER_IP}:{SERVER_PORT}')
print(f'Whitelisted IPs  : {ALLOWED_IPS}')
print(f'MAC verification : {ALLOWED_MACS}')

StartTcpServer(context=context, address=(SERVER_IP, SERVER_PORT))
