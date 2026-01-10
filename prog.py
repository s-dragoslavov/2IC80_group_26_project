import sys, argparse, time, socket
#from scapy.all import sendp, ARP, Ether

def arp_poison():
    return

def dns_spoof():
    return

def ssl_strip():
    return

parser = argparse.ArgumentParser("<name>")
subparser = parser.add_subparsers(dest='attack')

parser_arp = subparser.add_parser('arp-poison', aliases=['arp'])
parser_arp.add_argument('target_ip')
parser_arp.add_argument('-g', '--gratuitous', action='store_true')
parser_arp.set_defaults(func=arp_poison)

parser_dns = subparser.add_parser('dns-spoof', aliases=['dns'])
parser_dns.set_defaults(func=dns_spoof)

parser_ssl = subparser.add_parser('ssl-strip', aliases=['ssl'])
parser_ssl.set_defaults(func=ssl_strip)