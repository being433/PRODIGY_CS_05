from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        print(f"IP Packet: {ip_src} -> {ip_dst} (Protocol: {protocol})")

        if TCP in packet:
            tcp_sport = packet[TCP].sport
            tcp_dport = packet[TCP].dport
            payload = bytes(packet[TCP].payload).decode('utf-8', errors='ignore')

            print(f"TCP Segment: {ip_src}:{tcp_sport} -> {ip_dst}:{tcp_dport}")
            print(f"Payload: {payload}\n")

        elif UDP in packet:
            udp_sport = packet[UDP].sport
            udp_dport = packet[UDP].dport
            payload = bytes(packet[UDP].payload).decode('utf-8', errors='ignore')

            print(f"UDP Datagram: {ip_src}:{udp_sport} -> {ip_dst}:{udp_dport}")
            print(f"Payload: {payload}\n")
print("Starting packet sniffer...")
sniff(prn=packet_callback, store=0)
