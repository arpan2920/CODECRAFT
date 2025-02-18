from scapy.all import sniff, TCP, UDP, ICMP, IP, Raw

def packet_callback(packet):

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if packet.haslayer(TCP):
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
            src_port = ""
            dst_port = ""
        else:
            protocol = "Other"
            src_port = ""
            dst_port = ""

        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")
        print(f"Protocol: {protocol}")
        print(f"Source Port: {src_port}")
        print(f"Destination Port: {dst_port}")

        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print(f"Payload: {payload}")

        print("------------------------")

def main():
    sniff(prn=packet_callback, count=0)

if __name__ == "__main__":
    main()