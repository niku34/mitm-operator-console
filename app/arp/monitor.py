from scapy.all import sniff, ARP

def process_arp(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        print(
            f"ARP Reply: {packet[ARP].psrc} is-at {packet[ARP].hwsrc} "
            f"-> target {packet[ARP].pdst}"
        )

def start_arp_monitor():
    print("Starting ARP monitor... Press Ctrl+C to stop.")
    sniff(filter="arp", prn=process_arp, store=False)

if __name__ == "__main__":
    start_arp_monitor()
