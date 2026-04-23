from collections import Counter
from scapy.all import rdpcap, ARP, IP, TCP, UDP, ICMP

PCAP_FILE = "data/pcaps/test_capture.pcap"

def summarize_capture():
    packets = rdpcap(PCAP_FILE)
    proto_counts = Counter()
    flow_counts = Counter()

    for pkt in packets:
        if pkt.haslayer(ARP):
            proto_counts["ARP"] += 1
        elif pkt.haslayer(ICMP):
            proto_counts["ICMP"] += 1
        elif pkt.haslayer(TCP):
            proto_counts["TCP"] += 1
        elif pkt.haslayer(UDP):
            proto_counts["UDP"] += 1
        elif pkt.haslayer(IP):
            proto_counts["IP_OTHER"] += 1
        else:
            proto_counts["OTHER"] += 1

        if pkt.haslayer(IP):
            src = pkt[IP].src
            dst = pkt[IP].dst
            flow_counts[f"{src} -> {dst}"] += 1

    print(f"Summary for {PCAP_FILE}")
    print("")
    print("Protocol Counts:")
    for proto, count in proto_counts.items():
        print(f"{proto}: {count}")

    print("")
    print("Top Flows:")
    for flow, count in flow_counts.most_common(10):
        print(f"{flow}: {count}")

if __name__ == "__main__":
    summarize_capture()
