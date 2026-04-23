from collections import Counter
from scapy.all import rdpcap, ARP, IP, TCP, UDP, ICMP

def run(pcap_file):
    packets = rdpcap(pcap_file)
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

    return {
        "protocol_counts": dict(proto_counts),
        "top_flows": dict(flow_counts.most_common(10))
    }

if __name__ == "__main__":
    result = run("data/pcaps/test_capture.pcap")
    print(result)
