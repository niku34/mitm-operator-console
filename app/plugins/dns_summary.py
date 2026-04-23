from collections import Counter
from scapy.all import rdpcap, DNS, DNSQR

def run(pcap_file):
    packets = rdpcap(pcap_file)
    dns_queries = Counter()

    for pkt in packets:
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            try:
                query_name = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
                dns_queries[query_name] += 1
            except Exception:
                pass

    return {
        "top_dns_queries": dict(dns_queries.most_common(10))
    }

if __name__ == "__main__":
    result = run("data/pcaps/test_capture.pcap")
    print(result)
