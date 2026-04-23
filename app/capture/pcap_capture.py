from scapy.all import sniff, wrpcap

PCAP_FILE = "data/pcaps/test_capture.pcap"

def capture_packets(packet_count=20):
    print(f"Capturing {packet_count} packets...")
    packets = sniff(count=packet_count)
    wrpcap(PCAP_FILE, packets)
    print(f"Saved capture to {PCAP_FILE}")

if __name__ == "__main__":
    capture_packets()
