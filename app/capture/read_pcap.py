from scapy.all import rdpcap

PCAP_FILE = "data/pcaps/test_capture.pcap"

def read_capture():
    packets = rdpcap(PCAP_FILE)
    print(f"Loaded {len(packets)} packets from {PCAP_FILE}")

if __name__ == "__main__":
    read_capture()
