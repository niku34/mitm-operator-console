from scapy.all import ARP, Ether, srp

def get_mac(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    answered, _ = srp(packet, timeout=2, verbose=False)

    for _, received in answered:
        return received.hwsrc
    return None

def capture_baseline():
    hosts_to_check = {
        "gateway": "192.168.255.1",
        "victim": "192.168.255.10"
    }

    baseline = {}

    for name, ip in hosts_to_check.items():
        mac = get_mac(ip)
        baseline[name] = {
            "ip": ip,
            "mac": mac
        }

    return baseline

if __name__ == "__main__":
    baseline = capture_baseline()

    for name, info in baseline.items():
        print(f"{name.upper()} -> IP={info['ip']}, MAC={info['mac']}")
