from scapy.all import ARP, Ether, srp
from app.db.database import SessionLocal
from app.db.models import Host

def discover_hosts(network="192.168.255.0/24"):
    arp_request = ARP(pdst=network)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    answered, _ = srp(packet, timeout=2, verbose=False)

    hosts = []
    for _, received in answered:
        hosts.append({
            "ip": received.psrc,
            "mac": received.hwsrc
        })

    return hosts

def save_hosts_to_db(hosts):
    db = SessionLocal()

    for host in hosts:
        existing_host = db.query(Host).filter_by(ip_address=host["ip"]).first()
        if not existing_host:
            new_host = Host(
                ip_address=host["ip"],
                mac_address=host["mac"],
                hostname=None
            )
            db.add(new_host)

    db.commit()
    db.close()

if __name__ == "__main__":
    results = discover_hosts()

    for host in results:
        print(f"IP={host['ip']}, MAC={host['mac']}")

    save_hosts_to_db(results)
    print("Discovered hosts saved to database.")
