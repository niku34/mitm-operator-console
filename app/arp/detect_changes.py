from scapy.all import sniff, ARP
from datetime import datetime
from app.db.database import SessionLocal
from app.db.models import ArpEvent

BASELINE = {
    "192.168.255.1": "0a:00:27:00:00:3b",
    "192.168.255.10": "08:00:27:b6:38:1e"
}

seen_mappings = {}
LOG_FILE = "logs/arp_events.log"

def save_event_to_db(timestamp, source_ip, source_mac, event_type, message):
    db = SessionLocal()
    event = ArpEvent(
        timestamp=timestamp,
        source_ip=source_ip,
        source_mac=source_mac,
        event_type=event_type,
        message=message
    )
    db.add(event)
    db.commit()
    db.close()

def log_event(source_ip, source_mac, event_type, message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {message}"
    print(line)

    with open(LOG_FILE, "a") as f:
        f.write(line + "`n")

    save_event_to_db(timestamp, source_ip, source_mac, event_type, message)

def process_arp(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc

        log_event(ip, mac, "OBSERVED", f"Observed ARP Reply: {ip} is-at {mac}")

        if ip in BASELINE and BASELINE[ip].lower() != mac.lower():
            log_event(ip, mac, "ALERT", f"ALERT: {ip} changed! Baseline MAC={BASELINE[ip]}, Observed MAC={mac}")

        if ip in seen_mappings and seen_mappings[ip].lower() != mac.lower():
            log_event(ip, mac, "WARNING", f"WARNING: Mapping changed during monitoring for {ip}! Old={seen_mappings[ip]}, New={mac}")

        seen_mappings[ip] = mac

def start_detector():
    print("Starting ARP change detector... Press Ctrl+C to stop.")
    sniff(filter="arp", prn=process_arp, store=False)

if __name__ == "__main__":
    start_detector()
