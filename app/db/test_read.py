from app.db.database import SessionLocal
from app.db.models import Host

def read_hosts():
    db = SessionLocal()
    hosts = db.query(Host).all()

    for host in hosts:
        print(f"ID={host.id}, IP={host.ip_address}, MAC={host.mac_address}, HOSTNAME={host.hostname}")

    db.close()

if __name__ == "__main__":
    read_hosts()
