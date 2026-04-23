from app.db.database import SessionLocal
from app.db.models import Host

def insert_test_host():
    db = SessionLocal()

    host = Host(
        ip_address="192.168.255.10",
        mac_address="08:00:27:b6:38:1e",
        hostname="victim"
    )

    db.add(host)
    db.commit()
    db.close()

    print("Test host inserted successfully.")

if __name__ == "__main__":
    insert_test_host()
