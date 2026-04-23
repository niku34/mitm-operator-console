from sqlalchemy import Column, Integer, String
from app.db.database import Base

class Host(Base):
    __tablename__ = "hosts"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, unique=True, index=True, nullable=False)
    mac_address = Column(String, unique=True, nullable=False)
    hostname = Column(String, nullable=True)

class ArpEvent(Base):
    __tablename__ = "arp_events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(String, nullable=False)
    source_ip = Column(String, nullable=False)
    source_mac = Column(String, nullable=False)
    event_type = Column(String, nullable=False)
    message = Column(String, nullable=False)
