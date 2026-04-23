# MITM Operator Console

A lab-only educational network security project demonstrating LAN host discovery, ARP monitoring, packet capture, and protocol/flow analysis in an isolated virtual environment.

## Project Features

- Host discovery with ARP scanning
- Host storage in SQLite database
- ARP baseline capture
- Live ARP monitoring
- ARP change detection
- ARP event logging to file
- ARP event storage in database
- Packet capture to PCAP
- PCAP readback and summary
- Flow statistics plugin
- Flask-based dashboard

## Dashboard Pages

- `/` Home
- `/hosts` Discovered hosts
- `/arp-events` ARP event history
- `/plugins/flow-stats` Flow statistics

## Lab Topology

- Gateway VM: `192.168.255.1`
- Victim VM: `192.168.255.10`
- Attacker VM: `192.168.255.20`

## Tech Stack

- Python 3
- Scapy
- Flask
- SQLAlchemy
- SQLite
- VirtualBox
- Kali Linux / Linux VMs

## Notes

This project is intended strictly for an isolated educational lab environment.
