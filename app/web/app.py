from flask import Flask
from app.db.database import SessionLocal
from app.db.models import Host, ArpEvent
from app.plugins.flow_stats import run as run_flow_stats

app = Flask(__name__)

def render_page(title, body):
    return f"""
    <html>
    <head>
        <title>{title}</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                background: #f4f7fb;
                color: #1f2937;
                margin: 0;
                padding: 0;
            }}
            .container {{
                max-width: 1000px;
                margin: 40px auto;
                background: white;
                padding: 30px;
                border-radius: 14px;
                box-shadow: 0 8px 24px rgba(0,0,0,0.08);
            }}
            h1 {{
                margin-top: 0;
                color: #0f172a;
            }}
            h2 {{
                color: #1d4ed8;
                margin-top: 28px;
            }}
            a {{
                color: #2563eb;
                text-decoration: none;
                font-weight: 600;
            }}
            a:hover {{
                text-decoration: underline;
            }}
            .nav {{
                display: flex;
                gap: 18px;
                flex-wrap: wrap;
                margin-bottom: 20px;
                padding-bottom: 15px;
                border-bottom: 1px solid #e5e7eb;
            }}
            .card {{
                background: #f8fafc;
                border: 1px solid #e5e7eb;
                border-radius: 10px;
                padding: 14px 16px;
                margin: 12px 0;
            }}
            .muted {{
                color: #6b7280;
            }}
            .badge {{
                display: inline-block;
                padding: 4px 10px;
                border-radius: 999px;
                font-size: 12px;
                font-weight: 700;
            }}
            .badge-observed {{
                background: #dbeafe;
                color: #1d4ed8;
            }}
            .badge-alert {{
                background: #fee2e2;
                color: #b91c1c;
            }}
            .badge-warning {{
                background: #fef3c7;
                color: #b45309;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            {body}
        </div>
    </body>
    </html>
    """

def event_badge(event_type):
    et = (event_type or "").upper()
    if et == "ALERT":
        return f"<span class='badge badge-alert'>{et}</span>"
    if et == "WARNING":
        return f"<span class='badge badge-warning'>{et}</span>"
    return f"<span class='badge badge-observed'>{et}</span>"

@app.route("/")
def home():
    body = """
    <h1>MITM Operator Console</h1>
    <p class="muted">LAN discovery, ARP monitoring, packet capture, and plugin summaries.</p>
    <div class="nav">
        <a href="/hosts">Hosts</a>
        <a href="/arp-events">ARP Events</a>
        <a href="/plugins/flow-stats">Flow Stats</a>
    </div>
    <div class="card">
        <strong>Project Status:</strong> Core backend and dashboard demo are working.
    </div>
    """
    return render_page("MITM Operator Console", body)

@app.route("/hosts")
def hosts():
    db = SessionLocal()
    host_rows = db.query(Host).all()
    db.close()

    body = "<h1>Discovered Hosts</h1><div class='nav'><a href='/'>Home</a></div>"
    for host in host_rows:
        body += f"""
        <div class="card">
            <strong>IP:</strong> {host.ip_address}<br>
            <strong>MAC:</strong> {host.mac_address}<br>
            <strong>Hostname:</strong> {host.hostname or "Unknown"}
        </div>
        """
    return render_page("Hosts", body)

@app.route("/arp-events")
def arp_events():
    db = SessionLocal()
    event_rows = db.query(ArpEvent).all()
    db.close()

    body = "<h1>ARP Events</h1><div class='nav'><a href='/'>Home</a></div>"
    for event in event_rows:
        body += f"""
        <div class="card">
            <strong>Time:</strong> {event.timestamp}<br>
            <strong>IP:</strong> {event.source_ip}<br>
            <strong>MAC:</strong> {event.source_mac}<br>
            <strong>Type:</strong> {event_badge(event.event_type)}<br><br>
            <strong>Message:</strong> {event.message}
        </div>
        """
    return render_page("ARP Events", body)

@app.route("/plugins/flow-stats")
def flow_stats():
    result = run_flow_stats("data/pcaps/test_capture.pcap")

    body = "<h1>Flow Stats Plugin</h1><div class='nav'><a href='/'>Home</a></div>"

    body += "<h2>Protocol Counts</h2>"
    for proto, count in result["protocol_counts"].items():
        body += f"<div class='card'><strong>{proto}</strong>: {count}</div>"

    body += "<h2>Top Flows</h2>"
    for flow, count in result["top_flows"].items():
        body += f"<div class='card'><strong>{flow}</strong>: {count}</div>"

    return render_page("Flow Stats", body)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
