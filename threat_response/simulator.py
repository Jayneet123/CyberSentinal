# threat_response/simulator.py
import uuid
from datetime import datetime

BAD_IPS = {
    "103.70.115.121", "42.0.129.10", "204.44.110.203", "15.235.151.18",
    "107.175.62.236", "146.59.45.160", "117.86.57.177", "42.0.129.145",
    "140.237.86.152", "42.0.129.182", "171.211.48.35", "175.165.144.206",
    "118.120.230.109", "42.6.176.117", "121.232.99.179", "34.85.112.44",
    "103.149.28.83", "103.149.28.174", "42.0.129.83", "103.149.29.13",
    "172.233.115.32", "42.6.177.92", "34.146.250.104", "23.226.136.178",
    "160.191.52.44"
} 

def simulate_response(event: dict) -> dict:
    ip = event.get("ip_address")
    action = event.get("action", "").lower()
    msg = event.get("message_summary", "").lower()
    
    plan = []
    confidence = 0.8

    if ip in BAD_IPS:
        plan.append(f"Block IP {ip} at firewall")
        confidence = 0.95
    if "failed password" in msg or "multiple failed sudo" in msg:
        plan.append("Lock affected account temporarily")
    if "database" in msg:
        plan.append("Revoke DB user credentials")
        plan.append("Rotate database passwords")
    plan.append("Alert SOC team")
    
    return {
        "response_id": str(uuid.uuid4()),
        "event_id": event.get("event_id", "unknown"),
        "timestamp": datetime.utcnow().isoformat(),
        "actions": plan,
        "confidence": confidence,
        "simulation": f"Simulated {len(plan)} actions for IP {ip}"
    }
