import json
import sqlite3
import datetime
import threading
import ipaddress
import urllib.request
from config import DB_FILE, THREAT_LIMIT, MAX_TRACKED_IPS, WHITELIST_IPS, RED, YELLOW, RESET
from firewall import block_ip

suspicious_ips = {}
blocked_ips = set()
geo_cache = {}
lock = threading.Lock()

def init_db():
    with lock:
        try:
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    attacker_ip TEXT,
                    target_port INTEGER,
                    detected_service TEXT,
                    country TEXT,
                    isp TEXT,
                    payload_received TEXT
                )
            """)
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[-] Database initialization error: {e}")

def get_geo_info(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback:
            return {"country": "Localhost/LAN", "isp": "Internal Network"}
    except ValueError:
        return {"country": "Unknown", "isp": "Unknown"}

    with lock:
        if ip in geo_cache:
            return geo_cache[ip]

    try:
        url = f"https://ipapi.co/{ip}/json/"
        req = urllib.request.Request(url, headers={'User-Agent': 'SHADOW-TRAP/1.0'})
        with urllib.request.urlopen(req, timeout=3) as response:
            data = json.loads(response.read().decode())
            geo_data = {
                "country": data.get("country_name") or "Unknown",
                "isp": data.get("org") or "Unknown"
            }
            with lock:
                geo_cache[ip] = geo_data
            return geo_data
    except Exception:
        pass
    
    return {"country": "Unknown", "isp": "Unknown"}

def log_incident(ip, port, service, payload, geo):
    safe_payload = (payload[:500] + " [TRUNCATED]") if len(payload) > 500 else payload
    timestamp = datetime.datetime.now().isoformat()
    
    with lock:
        try:
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO incidents (timestamp, attacker_ip, target_port, detected_service, country, isp, payload_received)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (timestamp, ip, port, service, geo["country"], geo["isp"], safe_payload))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[-] Error writing to database: {e}")

def assess_threat(ip, points, action_description, port, service, payload):
    geo = get_geo_info(ip)
    log_incident(ip, port, service, payload, geo)

    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback or ip in WHITELIST_IPS:
            return
    except ValueError:
        return

    with lock:
        if ip in blocked_ips:
            return

        if len(suspicious_ips) >= MAX_TRACKED_IPS:
            discarded_ip = next(iter(suspicious_ips))
            suspicious_ips.pop(discarded_ip, None)

        suspicious_ips[ip] = suspicious_ips.get(ip, 0) + points
        current_score = suspicious_ips[ip]

        print(f"{YELLOW}[*] Threat analysis for {ip}: +{points} pts ({action_description}) | Total: {current_score}/{THREAT_LIMIT}{RESET}")

        if current_score >= THREAT_LIMIT:
            blocked_ips.add(ip)
            print(f"{RED}[🔥] Threat threshold reached for {ip}. Engaging firewall block!{RESET}")
            block_ip(ip)