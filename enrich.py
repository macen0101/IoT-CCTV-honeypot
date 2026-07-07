import time
import json
import os
import queue
import threading
import requests
from dotenv import load_dotenv

# ---------------- Configuration ----------------
RAW_LOG_FILE = 'iot_honeypot.log'
ENRICHED_LOG_FILE = 'enriched_threats.json'

load_dotenv()
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

if not ABUSEIPDB_API_KEY:
    print("[Critical Error] ABUSEIPDB_API_KEY not found in .env file.")
    print("Please create a .env file with 'ABUSEIPDB_API_KEY=your_key_here'")
    exit(1)


# Rule 1: Brute Force Thresholds (5 seconds window, 20 attempts)
BF_WINDOW_SECONDS = 5
BF_THRESHOLD_ATTEMPTS = 20

login_tracker = {}
log_queue = queue.Queue()

# ---------------- 1. Producer Thread: Real-time Log Monitoring ----------------
def log_tailer():
    print("[Thread-A] Log Monitor Service initiated successfully.")
    if not os.path.exists(RAW_LOG_FILE):
        open(RAW_LOG_FILE, 'a').close()
        
    with open(RAW_LOG_FILE, 'r', encoding='utf-8') as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            log_queue.put(line.strip())

# ---------------- 2. Core Analysis & Context Correlation Engine ----------------

def fetch_geoip(ip):
    try:
        if ip.startswith(('127.', '192.168.', '10.', '172.')):
            return "Local-Network", "Private-IP"
            
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                return data.get('country', 'Unknown'), data.get('isp', 'Unknown')
    except Exception as e:
        print(f"[Warning: GeoIP Lookup Failure] Unable to trace attributes for IP {ip}: {e}")
    return "Unknown", "Unknown"

def fetch_abuseipdb_score(ip):
    if ip.startswith(('127.', '192.168.', '10.', '172.')) or ABUSEIPDB_API_KEY == "YOUR_ABUSEIPDB_API_KEY_HERE":
        return 0
    
    url = 'https://api.abuseipdb.com/api/v2/check'
    querystring = {'ipAddress': ip, 'maxAgeInDays': '90'}
    headers = {'Accept': 'application/json', 'Key': ABUSEIPDB_API_KEY}
    
    try:
        response = requests.get(url, headers=headers, params=querystring, timeout=4)
        if response.status_code == 200:
            res_json = response.json()
            return res_json.get('data', {}).get('abuseConfidenceScore', 0)
    except Exception as e:
        print(f"[Warning: AbuseIPDB Error] Failed reputation query for {ip}: {e}")
    return 0

def analyze_threat_type(raw_event):
    ip = raw_event.get('attacker_ip', '')
    url = raw_event.get('requested_url', '').lower()
    username = raw_event.get('username', '').lower()
    password = raw_event.get('password', '').lower()
    method = raw_event.get('method', '')
    
    combined_payload = url + " " + username + " " + password
    
    # Rule 2: Vulnerability Attack (SQLi & Command Injection Payloads)
    web_vuln_keywords = [
        "'", "or", "and", "union", "select", "--", "#", "/*", 
        "cat ", "ping ", "wget ", "curl ", "uname", "id", ";", "&&", "||"
    ]
    if any(keyword in combined_payload for keyword in web_vuln_keywords):
        return "Vulnerability Attack"
        
    # Rule 1: Brute Force Attack Correlation (5s window, same IP, 20 attempts)
    if method == "POST" and (username != "" or password != ""):
        current_time = time.time()
        if ip not in login_tracker:
            login_tracker[ip] = []
        
        login_tracker[ip].append(current_time)
        login_tracker[ip] = [t for t in login_tracker[ip] if current_time - t <= BF_WINDOW_SECONDS]
        
        if len(login_tracker[ip]) >= BF_THRESHOLD_ATTEMPTS:
            return "Brute Force Attack"
        else:
            return "Suspicious Login Attempt"

    # Rule 3: Directory and Vulnerability Scanning
    scanning_sensitive_paths = [
        "/shell.php", "/.env", "/wp-admin", "/wp-login.php", 
        "/config", "/admin", "/backup", "/etc/passwd", ".git"
    ]
    if any(path in url for path in scanning_sensitive_paths):
        return "Directory/Vulnerability Scanning"

    return "General Reconnaissance"

# ---------------- 3. Consumer Thread: Threat Context Enrichment ----------------
def threat_intelligence_engine():
    print("[Thread-B] Threat Intelligence Aggregator & Enrichment Engine live.")
    
    while True:
        try:
            raw_line = log_queue.get(block=True)
            raw_event = json.loads(raw_line)
            ip = raw_event.get('attacker_ip')
            
            print(f"\n[Ingesting Event] Processing telemetry from source IP: {ip}...")
            
            country, isp = fetch_geoip(ip)
            abuse_score = fetch_abuseipdb_score(ip)
            threat_type = analyze_threat_type(raw_event)
            
            enriched_entry = {
                "timestamp": raw_event.get('timestamp'),
                "attacker_ip": ip,
                "country": country,
                "isp": isp,
                "method": raw_event.get('method'),
                "requested_url": raw_event.get('requested_url'),
                "username": raw_event.get('username'),
                "password": raw_event.get('password'),
                "user_agent": raw_event.get('user_agent'),
                "threat_type": threat_type,
                "abuse_score": abuse_score
            }
            
            with open(ENRICHED_LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(json.dumps(enriched_entry) + '\n')
                f.flush()
                
            print(f"[Event Triaged] {ip} ({country}) | Abuse Score: {abuse_score}% -> Classified As: {threat_type}")
            log_queue.task_done()
            
        except Exception as e:
            print(f"[Processing Engine Exception] Error handling log pipeline task: {e}")

if __name__ == '__main__':
    print("====== Dahua Honeypot Threat Intelligence Pipeline Daemon ======")
    t_tailer = threading.Thread(target=log_tailer, daemon=True)
    t_tailer.start()
    t_engine = threading.Thread(target=threat_intelligence_engine, daemon=True)
    t_engine.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nTermination request intercepted. Threat Intel Daemon shutting down cleanly.")
