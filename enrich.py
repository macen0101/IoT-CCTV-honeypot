import time
import json
import requests

def watch_log():
    with open('/var/log/iot_honeypot.log', 'r') as f:
        f.seek(0, 2)
        
        print("SOC Automation Script is running... Waiting for attacker logs...")
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue

            try:
                log_data = json.loads(line)
                attacker_ip = log_data['attacker_ip']
                print(f"🔥 Detected Attack from IP: {attacker_ip}!")
                
                
            except Exception as e:
                print(f"Error parsing log: {e}")

if __name__ == "__main__":
    watch_log()