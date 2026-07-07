import subprocess
import sys
import time

def run_services():
    services = [
        [sys.executable, "honeypot.py"],
        [sys.executable, "enrich.py"],
        ["streamlit", "run", "dashboard.py"]
    ]
    
    processes = []
    try:
        print("--- Initiating Full Honeypot Suite ---")
        for cmd in services:
            p = subprocess.Popen(cmd)
            processes.append(p)
            print(f"[Started] {' '.join(cmd)}")
            
        print("--- Suite is live. Press Ctrl+C to terminate all services. ---")
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n--- Terminating all services ---")
        for p in processes:
            p.terminate()
        print("All services shut down cleanly.")

if __name__ == "__main__":
    run_services()
