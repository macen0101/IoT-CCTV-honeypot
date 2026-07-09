# Dahua IoT Honeypot & Threat Intelligence Suite

A professional, modular honeypot system designed to capture, analyze, and categorize cyberattacks targeting IoT devices.

## 🎯 Motivation
To gain visibility into the growing landscape of IoT-targeted threats—such as brute-force attacks and vulnerability scanning—this project establishes a clean, automated pipeline to capture, process, and visualize malicious traffic.

## 🚀 System Architecture
The system is built on a modular design, ensuring that data collection and analysis are decoupled for stability:

* **Honeypot Entry**: A Python-based Web Server that captures raw attack metadata (IP, credentials, request paths).
* **Enrichment Engine**: A multi-threaded, producer-consumer pipeline that performs GeoIP lookups and AbuseIPDB reputation scoring to convert raw logs into actionable threat intelligence.
* **SOC Dashboard**: A Streamlit-based interface that provides high-level security insights, including attack vector breakdowns, geographic distribution, and credential targeting patterns.

## 📂 Project Structure
```text
IoT_Honeypot/
├── static/
│   └── dahua-logo.png
├── .env                  # Environment variables (API Keys)
├── launcher.py           # Unified service orchestrator
├── honeypot_server.py    # Web server trap for IoT requests
├── enrich.py             # Threat intelligence & analysis engine
├── dashboard.py          # Visualization dashboard
├── iot_honeypot.log      # Raw traffic capture
├── Login.html 
└── enriched_threats.json # Processed intelligence data
```

## 🛠️ Technical Stack
| Component | Technology |
|---|---|
| Backend Language | Python 3.x |
| Concurrency | threading, queue, subprocess |
| Data Processing | pandas, json |
| Visualization | streamlit, folium |
| Threat Intelligence | requests (AbuseIPDB API, IP-API) |
| Configuration | python-dotenv |

## ⚡ Quick Start
1. Environment Setup
Create a .env file in the root directory:
```ABUSEIPDB_API_KEY="REPLACE_THIS_WITH_YOUR_API_KEY"```

2. Install Dependencies
Install the required Python libraries using pip:
```
pip install -r requirements.txt
```

3. Execution
Launch the entire suite using the unified controller:
```
python launcher.py
```
OR
```
python3 launcher.py
```

## 🧠 Key Engineering Features
 * Multi-threaded Processing: Uses a Producer-Consumer model to handle incoming traffic and API-based enrichment concurrently, preventing performance bottlenecks.
 * Threat Categorization: Automatically classifies traffic into Vulnerability Attacks, Brute Force, or Scanning, allowing for efficient threat triage.
 * Credential Analytics: Tracks and visualizes the most targeted passwords, providing deep insight into the attacker’s dictionary-based tactics.
 * Modular Orchestration: The launcher.py script manages the lifecycle of the honeypot, enrichment engine, and dashboard, ensuring a unified start/stop experience.

## 🛡️ Future Roadmap
 * [ ] Implement live-streaming telemetry via WebSocket or polling mechanisms.
 * [ ] Containerization (Docker Compose) for scalable deployment.
 * [ ] Automated alerting integration (Slack/Telegram).
