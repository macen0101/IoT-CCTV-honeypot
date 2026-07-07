import streamlit as st
import pandas as pd
import json
import os
import folium
import time
from streamlit_folium import st_folium

st.set_page_config(page_title="IoT CCTV Honeypot Enterprise SOC Dashboard", layout="wide")

st.title("IoT CCTV Honeypot - Enterprise Cyber Threat Intelligence Dashboard")
st.markdown("---")

ENRICHED_LOG_FILE = 'enriched_threats.json'

def load_data():
    if not os.path.exists(ENRICHED_LOG_FILE):
        return pd.DataFrame()
    
    data = []
    with open(ENRICHED_LOG_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                data.append(json.loads(line.strip()))
    return pd.DataFrame(data)

df = load_data()

if df.empty:
    st.info("No threat intelligence data captured yet. Waiting for telemetry input...")
else:
    # ---------------- Data Post-Processing (Triage & Categorization) ----------------
    def assign_severity(threat_type):
        if "Vulnerability Attack" in threat_type: return "High"
        elif "Brute Force" in threat_type: return "Medium"
        elif "Scanning" in threat_type: return "Low"
        return "Info"
    
    df['severity'] = df['threat_type'].apply(assign_severity)

    def analyze_bot(ua):
        ua_lower = ua.lower()
        bots = ['python', 'go-http', 'nmap', 'masscan', 'zmeu', 'curl', 'wget', 'headless']
        for bot in bots:
            if bot in ua_lower: return "Automated Bot"
        return "Browser/Unknown"
    
    df['client_type'] = df['user_agent'].apply(analyze_bot)

    # ---------------- Top Section: Key Performance Indicators (KPIs) ----------------
    total_attacks = len(df)
    unique_ips = df['attacker_ip'].nunique()
    
    avg_abuse_score = df['abuse_score'].mean() if 'abuse_score' in df.columns else 0

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total Security Events", f"{total_attacks} hits")
    m2.metric("Unique Attacker IPs", f"{unique_ips} IPs")
    m3.metric("Avg Abuse Confidence (AbuseIPDB)", f"{avg_abuse_score:.1f} %")
    
    top_ip = df['attacker_ip'].value_counts().idxmax()
    top_ip_country = df[df['attacker_ip'] == top_ip]['country'].values[0]
    m4.metric("Top Threat Actor (IP)", f"{top_ip}", f"Origin: {top_ip_country}")

    st.markdown("---")

    # ---------------- Middle Section: Visualizations ----------------
    col_map, col_sev, col_threat = st.columns([4, 2, 2])

    with col_map:
        st.subheader("Live Cyber Threat Geo-Distribution")
        m = folium.Map(location=[20, 0], zoom_start=2, tiles="CartoDB dark_matter")
        
        country_geo = {
            "United States": [37.0902, -95.7129], "China": [35.8617, 104.1954],
            "Netherlands": [52.1326, 5.2913], "Germany": [51.1657, 10.4515],
            "Canada": [56.1304, -106.3468], "Hong Kong": [22.3193, 114.1694],
            "Taiwan": [23.6978, 120.9605], "Japan": [36.2048, 138.2529],
            "South Korea": [35.9078, 127.7669], "United Kingdom": [55.3781, -3.4360]
        }
        
        country_counts = df['country'].value_counts()
        for country, count in country_counts.items():
            if country in country_geo:
                folium.CircleMarker(
                    location=country_geo[country], radius=min(15, 5 + count),
                    popup=f"<b>{country}</b><br>Incident Count: {count}",
                    color="#FF4B4B", fill=True, fill_color="#FF4B4B", fill_opacity=0.6
                ).add_to(m)
        st_folium(m, width=550, height=300, returned_objects=[])

    with col_sev:
        st.subheader("Alert Triage (Severity Breakdown)")
        sev_counts = df['severity'].value_counts()
        st.bar_chart(sev_counts)

    with col_threat:
        st.subheader("Attack Vector Breakdown")
        threat_counts = df['threat_type'].value_counts()
        st.bar_chart(threat_counts)


    st.markdown("---")

    # ---------------- Bottom Section: Password Analytics & Raw Logs ----------------
    col_creds, col_raw = st.columns(2)

    with col_creds:
        st.subheader("Top 5 Credential Targets (Password Wordlist)")
        valid_passwords = df[df['password'] != '']['password'].value_counts().head(5)
        if not valid_passwords.empty:
            st.bar_chart(valid_passwords)
        else:
            st.info("No credential tracking data available yet.")

    with col_raw:
        st.subheader("Live Threat Intelligence Stream")
        with st.container(height=280):
            reversed_df = df.iloc[::-1]
            for index, row in reversed_df.iterrows():
                score_str = f"{row.get('abuse_score', 0)}%"
                log_text = f"[{row['timestamp']}] Severity: {row['severity']} | Source: {row['attacker_ip']} ({row['country']}) | AbuseIPDB: {score_str} -> {row['threat_type']}"
                st.code(log_text, language="bash")