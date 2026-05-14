import streamlit as st
import requests
import os
import plotly.graph_objects as go
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

try:
    VT_API_KEY = st.secrets["VIRUSTOTAL_API_KEY"]
    ABUSEIPDB_API_KEY = st.secrets["ABUSEIPDB_API_KEY"]
    st.sidebar.success("Keys loaded from Streamlit secrets")
except Exception as e:
    VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
    st.sidebar.error(f"Secrets error: {e}")

st.set_page_config(
    page_title="ThreatScope | Cyber Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=Rajdhani:wght@300;400;600;700&display=swap');
* { font-family: 'Rajdhani', sans-serif; }
.stApp { background: #080c14; }
.hero {
    background: linear-gradient(135deg, #080c14 0%, #0d1821 50%, #080c14 100%);
    border: 1px solid #1a2744;
    border-radius: 16px;
    padding: 40px;
    margin-bottom: 30px;
}
.hero-title { font-size: 3em; font-weight: 700; color: #ffffff; letter-spacing: 4px; margin: 0; text-transform: uppercase; }
.hero-title span { color: #00d4ff; }
.hero-sub { color: #4a6fa5; font-size: 1em; letter-spacing: 3px; text-transform: uppercase; margin-top: 8px; font-family: 'Space Mono', monospace; }
.risk-banner { padding: 24px 30px; border-radius: 12px; margin: 20px 0; border: 1px solid; }
.risk-critical { background: rgba(255,30,30,0.08); border-color: #ff1e1e; }
.risk-high { background: rgba(255,140,0,0.08); border-color: #ff8c00; }
.risk-low { background: rgba(0,212,100,0.08); border-color: #00d464; }
.risk-label { font-size: 1.8em; font-weight: 700; letter-spacing: 3px; text-transform: uppercase; font-family: 'Space Mono', monospace; }
.risk-critical .risk-label { color: #ff1e1e; }
.risk-high .risk-label { color: #ff8c00; }
.risk-low .risk-label { color: #00d464; }
.risk-action { color: #8899aa; font-size: 0.95em; margin-top: 6px; letter-spacing: 1px; }
.data-card { background: #0d1821; border: 1px solid #1a2744; border-radius: 12px; padding: 24px; height: 100%; }
.data-card-title { color: #4a6fa5; font-size: 0.75em; letter-spacing: 3px; text-transform: uppercase; font-family: 'Space Mono', monospace; margin-bottom: 8px; }
.data-card-value { color: #ffffff; font-size: 1.8em; font-weight: 700; letter-spacing: 1px; }
.mitre-card { background: #0d1821; border: 1px solid #1a2744; border-left: 4px solid #00d4ff; border-radius: 0 12px 12px 0; padding: 18px 24px; margin-bottom: 12px; }
.mitre-id { color: #00d4ff; font-family: 'Space Mono', monospace; font-size: 0.85em; font-weight: 700; }
.mitre-name { color: #ffffff; font-size: 1.1em; font-weight: 600; }
.mitre-tactic { color: #4a6fa5; font-size: 0.8em; letter-spacing: 2px; text-transform: uppercase; }
.mitre-desc { color: #667788; font-size: 0.9em; margin-top: 4px; }
.stTextInput > div > div > input { background: #0d1821 !important; border: 1px solid #1a2744 !important; border-radius: 8px !important; color: #ffffff !important; font-family: 'Space Mono', monospace !important; font-size: 1em !important; padding: 14px 18px !important; }
.stTextInput > div > div > input:focus { border-color: #00d4ff !important; box-shadow: 0 0 0 2px rgba(0,212,255,0.15) !important; }
.stButton > button { background: linear-gradient(135deg, #00d4ff, #0088cc) !important; color: #000000 !important; font-family: 'Rajdhani', sans-serif !important; font-weight: 700 !important; font-size: 1em !important; letter-spacing: 2px !important; text-transform: uppercase !important; border: none !important; border-radius: 8px !important; padding: 14px 28px !important; width: 100% !important; }
.section-header { color: #4a6fa5; font-size: 0.75em; letter-spacing: 3px; text-transform: uppercase; font-family: 'Space Mono', monospace; border-bottom: 1px solid #1a2744; padding-bottom: 12px; margin: 30px 0 20px 0; }
.stDownloadButton > button { background: transparent !important; border: 1px solid #1a2744 !important; color: #4a6fa5 !important; font-family: 'Space Mono', monospace !important; font-size: 0.8em !important; letter-spacing: 2px !important; border-radius: 8px !important; }
.stDownloadButton > button:hover { border-color: #00d4ff !important; color: #00d4ff !important; }
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="hero">
    <div class="hero-title">THREAT<span>SCOPE</span></div>
    <div class="hero-sub">Cyber Threat Intelligence Platform &nbsp;|&nbsp; Priyanshi Dhokiya &nbsp;|&nbsp; Real-Time IOC Analysis</div>
</div>
""", unsafe_allow_html=True)

col_in, col_btn = st.columns([5, 1])
with col_in:
    ip_input = st.text_input("IP Address", placeholder="Enter target IP address...", label_visibility="collapsed")
with col_btn:
    analyze = st.button("ANALYZE", type="primary")

st.markdown("<div style='height:20px'></div>", unsafe_allow_html=True)

if analyze and ip_input:
    with st.spinner(f"Interrogating threat databases for {ip_input}..."):
        vt_res = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip_input.strip()}",
            headers={"x-apikey": VT_API_KEY.strip()}
        )
        ab_res = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_API_KEY.strip(), "Accept": "application/json"},
            params={"ipAddress": ip_input.strip(), "maxAgeInDays": 90}
        )

        if vt_res.status_code == 200 and ab_res.status_code == 200:
            vt = vt_res.json()["data"]["attributes"]
            ab = ab_res.json()["data"]

            stats = vt["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            total = malicious + suspicious + harmless
            country = vt.get("country", "Unknown")

            abuse_score = ab["abuseConfidenceScore"]
            total_reports = ab["totalReports"]
            isp = ab["isp"]
            usage_type = ab["usageType"]
            last_reported = ab.get("lastReportedAt", "Never")[:10] if ab.get("lastReportedAt") else "Never"

            if malicious > 5 or abuse_score >= 80:
                risk = "CRITICAL"
                risk_class = "risk-critical"
                action = "BLOCK IMMEDIATELY — Escalate to senior analyst"
            elif malicious > 0 or abuse_score >= 40:
                risk = "HIGH"
                risk_class = "risk-high"
                action = "INVESTIGATE — Monitor all traffic from this source"
            else:
                risk = "LOW"
                risk_class = "risk-low"
                action = "MONITOR — Add to threat watchlist"

            st.markdown(f"""
            <div class="risk-banner {risk_class}">
                <div class="risk-label">{risk} THREAT — {ip_input}</div>
                <div class="risk-action">▶ {action}</div>
            </div>
            """, unsafe_allow_html=True)

            c1, c2, c3, c4, c5, c6 = st.columns(6)
            with c1:
                st.markdown(f'<div class="data-card"><div class="data-card-title">Country</div><div class="data-card-value">{country}</div></div>', unsafe_allow_html=True)
            with c2:
                st.markdown(f'<div class="data-card"><div class="data-card-title">Malicious</div><div class="data-card-value">{malicious}/{total}</div></div>', unsafe_allow_html=True)
            with c3:
                st.markdown(f'<div class="data-card"><div class="data-card-title">Abuse Score</div><div class="data-card-value">{abuse_score}/100</div></div>', unsafe_allow_html=True)
            with c4:
                st.markdown(f'<div class="data-card"><div class="data-card-title">Reports</div><div class="data-card-value">{total_reports}</div></div>', unsafe_allow_html=True)
            with c5:
                st.markdown(f'<div class="data-card"><div class="data-card-title">Last Seen</div><div class="data-card-value" style="font-size:1.2em">{last_reported}</div></div>', unsafe_allow_html=True)
            with c6:
                st.markdown(f'<div class="data-card"><div class="data-card-title">Usage</div><div class="data-card-value" style="font-size:1em">{usage_type[:12]}</div></div>', unsafe_allow_html=True)

            st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)

            col_l, col_r = st.columns(2)

            with col_l:
                st.markdown('<div class="section-header">VIRUSTOTAL — VENDOR ANALYSIS</div>', unsafe_allow_html=True)
                fig1 = go.Figure(data=[go.Pie(
                    labels=["Malicious", "Suspicious", "Harmless"],
                    values=[max(malicious, 0.1), max(suspicious, 0.1), max(harmless, 0.1)],
                    hole=0.6,
                    marker_colors=["#ff1e1e", "#ff8c00", "#00d464"],
                    textfont=dict(family="Space Mono", color="white"),
                )])
                fig1.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    font=dict(color="white", family="Rajdhani"),
                    height=280,
                    margin=dict(t=10, b=10, l=10, r=10),
                    legend=dict(bgcolor="rgba(0,0,0,0)", font=dict(color="#8899aa"))
                )
                fig1.add_annotation(
                    text=f"<b>{malicious}</b><br>MALICIOUS",
                    x=0.5, y=0.5, showarrow=False,
                    font=dict(size=16, color="#ff1e1e", family="Space Mono")
                )
                st.plotly_chart(fig1, use_container_width=True)

            with col_r:
                st.markdown('<div class="section-header">ABUSEIPDB — RISK GAUGE</div>', unsafe_allow_html=True)
                gauge_color = "#ff1e1e" if abuse_score >= 80 else "#ff8c00" if abuse_score >= 40 else "#00d464"
                fig2 = go.Figure(go.Indicator(
                    mode="gauge+number",
                    value=abuse_score,
                    number={"font": {"color": gauge_color, "family": "Space Mono", "size": 36}},
                    gauge={
                        "axis": {"range": [0, 100], "tickcolor": "#1a2744",
                                 "tickfont": {"color": "#4a6fa5", "family": "Space Mono", "size": 10}},
                        "bar": {"color": gauge_color, "thickness": 0.3},
                        "bgcolor": "rgba(0,0,0,0)",
                        "bordercolor": "#1a2744",
                        "steps": [
                            {"range": [0, 40], "color": "rgba(0,212,100,0.1)"},
                            {"range": [40, 80], "color": "rgba(255,140,0,0.1)"},
                            {"range": [80, 100], "color": "rgba(255,30,30,0.1)"}
                        ],
                    }
                ))
                fig2.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)",
                    font=dict(color="white", family="Rajdhani"),
                    height=280,
                    margin=dict(t=30, b=10, l=30, r=30)
                )
                st.plotly_chart(fig2, use_container_width=True)

            st.markdown(f"""
            <div style="background:#0d1821; border:1px solid #1a2744; border-radius:10px; padding:16px 24px; margin-bottom:20px;">
            <span style="color:#4a6fa5; font-family:'Space Mono',monospace; font-size:0.75em; letter-spacing:2px;">ISP</span>
            <span style="color:#ffffff; font-size:1.1em; font-weight:600; margin-left:20px;">{isp}</span>
            </div>
            """, unsafe_allow_html=True)

            st.markdown('<div class="section-header">MITRE ATT&CK MAPPING</div>', unsafe_allow_html=True)

            techniques = []
            if "tor" in isp.lower():
                techniques.append(("T1090.003", "Proxy: Multi-hop Proxy", "Defense Evasion", "Attacker used Tor network to anonymize origin"))
            if abuse_score >= 80:
                techniques.append(("T1110.001", "Brute Force: Password Guessing", "Credential Access", "IP strongly associated with credential-based attacks"))
            if total_reports >= 50:
                techniques.append(("T1595", "Active Scanning", "Reconnaissance", "IP has been widely reported for scanning activity"))
            if malicious > 10:
                techniques.append(("T1071", "Application Layer Protocol", "Command and Control", "High malicious score indicates potential C2 activity"))

            if techniques:
                for tid, tname, tactic, desc in techniques:
                    st.markdown(f"""
                    <div class="mitre-card">
                        <div style="display:flex; align-items:center; gap:16px; flex-wrap:wrap;">
                            <span class="mitre-id">{tid}</span>
                            <span class="mitre-name">{tname}</span>
                            <span class="mitre-tactic">{tactic}</span>
                        </div>
                        <div class="mitre-desc">{desc}</div>
                    </div>
                    """, unsafe_allow_html=True)
            else:
                st.markdown("""
                <div class="mitre-card" style="border-left-color:#00d464">
                    <span class="mitre-name" style="color:#00d464">No techniques mapped — IP appears benign</span>
                </div>
                """, unsafe_allow_html=True)

            st.markdown('<div class="section-header">EXPORT REPORT</div>', unsafe_allow_html=True)
            report = f"""THREATSCOPE — THREAT INTELLIGENCE REPORT
{'='*55}
Analyst:        Priyanshi Dhokiya
Generated:      {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
Target IP:      {ip_input}
{'='*55}

VERDICT: {risk} THREAT
Action:  {action}

INTELLIGENCE SUMMARY
{'─'*55}
Country:        {country}
ISP:            {isp}
Usage Type:     {usage_type}
Last Reported:  {last_reported}

VIRUSTOTAL ANALYSIS
{'─'*55}
Malicious Vendors:   {malicious}/{total}
Suspicious Vendors:  {suspicious}/{total}
Harmless Vendors:    {harmless}/{total}

ABUSEIPDB ANALYSIS
{'─'*55}
Abuse Score:    {abuse_score}/100
Total Reports:  {total_reports}

MITRE ATT&CK TECHNIQUES
{'─'*55}
"""
            for tid, tname, tactic, desc in techniques:
                report += f"[{tactic}] {tid} — {tname}\n{desc}\n\n"

            if not techniques:
                report += "No MITRE techniques mapped.\n"

            st.download_button(
                label="⬇  EXPORT FULL REPORT (.TXT)",
                data=report,
                file_name=f"threatscope_{ip_input.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M')}.txt",
                mime="text/plain"
            )

        else:
            st.error(f"API Error — VT: {vt_res.status_code} | AbuseIPDB: {ab_res.status_code}")

elif analyze and not ip_input:
    st.warning("Enter a target IP address to begin analysis.")