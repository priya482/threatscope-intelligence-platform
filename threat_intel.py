import requests
import json
import os
from datetime import datetime
from dotenv import load_dotenv

# Load API keys from .env file
load_dotenv()
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

# Test that keys loaded correctly
print("VirusTotal Key loaded:", "Yes" if VT_API_KEY else "No")
print("AbuseIPDB Key loaded:", "Yes" if ABUSEIPDB_API_KEY else "No")

def check_virustotal(ip_address):
    print(f"\n[*] Checking VirusTotal for: {ip_address}")
    
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"x-apikey": VT_API_KEY}
    
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        total = malicious + suspicious + harmless
        
        country = data["data"]["attributes"].get("country", "Unknown")
        
        print(f"  Country: {country}")
        print(f"  Malicious votes: {malicious}/{total} vendors")
        print(f"  Suspicious votes: {suspicious}/{total} vendors")
        
        if malicious > 5:
            verdict = "MALICIOUS"
        elif malicious > 0 or suspicious > 0:
            verdict = "SUSPICIOUS"
        else:
            verdict = "CLEAN"
            
        print(f"  Verdict: {verdict}")
        return verdict, malicious, country
    else:
        print(f"  Error: {response.status_code}")
        return "UNKNOWN", 0, "Unknown"



def check_abuseipdb(ip_address):
    print(f"\n[*] Checking AbuseIPDB for: {ip_address}")
    
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip_address, "maxAgeInDays": 90}
    
    response = requests.get(url, headers=headers, params=params)
    
    if response.status_code == 200:
        data = response.json()["data"]
        
        abuse_score = data["abuseConfidenceScore"]
        total_reports = data["totalReports"]
        last_reported = data["lastReportedAt"]
        isp = data["isp"]
        usage_type = data["usageType"]
        
        print(f"  ISP: {isp}")
        print(f"  Usage Type: {usage_type}")
        print(f"  Abuse Score: {abuse_score}/100")
        print(f"  Total Reports: {total_reports}")
        print(f"  Last Reported: {last_reported}")
        
        if abuse_score >= 80:
            verdict = "HIGH RISK"
        elif abuse_score >= 40:
            verdict = "MEDIUM RISK"
        else:
            verdict = "LOW RISK"
            
        print(f"  Risk Level: {verdict}")
        return verdict, abuse_score, total_reports
    else:
        print(f"  Error: {response.status_code}")
        return "UNKNOWN", 0, 0



def map_mitre_attack(isp, abuse_score, total_reports):
    print(f"\n[*] MITRE ATT&CK Mapping...")
    
    techniques = []
    
    # Tor exit node = Defense Evasion
    if "tor" in isp.lower():
        techniques.append({
            "id": "T1090.003",
            "name": "Proxy: Multi-hop Proxy",
            "tactic": "Defense Evasion",
            "description": "Attacker used Tor to hide true origin"
        })
    
    # High abuse score = likely scanning/brute force
    if abuse_score >= 80:
        techniques.append({
            "id": "T1110.001", 
            "name": "Brute Force: Password Guessing",
            "tactic": "Credential Access",
            "description": "IP associated with credential attacks"
        })
    
    # Many reports = reconnaissance
    if total_reports >= 50:
        techniques.append({
            "id": "T1595",
            "name": "Active Scanning",
            "tactic": "Reconnaissance", 
            "description": "IP reported for scanning activity"
        })
    
    for t in techniques:
        print(f"  [{t['tactic']}] {t['id']} - {t['name']}")
        print(f"  -> {t['description']}")
    
    return techniques
def analyze_ioc(ip_address):
    print("\n" + "="*65)
    print("   THREAT INTELLIGENCE PLATFORM")
    print("   Analyst: Priyanshi Dhokiya")
    print(f"   Target: {ip_address}")
    print(f"   Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*65)
    
    # Run all checks
    vt_verdict, vt_malicious, country = check_virustotal(ip_address)
    ab_verdict, abuse_score, total_reports = check_abuseipdb(ip_address)
    techniques = map_mitre_attack(
        "tor" if abuse_score == 100 else "commercial",
        abuse_score,
        total_reports
    )
    
    # Calculate overall risk
    if vt_malicious >= 10 or abuse_score >= 80:
        overall_risk = "CRITICAL"
        action = "BLOCK IMMEDIATELY — Escalate to senior analyst"
    elif vt_malicious >= 5 or abuse_score >= 40:
        overall_risk = "HIGH"
        action = "INVESTIGATE — Monitor all traffic from this IP"
    else:
        overall_risk = "LOW"
        action = "MONITOR — Add to watchlist"
    
    # Print final summary
    print("\n" + "="*65)
    print("THREAT INTELLIGENCE SUMMARY")
    print("="*65)
    print(f"IP Address:      {ip_address}")
    print(f"Country:         {country}")
    print(f"VT Verdict:      {vt_verdict} ({vt_malicious} malicious vendors)")
    print(f"Abuse Score:     {abuse_score}/100 ({total_reports} reports)")
    print(f"Overall Risk:    {overall_risk}")
    print(f"MITRE Techniques: {len(techniques)} mapped")
    print(f"Recommended Action: {action}")
    
    # Save report
    report_file = f"threat_report_{ip_address.replace('.','_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(report_file, 'w') as f:
        f.write(f"THREAT INTELLIGENCE REPORT\n")
        f.write(f"{'='*65}\n")
        f.write(f"Analyst: Priyanshi Dhokiya\n")
        f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Target IP: {ip_address}\n")
        f.write(f"Country: {country}\n")
        f.write(f"VirusTotal: {vt_verdict} - {vt_malicious} malicious vendors\n")
        f.write(f"AbuseIPDB: {abuse_score}/100 confidence - {total_reports} reports\n")
        f.write(f"Overall Risk: {overall_risk}\n")
        f.write(f"Action: {action}\n\n")
        f.write(f"MITRE ATT&CK TECHNIQUES:\n")
        for t in techniques:
            f.write(f"  [{t['tactic']}] {t['id']} - {t['name']}\n")
            f.write(f"  {t['description']}\n\n")
    
    print(f"\n[*] Report saved: {report_file}")
    print("="*65)

# Remove old test calls and replace with this
analyze_ioc("185.220.101.45")

def analyze_multiple_iocs(ip_list):
    print("\n" + "="*65)
    print(f"   BULK THREAT INTELLIGENCE ANALYSIS")
    print(f"   Analyst: Priyanshi Dhokiya")
    print(f"   Total IPs: {len(ip_list)}")
    print(f"   Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*65)
    
    results = []
    critical = []
    high = []
    low = []
    
    for ip in ip_list:
        result = analyze_ioc(ip)
        results.append(result)
    
    # Summary report
    summary_file = f"bulk_threat_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(summary_file, 'w') as f:
        f.write("BULK THREAT INTELLIGENCE SUMMARY\n")
        f.write("="*65 + "\n")
        f.write(f"Analyst: Priyanshi Dhokiya\n")
        f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total IPs Analyzed: {len(ip_list)}\n\n")
        for ip in ip_list:
            f.write(f"Analyzed: {ip}\n")
    
    print(f"\n[*] Bulk analysis complete")
    print(f"[*] Summary saved: {summary_file}")

# Test with multiple IPs
suspicious_ips = [
    "185.220.101.45",  # Known Tor exit node
    "8.8.8.8",         # Google DNS - should be clean
    "45.33.32.156"     # Known malicious
]

analyze_multiple_iocs(suspicious_ips)