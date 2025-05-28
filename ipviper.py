import requests
import json
import ipaddress  # ← for IP validation
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from datetime import datetime

from dotenv import load_dotenv
import os

load_dotenv()  # load .env file

VT_API_KEY = os.getenv("VT_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
IPINFO_TOKEN = os.getenv("IPINFO_TOKEN")

def is_result_valid(text):
    return not text.strip().startswith("🔴") and len(text.strip()) > 0

# === Validate IP ===
def get_user_ip():
    while True:
        user_input = input("Enter an IP address to analyze: ").strip()
        try:
            ip = ipaddress.ip_address(user_input)
            return str(ip)
        except ValueError:
            print("👽 Nice try, HACKER xD\n")

# === API Functions ===

def get_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        return "🔴 VirusTotal: This IP has not been found.\n"

    data = response.json().get("data", {})
    attributes = data.get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    comments_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/comments?limit=10"
    comments_resp = requests.get(comments_url, headers=headers).json()
    comments_text = [c['attributes']['text'] for c in comments_resp.get('data', [])]

    resolutions_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/resolutions?limit=10"
    resolutions_resp = requests.get(resolutions_url, headers=headers).json()
    resolutions = resolutions_resp.get("data", [])
    resolution_lines = [
        f"{r['attributes']['host_name']} (last resolved: {r['attributes']['date']})"
        for r in resolutions
    ]

    reputation = attributes.get("reputation", "N/A")
    tags = attributes.get("tags", [])

    result = "🛡️ VirusTotal Results:\n"
    result += f"  - Reputation Score: {reputation}\n"
    result += f"  - Malicious Detections: {stats.get('malicious', 0)} vendors\n"
    result += f"  - Tags: {', '.join(tags) if tags else 'None'}\n"
    result += f"  - Resolved Domains (up to 10):\n"
    result += "".join([f"    • {line}\n" for line in resolution_lines]) if resolution_lines else "    • None found.\n"
    result += f"  - Community Comments (up to 10):\n"
    result += "".join([f"    • {c}\n" for c in comments_text]) if comments_text else "    • No comments found.\n"

    return result

def get_abuseipdb(ip):
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&verbose=true"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        return "🔴 AbuseIPDB: This IP has not been found.\n"

    data = response.json()["data"]
    abuse_score = data['abuseConfidenceScore']
    total_reports = data['totalReports']
    country = data['countryCode']
    isp = data['isp']
    reports = data.get("reports", [])[:10]

    result = "⚠️ AbuseIPDB Results:\n"
    result += f"  - Abuse Score: {abuse_score}\n"
    result += f"  - Total Reports: {total_reports}\n"
    result += f"  - Country: {country}\n"
    result += f"  - ISP: {isp}\n"
    result += f"  - Recent Comments (up to 10):\n"
    if reports:
        for r in reports:
            if r.get("comment"):
                result += f"    • {r['comment']}\n"
    else:
        result += "    • No recent comments.\n"
    return result

def get_ipinfo(ip):
    url = f"https://ipinfo.io/{ip}?token={IPINFO_TOKEN}"
    response = requests.get(url)
    if response.status_code != 200:
        return "🔴 IPInfo: This IP has not been found.\n"

    data = response.json()
    result = "🌐 IPInfo Results:\n"
    result += f"  - IP: {data.get('ip')}\n"
    result += f"  - Org: {data.get('org')}\n"
    result += f"  - Location: {data.get('city')}, {data.get('region')}, {data.get('country')}\n"
    result += f"  - Type: {data.get('privacy', {}).get('service', 'N/A')}\n"
    return result

def export_to_pdf(ip, vt_result, abuse_result, ipinfo_result):
    filename = f"ip_report_{ip.replace('.', '_')}.pdf"
    doc = SimpleDocTemplate(filename, pagesize=A4)
    styles = getSampleStyleSheet()
    flow = []

    flow.append(Paragraph(f"<b>IP Analysis Report</b>", styles['Title']))
    flow.append(Paragraph(f"<b>IP Address:</b> {ip}", styles['Heading2']))
    flow.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    flow.append(Spacer(1, 12))

    for title, content in [
        ("VirusTotal Results", vt_result),
        ("AbuseIPDB Results", abuse_result),
        ("IPInfo Results", ipinfo_result),
    ]:
        flow.append(Paragraph(f"<b>{title}</b>", styles['Heading3']))
        for line in content.strip().split('\n'):
            flow.append(Paragraph(line.replace("•", "➤"), styles['Normal']))
        flow.append(Spacer(1, 12))

    doc.build(flow)
    print(f"📄 PDF report saved as: {filename}")

def summarize_ip(ip):
    divider = "=" * 60
    print(f"\n{divider}")
    print(f"🔍 IP Summary Report for {ip}")
    print(f"{divider}\n")

    vt_result = get_virustotal(ip)
    abuse_result = get_abuseipdb(ip)
    ipinfo_result = get_ipinfo(ip)

    print(vt_result)
    print(abuse_result)
    print(ipinfo_result)

    if any(map(is_result_valid, [vt_result, abuse_result, ipinfo_result])):
        export_to_pdf(ip, vt_result, abuse_result, ipinfo_result)
    else:
        print("ℹ️ No valid data found. PDF report not generated.")

# === Run with validated IP ===
if __name__ == "__main__":
    ip = get_user_ip()
    summarize_ip(ip)
