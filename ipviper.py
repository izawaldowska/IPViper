import requests
import json
import certifi
import ipaddress
import sys
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from datetime import datetime

from dotenv import load_dotenv
import os

load_dotenv()  # load .env file

VT_API_KEY = os.getenv("VT_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")


def is_result_valid(text):
    return not text.strip().startswith("🔴") and len(text.strip()) > 0


def get_user_ips():
    if len(sys.argv) > 1:
        filename = sys.argv[1]
        try:
            with open(filename, "r") as f:
                ips = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"❌ File '{filename}' not found.")
            sys.exit(1)
    else:
        user_input = input("Enter one or more IP addresses (comma-separated): ")
        ips = [ip.strip() for ip in user_input.split(",")]

    valid_ips = []
    for ip in ips:
        try:
            ipaddress.ip_address(ip)
            valid_ips.append(ip)
        except ValueError:
            print(f"❌ Invalid IP address skipped: {ip}")
    return valid_ips


def get_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(url, headers=headers, verify=certifi.where())
    if response.status_code != 200:
        return "🔴 VirusTotal: This IP has not been found.\n"

    data = response.json().get("data", {})
    attributes = data.get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    whois = attributes.get("whois", "N/A")
    reputation = attributes.get("reputation", "N/A")
    tags = attributes.get("tags", [])

    comments_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/comments?limit=10"
    comments_resp = requests.get(comments_url, headers=headers, verify=certifi.where()).json()
    comments_text = [c['attributes']['text'] for c in comments_resp.get('data', [])]

    resolutions_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/resolutions?limit=10"
    resolutions_resp = requests.get(resolutions_url, headers=headers, verify=certifi.where()).json()
    resolutions = resolutions_resp.get("data", [])
    resolution_lines = [
        f"{r['attributes']['host_name']} (last resolved: {r['attributes']['date']})"
        for r in resolutions
    ]

    result = "🛡️ VirusTotal Results:\n"
    result += f"  - Reputation Score: {reputation}\n"
    result += f"  - Malicious Detections: {stats.get('malicious', 0)} vendors\n"
    result += f"  - Tags: {', '.join(tags) if tags else 'None'}\n"
    result += f"  - WHOIS: {whois[:300]}...\n" if whois != "N/A" else "  - WHOIS: Not available\n"
    result += f"  - Resolved Domains (up to 10):\n"
    result += "".join([f"    • {line}\n" for line in resolution_lines]) if resolution_lines else "    • None found.\n"
    result += f"  - Community Comments (up to 10):\n"
    result += "".join([f"    • {c}\n" for c in comments_text]) if comments_text else "    • No comments found.\n"

    return result


def get_abuseipdb(ip):
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&verbose=true"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    response = requests.get(url, headers=headers, verify=certifi.where())
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


def is_tor_exit_node(ip):
    try:
        response = requests.get("https://check.torproject.org/exit-addresses", verify=certifi.where())
        if response.status_code != 200:
            return "🔴 Tor Exit Node Check: Could not retrieve list.\n"
        exit_nodes = response.text.splitlines()
        for line in exit_nodes:
            if line.startswith("ExitAddress") and ip in line:
                return "🟢 Tor Exit Node Check: This IP is a known Tor exit node.\n"
        return "⚪ Tor Exit Node Check: This IP is not a Tor exit node.\n"
    except Exception as e:
        return f"🔴 Tor Exit Node Check: Error occurred - {str(e)}\n"


def export_to_pdf(ip, vt_result, abuse_result):
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
    tor_result = is_tor_exit_node(ip)

    print(vt_result)
    print(abuse_result)
    print(tor_result)

    if any(map(is_result_valid, [vt_result, abuse_result, tor_result])):
        export_to_pdf(ip, vt_result, abuse_result + tor_result)
    else:
        print("ℹ️ No valid data found. PDF report not generated.")


# === Run for multiple IPs ===
if __name__ == "__main__":
    ips = get_user_ips()
    for ip in ips:
        summarize_ip(ip)