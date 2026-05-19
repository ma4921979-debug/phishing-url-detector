import streamlit as st
import socket
import ssl
import requests
import sqlite3
import pandas as pd
import plotly.express as px
import io
import hashlib
import json
try:
    import nmap
except Exception:
    nmap = None
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas


DB_NAME = "phishing_history.db"

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Protects against downgrade and man-in-the-middle attacks.",
    "Content-Security-Policy": "Helps prevent XSS and content injection attacks.",
    "X-Frame-Options": "Helps prevent clickjacking attacks.",
    "X-Content-Type-Options": "Prevents MIME type sniffing.",
    "Referrer-Policy": "Controls referrer information leakage.",
    "Permissions-Policy": "Restricts browser features such as camera and microphone."
}


# =========================
# HELPERS
# =========================
def clean_domain(domain):
    domain = domain.strip()
    domain = domain.replace("https://", "").replace("http://", "")
    domain = domain.split("/")[0]
    return domain


def risk_status(final_score):
    if final_score >= 80:
        return "SAFE", "Low Risk"
    elif final_score >= 50:
        return "MEDIUM RISK", "Medium Risk"
    else:
        return "HIGH RISK", "High Risk"


def json_dumps(data):
    return json.dumps(data, ensure_ascii=False)


def json_loads(data):
    try:
        return json.loads(data)
    except Exception:
        return None


# =========================
# AI SECURITY ASSISTANT ENGINE
# =========================
def generate_ai_security_analysis(audit_data):
    findings = audit_data.get("findings", [])
    final_score = audit_data.get("final_score", 0)
    final_level = audit_data.get("final_level", "Unknown")
    scores = audit_data.get("scores", {})

    analysis = []
    recommendations = []

    # Overall AI summary based on score
    if final_score >= 85:
        analysis.append(
            "The company currently has a strong security posture. Most major passive checks look healthy."
        )
    elif final_score >= 60:
        analysis.append(
            "The company has a medium security risk. Some weaknesses were detected and should be improved."
        )
    else:
        analysis.append(
            "The company has a high security risk. The detected issues may expose the system to attacks."
        )

    # Score-based AI explanation
    if scores.get("headers", 100) < 80:
        analysis.append(
            "The security headers score is low, which means the website may be missing browser-level protections."
        )
        recommendations.append(
            "Add important security headers such as Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy."
        )

    if scores.get("ports", 100) < 80:
        analysis.append(
            "The port exposure score indicates that some services may be reachable from the internet."
        )
        recommendations.append(
            "Close unnecessary ports and restrict sensitive services using firewall rules, VPN, or IP allowlisting."
        )

    if scores.get("ssl", 100) < 80:
        analysis.append(
            "The SSL score indicates a possible HTTPS or certificate issue."
        )
        recommendations.append(
            "Use a valid SSL certificate, renew expired certificates, and force HTTPS for all traffic."
        )

    if scores.get("dns", 100) < 80:
        analysis.append(
            "The DNS score indicates a domain resolution or DNS configuration issue."
        )
        recommendations.append(
            "Review DNS records and ensure the domain resolves correctly."
        )

    if scores.get("tech", 100) < 80:
        analysis.append(
            "The technology detection score indicates that some server or framework information may be exposed."
        )
        recommendations.append(
            "Avoid exposing server technologies and framework versions in HTTP headers."
        )

    # Finding-based AI explanation
    for finding in findings:
        finding_lower = finding.lower()

        if "open port" in finding_lower:
            analysis.append(
                "Open ports can increase the attack surface if the exposed services are not properly secured."
            )
            recommendations.append(
                "Review every open port and keep only required services publicly accessible."
            )

        if "port detected: 21" in finding_lower or "ftp" in finding_lower:
            analysis.append(
                "FTP exposure may be risky because FTP is commonly targeted and can transmit data insecurely."
            )
            recommendations.append(
                "Disable FTP if not needed, or replace it with SFTP/FTPS and restrict access."
            )

        if "port detected: 22" in finding_lower or "ssh" in finding_lower:
            analysis.append(
                "SSH exposure can be safe if properly configured, but it should not be open to everyone."
            )
            recommendations.append(
                "Restrict SSH access using firewall rules, strong authentication, and key-based login."
            )

        if "port detected: 3306" in finding_lower or "mysql" in finding_lower:
            analysis.append(
                "Public database ports are dangerous because attackers may attempt brute force or exploit database vulnerabilities."
            )
            recommendations.append(
                "Do not expose MySQL directly to the internet. Restrict it to internal networks only."
            )

        if "port detected: 3389" in finding_lower or "rdp" in finding_lower:
            analysis.append(
                "RDP exposure is high risk because attackers often target it for unauthorized remote access."
            )
            recommendations.append(
                "Disable public RDP or protect it using VPN, MFA, and strict firewall rules."
            )

        if "missing security header" in finding_lower:
            analysis.append(
                "Missing security headers reduce browser-side protection and may increase web attack risks."
            )

        if "content-security-policy" in finding_lower:
            analysis.append(
                "Missing Content-Security-Policy may increase the risk of Cross-Site Scripting attacks."
            )
            recommendations.append(
                "Implement a strong Content-Security-Policy to control allowed scripts, styles, and resources."
            )

        if "strict-transport-security" in finding_lower:
            analysis.append(
                "Missing HSTS may allow downgrade attacks or insecure HTTP access."
            )
            recommendations.append(
                "Enable Strict-Transport-Security to force browsers to use HTTPS."
            )

        if "x-frame-options" in finding_lower:
            analysis.append(
                "Missing X-Frame-Options may allow clickjacking attacks."
            )
            recommendations.append(
                "Add X-Frame-Options or frame-ancestors inside CSP to prevent clickjacking."
            )

        if "x-content-type-options" in finding_lower:
            analysis.append(
                "Missing X-Content-Type-Options may allow MIME sniffing attacks."
            )
            recommendations.append(
                "Add X-Content-Type-Options: nosniff."
            )

        if "referrer-policy" in finding_lower:
            analysis.append(
                "Missing Referrer-Policy may leak sensitive URL information to external sites."
            )
            recommendations.append(
                "Configure a strict Referrer-Policy such as strict-origin-when-cross-origin."
            )

        if "ssl certificate validation failed" in finding_lower:
            analysis.append(
                "SSL certificate validation failure means encrypted communication may not be trusted."
            )
            recommendations.append(
                "Fix the SSL certificate, ensure it is valid, trusted, and not expired."
            )

        if "dns resolution issue" in finding_lower:
            analysis.append(
                "DNS resolution issues can affect availability and may indicate misconfiguration."
            )
            recommendations.append(
                "Review DNS records and make sure the domain points to the correct servers."
            )

        if "exposed technology information" in finding_lower:
            analysis.append(
                "Exposed technology information may help attackers fingerprint the system."
            )
            recommendations.append(
                "Hide unnecessary technology headers such as Server and X-Powered-By."
            )

    if not recommendations:
        recommendations.append(
            "Continue regular security monitoring and repeat audits periodically to detect future changes."
        )

    # Remove duplicates while preserving order
    analysis = list(dict.fromkeys(analysis))
    recommendations = list(dict.fromkeys(recommendations))

    summary = f"""
*AI Security Summary*

Final Security Score: *{final_score}%*  
Risk Level: *{final_level}*

The AI assistant reviewed the company audit results, including ports, SSL, DNS, security headers, detected technologies, and monitoring findings. Based on these indicators, it generated a security explanation and recommended actions to reduce risk.
"""

    return {
        "summary": summary,
        "analysis": analysis,
        "recommendations": recommendations
    }


# =========================
# DATABASE
# =========================
def create_company_tables():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS company_audits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            domain TEXT,
            port_score INTEGER,
            headers_score INTEGER,
            ssl_score INTEGER,
            dns_score INTEGER,
            tech_score INTEGER,
            final_score INTEGER,
            risk_level TEXT,
            findings TEXT,
            checked_at TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS company_verifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            domain TEXT,
            token TEXT,
            verified TEXT,
            created_at TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS company_monitoring (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            domain TEXT,
            frequency TEXT,
            alert_email TEXT,
            created_at TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS monitoring_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            domain TEXT,
            final_score INTEGER,
            risk_level TEXT,
            scores_json TEXT,
            port_results_json TEXT,
            headers_results_json TEXT,
            ssl_results_json TEXT,
            dns_results_json TEXT,
            tech_results_json TEXT,
            findings_json TEXT,
            alerts_json TEXT,
            checked_at TEXT
        )
    """)

    conn.commit()
    conn.close()


def save_company_audit(username, domain, scores, final_score, risk_level, findings):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO company_audits (
            username, domain, port_score, headers_score, ssl_score,
            dns_score, tech_score, final_score, risk_level, findings, checked_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        username,
        domain,
        scores.get("ports", 100),
        scores.get("headers", 100),
        scores.get("ssl", 100),
        scores.get("dns", 100),
        scores.get("tech", 100),
        final_score,
        risk_level,
        "\n".join(findings),
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    conn.commit()
    conn.close()


def load_company_history(username):
    conn = sqlite3.connect(DB_NAME)
    df = pd.read_sql_query(
        "SELECT * FROM company_audits WHERE username = ? ORDER BY id DESC",
        conn,
        params=(username,)
    )
    conn.close()
    return df


def generate_verification_token(username, domain):
    raw = f"{username}-{domain}-{datetime.now()}"
    return "cyber-verify-" + hashlib.sha256(raw.encode()).hexdigest()[:12]


def save_verification(username, domain, token, verified="No"):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO company_verifications (username, domain, token, verified, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (
        username,
        domain,
        token,
        verified,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    conn.commit()
    conn.close()


def update_verification_status(username, domain, token, verified):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE company_verifications
        SET verified = ?
        WHERE username = ? AND domain = ? AND token = ?
    """, (
        verified,
        username,
        domain,
        token
    ))

    conn.commit()
    conn.close()


def is_domain_verified(username, domain):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM company_verifications
        WHERE username = ? AND domain = ? AND verified = 'Yes'
        ORDER BY id DESC
        LIMIT 1
    """, (
        username,
        domain
    ))

    row = cursor.fetchone()
    conn.close()

    return row is not None


def save_monitoring_plan(username, domain, frequency, alert_email):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO company_monitoring (username, domain, frequency, alert_email, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (
        username,
        domain,
        frequency,
        alert_email,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    conn.commit()
    conn.close()


def load_monitoring_plans(username):
    conn = sqlite3.connect(DB_NAME)
    df = pd.read_sql_query(
        "SELECT * FROM company_monitoring WHERE username = ? ORDER BY id DESC",
        conn,
        params=(username,)
    )
    conn.close()
    return df


def load_latest_monitoring_result(username, domain):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM monitoring_results
        WHERE username = ? AND domain = ?
        ORDER BY id DESC
        LIMIT 1
    """, (username, domain))
    row = cursor.fetchone()
    if row is None:
        conn.close()
        return None
    columns = [description[0] for description in cursor.description]
    conn.close()
    return dict(zip(columns, row))


def save_monitoring_result(username, audit, alerts):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO monitoring_results (
            username, domain, final_score, risk_level, scores_json,
            port_results_json, headers_results_json, ssl_results_json,
            dns_results_json, tech_results_json, findings_json, alerts_json, checked_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        username,
        audit["domain"],
        audit["final_score"],
        audit["final_level"],
        json_dumps(audit["scores"]),
        json_dumps(audit["port_results"]),
        json_dumps(audit["headers_results"]),
        json_dumps(audit["ssl_results"]),
        json_dumps(audit["dns_results"]),
        json_dumps(audit["tech_results"]),
        json_dumps(audit["findings"]),
        json_dumps(alerts),
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))
    conn.commit()
    conn.close()


def load_monitoring_results(username):
    conn = sqlite3.connect(DB_NAME)
    df = pd.read_sql_query(
        "SELECT * FROM monitoring_results WHERE username = ? ORDER BY id DESC",
        conn,
        params=(username,)
    )
    conn.close()
    return df


# =========================
# DOMAIN VERIFICATION
# =========================
def verify_domain_file(domain, token):
    url = f"https://{domain}/.well-known/security-verification.txt"

    try:
        response = requests.get(url, timeout=8)
        return token in response.text
    except Exception:
        return False


# =========================
# COMPANY SCAN TOOLS
# =========================
def scan_ports(domain):
    results = []

    for port, service in COMMON_PORTS.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        try:
            result = sock.connect_ex((domain, port))

            if result == 0:
                status = "Open"
                risk = "Medium" if port in [21, 22, 3306, 3389] else "Low"
            else:
                status = "Closed"
                risk = "Low"

            results.append({
                "Port": port,
                "Service": service,
                "Status": status,
                "Risk": risk
            })

        except Exception:
            results.append({
                "Port": port,
                "Service": service,
                "Status": "Error",
                "Risk": "Unknown"
            })

        finally:
            sock.close()

    return results


def advanced_nmap_scan(domain):
    results = []

    if nmap is None:
        return [{
            "Host": domain,
            "Port": "-",
            "Protocol": "N/A",
            "State": "Failed",
            "Service": "Nmap library is not installed",
            "Version": "Run: python -m pip install python-nmap"
        }]

    try:
        scanner = nmap.PortScanner(
            nmap_search_path=(
                r"C:\\Program Files (x86)\\Nmap\\nmap.exe",
                r"C:\\Program Files\\Nmap\\nmap.exe",
                "nmap"
            )
        )

        scanner.scan(domain, arguments="-sV --version-light -T3 --top-ports 50")

        for host in scanner.all_hosts():
            for proto in scanner[host].all_protocols():
                ports = scanner[host][proto].keys()

                for port in ports:
                    port_data = scanner[host][proto][port]
                    product = port_data.get("product", "")
                    version = port_data.get("version", "")
                    extrainfo = port_data.get("extrainfo", "")

                    version_text = " ".join(
                        part for part in [product, version, extrainfo] if part
                    )

                    results.append({
                        "Host": host,
                        "Port": port,
                        "Protocol": proto,
                        "State": port_data.get("state", "unknown"),
                        "Service": port_data.get("name", "unknown"),
                        "Version": version_text if version_text else "unknown"
                    })

        if not results:
            results.append({
                "Host": domain,
                "Port": "None",
                "Protocol": "N/A",
                "State": "No open ports detected",
                "Service": "N/A",
                "Version": "N/A"
            })

    except Exception as e:
        results.append({
            "Host": domain,
            "Port": "Error",
            "Protocol": "N/A",
            "State": "Failed",
            "Service": "Nmap Error",
            "Version": str(e)
        })

    return results


# =========================
# CVE DETECTION ENGINE
# =========================
def build_cve_keyword(service, version):
    service = str(service or "").strip()
    version = str(version or "").strip()

    parts = []

    if service and service.lower() not in ["unknown", "n/a", "error"]:
        parts.append(service)

    if version and version.lower() not in ["unknown", "n/a", "-"]:
        parts.append(version)

    return " ".join(parts).strip()


def normalize_cve_severity(cve_item):
    metrics = cve_item.get("metrics", {})

    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if key in metrics and metrics[key]:
            metric = metrics[key][0]
            cvss_data = metric.get("cvssData", {})
            severity = metric.get("baseSeverity") or cvss_data.get("baseSeverity") or "Unknown"
            score = cvss_data.get("baseScore", "Unknown")
            return severity, score

    return "Unknown", "Unknown"


def search_nvd_cves(keyword, max_results=3):
    """
    Searches the public NVD API for possible CVEs.
    Internet connection is required. If the API is unavailable, the function returns an empty list.
    """
    if not keyword:
        return []

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": max_results
    }

    try:
        response = requests.get(url, params=params, timeout=10)

        if response.status_code != 200:
            return []

        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])
        results = []

        for entry in vulnerabilities[:max_results]:
            cve = entry.get("cve", {})
            cve_id = cve.get("id", "Unknown")
            descriptions = cve.get("descriptions", [])
            description = "No description available."

            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", description)
                    break

            severity, score = normalize_cve_severity(cve)

            results.append({
                "CVE": cve_id,
                "Severity": severity,
                "CVSS Score": score,
                "Description": description[:220],
                "Source": "NVD"
            })

        return results

    except Exception:
        return []


def heuristic_cve_detection(service, version):
    """
    Local fallback detection when the NVD API is unavailable.
    This does not confirm a specific CVE, but highlights risky exposed services.
    """
    service_text = str(service or "").lower()
    version_text = str(version or "").lower()
    combined = service_text + " " + version_text
    results = []

    if "openssh" in combined or service_text == "ssh":
        results.append({
            "CVE": "Potential SSH Exposure",
            "Severity": "Medium",
            "CVSS Score": "N/A",
            "Description": "SSH is exposed. Older OpenSSH versions may contain known vulnerabilities or may be targeted by brute-force attacks.",
            "Source": "Local Rule"
        })

    if "apache" in combined or "httpd" in combined:
        results.append({
            "CVE": "Potential Apache Exposure",
            "Severity": "Medium",
            "CVSS Score": "N/A",
            "Description": "Apache service/version is exposed. Outdated Apache versions may have known vulnerabilities and should be updated.",
            "Source": "Local Rule"
        })

    if "ftp" in combined or "tcpwrapped" in combined:
        results.append({
            "CVE": "Potential FTP/Service Exposure",
            "Severity": "Medium",
            "CVSS Score": "N/A",
            "Description": "FTP or a wrapped service is detected. Ensure the service is required, patched, and protected.",
            "Source": "Local Rule"
        })

    if "telnet" in combined:
        results.append({
            "CVE": "Insecure Telnet Service",
            "Severity": "High",
            "CVSS Score": "N/A",
            "Description": "Telnet is an insecure legacy service. It should be disabled or replaced with SSH.",
            "Source": "Local Rule"
        })

    if "mysql" in combined or "3306" in combined:
        results.append({
            "CVE": "Database Service Exposure",
            "Severity": "High",
            "CVSS Score": "N/A",
            "Description": "Database services should not be publicly exposed. Restrict access using firewall rules or private networking.",
            "Source": "Local Rule"
        })

    if not results:
        results.append({
            "CVE": "No obvious CVE indicator",
            "Severity": "Low",
            "CVSS Score": "N/A",
            "Description": "No obvious risky service signature was detected locally. Keep services updated and monitor regularly.",
            "Source": "Local Rule"
        })

    return results


def detect_cves_from_nmap(nmap_results):
    cve_results = []
    checked_keywords = set()

    for item in nmap_results or []:
        state = str(item.get("State", "")).lower()
        service = item.get("Service", "")
        version = item.get("Version", "")
        port = item.get("Port", "")

        if state not in ["open", "filtered"]:
            continue

        keyword = build_cve_keyword(service, version)

        if not keyword:
            keyword = str(service or port)

        keyword_key = keyword.lower()
        if keyword_key in checked_keywords:
            continue

        checked_keywords.add(keyword_key)

        online_results = search_nvd_cves(keyword, max_results=3)

        if online_results:
            for cve in online_results:
                cve_results.append({
                    "Port": port,
                    "Service": service,
                    "Version": version,
                    "CVE": cve["CVE"],
                    "Severity": cve["Severity"],
                    "CVSS Score": cve["CVSS Score"],
                    "Description": cve["Description"],
                    "Source": cve["Source"]
                })
        else:
            for cve in heuristic_cve_detection(service, version):
                cve_results.append({
                    "Port": port,
                    "Service": service,
                    "Version": version,
                    "CVE": cve["CVE"],
                    "Severity": cve["Severity"],
                    "CVSS Score": cve["CVSS Score"],
                    "Description": cve["Description"],
                    "Source": cve["Source"]
                })

    if not cve_results:
        cve_results.append({
            "Port": "None",
            "Service": "None",
            "Version": "N/A",
            "CVE": "No CVE indicators detected",
            "Severity": "Low",
            "CVSS Score": "N/A",
            "Description": "No open service with a clear CVE indicator was detected in the Nmap results.",
            "Source": "Local Rule"
        })

    return cve_results




def calculate_nmap_exposure_score(nmap_results):
    """
    Calculates an extra exposure score based on real Nmap results.
    This complements the basic socket scan and makes the company risk engine stronger.
    """
    score = 100
    sensitive_ports = {21, 22, 23, 25, 110, 143, 3306, 3389, 5900, 6379, 8080, 8443}

    for item in nmap_results or []:
        state = str(item.get("State", "")).lower()
        if state != "open":
            continue

        try:
            port = int(item.get("Port"))
        except Exception:
            port = None

        service = str(item.get("Service", "")).lower()
        version = str(item.get("Version", "")).lower()

        if port in sensitive_ports:
            score -= 12
        else:
            score -= 4

        if version and version not in ["unknown", "n/a", "-"]:
            score -= 3

        if any(word in service + " " + version for word in ["telnet", "ftp", "mysql", "rdp", "vnc", "redis"]):
            score -= 10

    score = max(score, 0)

    if score >= 80:
        level = "Low Risk"
    elif score >= 50:
        level = "Medium Risk"
    else:
        level = "High Risk"

    return score, level


def calculate_cve_score(cve_results):
    """
    Converts CVE severity results into a numerical score used by the final risk engine.
    Lower score means higher vulnerability risk.
    """
    score = 100

    for item in cve_results or []:
        severity = str(item.get("Severity", "")).lower()
        cve_id = str(item.get("CVE", "")).lower()

        if "critical" in severity:
            score -= 30
        elif "high" in severity:
            score -= 22
        elif "medium" in severity:
            score -= 12
        elif "low" in severity:
            score -= 5

        if cve_id.startswith("cve-"):
            score -= 5

    score = max(score, 0)

    if score >= 80:
        level = "Low Risk"
    elif score >= 50:
        level = "Medium Risk"
    else:
        level = "High Risk"

    return score, level


def build_technical_recommendations(audit):
    """
    Builds direct technical recommendations from all audit modules.
    """
    recommendations = []

    for item in audit.get("port_results", []) or []:
        if item.get("Status") == "Open":
            port = item.get("Port")
            service = item.get("Service")
            if port in [21, 22, 3306, 3389]:
                recommendations.append(f"Restrict public access to sensitive service {service} on port {port} using firewall rules, VPN, or IP allowlisting.")
            else:
                recommendations.append(f"Review whether port {port} ({service}) must be publicly accessible.")

    for item in audit.get("headers_results", []) or []:
        if item.get("Status") == "Missing":
            header = item.get("Header")
            recommendations.append(f"Add missing security header: {header}.")

    for item in audit.get("ssl_results", []) or []:
        if item.get("Status") in ["Failed", "Warning"]:
            recommendations.append("Fix SSL/TLS configuration and ensure the certificate is valid and not close to expiration.")

    for item in audit.get("cve_results", []) or []:
        severity = str(item.get("Severity", "")).lower()
        if severity in ["critical", "high", "medium"]:
            service = item.get("Service", "service")
            recommendations.append(f"Review and patch {service}. Possible vulnerability indicator: {item.get('CVE')}.")

    if not recommendations:
        recommendations.append("No urgent action detected. Continue regular monitoring, patching, and security reviews.")

    return list(dict.fromkeys(recommendations))

def calculate_port_score(results):
    score = 100

    for item in results:
        if item["Status"] == "Open":
            if item["Port"] in [21, 22, 3306, 3389]:
                score -= 15
            else:
                score -= 5

    score = max(score, 0)

    if score >= 80:
        level = "Low Risk"
    elif score >= 50:
        level = "Medium Risk"
    else:
        level = "High Risk"

    return score, level


def check_security_headers(domain):
    url = domain.strip()

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    results = []
    score = 100

    try:
        response = requests.get(url, timeout=8, allow_redirects=True)

        for header, description in SECURITY_HEADERS.items():
            if header in response.headers:
                status = "Present"
                risk = "Low"
            else:
                status = "Missing"
                risk = "High"
                score -= 12

            results.append({
                "Header": header,
                "Status": status,
                "Risk": risk,
                "Description": description
            })

    except Exception as e:
        return [], 0, "Error", str(e)

    score = max(score, 0)

    if score >= 80:
        level = "Low Risk"
    elif score >= 50:
        level = "Medium Risk"
    else:
        level = "High Risk"

    return results, score, level, None


def check_ssl(domain):
    results = []
    score = 100

    try:
        context = ssl.create_default_context()

        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                tls_version = ssock.version()
                cipher = ssock.cipher()

        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        not_after = cert.get("notAfter")

        results.append({
            "Check": "SSL Certificate",
            "Status": "Valid",
            "Details": f"Issued to: {subject.get('commonName', 'Unknown')}"
        })

        results.append({
            "Check": "Issuer",
            "Status": "Info",
            "Details": issuer.get("organizationName", "Unknown")
        })

        results.append({
            "Check": "TLS Version",
            "Status": "Info",
            "Details": tls_version or "Unknown"
        })

        if cipher:
            results.append({
                "Check": "Cipher Suite",
                "Status": "Info",
                "Details": str(cipher[0])
            })

        results.append({
            "Check": "Expiration",
            "Status": "Info",
            "Details": not_after
        })

        try:
            expiry_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry_date - datetime.utcnow()).days

            if days_left < 0:
                score = 20
                results.append({
                    "Check": "Expiration Risk",
                    "Status": "Failed",
                    "Details": "SSL certificate is expired."
                })
            elif days_left <= 30:
                score -= 35
                results.append({
                    "Check": "Expiration Risk",
                    "Status": "Warning",
                    "Details": f"SSL certificate expires soon in {days_left} days."
                })
            else:
                results.append({
                    "Check": "Expiration Risk",
                    "Status": "Valid",
                    "Details": f"SSL certificate is valid for approximately {days_left} more days."
                })
        except Exception:
            score -= 10
            results.append({
                "Check": "Expiration Parse",
                "Status": "Warning",
                "Details": "Could not calculate certificate expiration days."
            })

        level = "Low Risk" if score >= 80 else "Medium Risk" if score >= 50 else "High Risk"

    except Exception as e:
        score = 30
        level = "High Risk"
        results.append({
            "Check": "SSL Certificate",
            "Status": "Failed",
            "Details": str(e)
        })

    return results, score, level


def check_dns(domain):
    results = []
    score = 100

    try:
        hostname, aliases, addresses = socket.gethostbyname_ex(domain)

        results.append({
            "Record": "A Record",
            "Status": "Found",
            "Details": ", ".join(addresses)
        })

        if len(addresses) == 0:
            score -= 40

    except Exception as e:
        score = 50
        results.append({
            "Record": "A Record",
            "Status": "Error",
            "Details": str(e)
        })

    if score >= 80:
        level = "Low Risk"
    elif score >= 50:
        level = "Medium Risk"
    else:
        level = "High Risk"

    return results, score, level


def detect_technologies(domain):
    url = domain.strip()

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    results = []
    score = 100

    try:
        response = requests.get(url, timeout=8, allow_redirects=True)
        headers = response.headers
        body = response.text.lower()

        server = headers.get("Server", "Not exposed")
        powered_by = headers.get("X-Powered-By", "Not exposed")

        results.append({
            "Technology": "Server",
            "Detected": server,
            "Risk": "Medium" if server != "Not exposed" else "Low"
        })

        results.append({
            "Technology": "X-Powered-By",
            "Detected": powered_by,
            "Risk": "Medium" if powered_by != "Not exposed" else "Low"
        })

        if server != "Not exposed":
            score -= 10

        if powered_by != "Not exposed":
            score -= 10

        fingerprints = {
            "WordPress": "wp-content",
            "React": "react",
            "Angular": "ng-version",
            "Bootstrap": "bootstrap",
            "jQuery": "jquery",
            "PHP": ".php",
            "Laravel": "laravel"
        }

        for tech, marker in fingerprints.items():
            if marker.lower() in body:
                results.append({
                    "Technology": tech,
                    "Detected": "Yes",
                    "Risk": "Low"
                })

    except Exception as e:
        score = 60
        results.append({
            "Technology": "Detection Error",
            "Detected": str(e),
            "Risk": "Unknown"
        })

    if score >= 80:
        level = "Low Risk"
    elif score >= 50:
        level = "Medium Risk"
    else:
        level = "High Risk"

    return results, score, level


# =========================
# RISK ENGINE
# =========================
def calculate_final_score(scores):
    values = list(scores.values())

    if not values:
        final_score = 0
    else:
        final_score = round(sum(values) / len(values))

    if final_score >= 80:
        level = "Low Risk"
    elif final_score >= 50:
        level = "Medium Risk"
    else:
        level = "High Risk"

    return final_score, level


def build_findings(port_results, headers_results, ssl_results, dns_results, tech_results):
    findings = []

    for item in port_results or []:
        if item["Status"] == "Open":
            findings.append(f"Open port detected: {item['Port']} ({item['Service']}) - Risk: {item['Risk']}")

    for item in headers_results or []:
        if item["Status"] == "Missing":
            findings.append(f"Missing security header: {item['Header']}")

    for item in ssl_results or []:
        if item["Status"] == "Failed":
            findings.append("SSL certificate validation failed.")

    for item in dns_results or []:
        if item["Status"] == "Error":
            findings.append("DNS resolution issue detected.")

    for item in tech_results or []:
        if item["Risk"] == "Medium":
            findings.append(f"Exposed technology information: {item['Technology']} = {item['Detected']}")

    if not findings:
        findings.append("No major security issues detected in passive checks.")

    return findings


def run_full_audit(domain):
    clean = clean_domain(domain)

    port_results = scan_ports(clean)
    nmap_results = advanced_nmap_scan(clean)
    cve_results = detect_cves_from_nmap(nmap_results)
    port_score, port_level = calculate_port_score(port_results)
    nmap_score, nmap_level = calculate_nmap_exposure_score(nmap_results)
    cve_score, cve_level = calculate_cve_score(cve_results)

    headers_results, headers_score, headers_level, headers_error = check_security_headers(clean)

    ssl_results, ssl_score, ssl_level = check_ssl(clean)

    dns_results, dns_score, dns_level = check_dns(clean)

    tech_results, tech_score, tech_level = detect_technologies(clean)

    scores = {
        "ports": port_score,
        "nmap": nmap_score,
        "cve": cve_score,
        "headers": headers_score,
        "ssl": ssl_score,
        "dns": dns_score,
        "tech": tech_score
    }

    final_score, final_level = calculate_final_score(scores)

    findings = build_findings(
        port_results,
        headers_results,
        ssl_results,
        dns_results,
        tech_results
    )

    for item in nmap_results or []:
        if str(item.get("State", "")).lower() == "open":
            findings.append(f"Nmap detected open service: port {item.get('Port')} / {item.get('Service')} / version: {item.get('Version')}")

    for item in cve_results or []:
        severity = str(item.get("Severity", "")).lower()
        if severity in ["critical", "high", "medium"]:
            findings.append(f"CVE indicator detected: {item.get('CVE')} on {item.get('Service')} - Severity: {item.get('Severity')}")

    technical_recommendations = build_technical_recommendations({
        "port_results": port_results,
        "headers_results": headers_results,
        "ssl_results": ssl_results,
        "cve_results": cve_results
    })

    return {
        "domain": clean,
        "port_results": port_results,
        "nmap_results": nmap_results,
        "cve_results": cve_results,
        "headers_results": headers_results,
        "ssl_results": ssl_results,
        "dns_results": dns_results,
        "tech_results": tech_results,
        "scores": scores,
        "final_score": final_score,
        "final_level": final_level,
        "findings": findings,
        "technical_recommendations": technical_recommendations
    }


# =========================
# REAL-TIME MONITORING ENGINE
# =========================
def extract_open_ports(port_results):
    ports = set()
    for item in port_results or []:
        if item.get("Status") == "Open":
            ports.add(str(item.get("Port")))
    return ports


def extract_missing_headers(headers_results):
    headers = set()
    for item in headers_results or []:
        if item.get("Status") == "Missing":
            headers.add(str(item.get("Header")))
    return headers


def ssl_failed(ssl_results):
    for item in ssl_results or []:
        if item.get("Status") == "Failed":
            return True
    return False


def compare_with_previous(previous_result, current_audit):
    alerts = []
    if previous_result is None:
        alerts.append("First monitoring scan saved. No previous scan to compare with.")
        return alerts

    previous_score = previous_result.get("final_score", 100)
    current_score = current_audit["final_score"]

    if current_score < previous_score:
        difference = previous_score - current_score
        alerts.append(f"Security score dropped from {previous_score}% to {current_score}% (-{difference}%).")

    previous_ports = extract_open_ports(json_loads(previous_result.get("port_results_json", "[]")) or [])
    current_ports = extract_open_ports(current_audit["port_results"])
    for port in current_ports - previous_ports:
        alerts.append(f"New open port detected: {port}")

    previous_missing_headers = extract_missing_headers(json_loads(previous_result.get("headers_results_json", "[]")) or [])
    current_missing_headers = extract_missing_headers(current_audit["headers_results"])
    for header in current_missing_headers - previous_missing_headers:
        alerts.append(f"New missing security header detected: {header}")

    previous_ssl_results = json_loads(previous_result.get("ssl_results_json", "[]")) or []
    if not ssl_failed(previous_ssl_results) and ssl_failed(current_audit["ssl_results"]):
        alerts.append("SSL certificate status changed from valid to failed.")

    previous_risk = previous_result.get("risk_level", "Low Risk")
    current_risk = current_audit["final_level"]
    risk_order = {"Low Risk": 1, "Medium Risk": 2, "High Risk": 3}

    if risk_order.get(current_risk, 1) > risk_order.get(previous_risk, 1):
        alerts.append(f"Risk level increased from {previous_risk} to {current_risk}.")

    if not alerts:
        alerts.append("No dangerous changes detected compared with the previous monitoring scan.")

    return alerts


# =========================
# PDF REPORT
# =========================
def generate_company_pdf(domain, scores, final_score, final_level, port_results, headers_results, ssl_results, dns_results, tech_results, findings, nmap_results=None, cve_results=None):
    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)

    y = 750

    pdf.setFont("Helvetica-Bold", 18)
    pdf.drawString(50, y, "Company Security Audit Report")

    y -= 35
    pdf.setFont("Helvetica", 12)
    pdf.drawString(50, y, f"Domain: {domain}")

    y -= 20
    pdf.drawString(50, y, f"Generated At: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    y -= 30
    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(50, y, "Executive Summary")

    y -= 25
    pdf.setFont("Helvetica", 12)
    pdf.drawString(60, y, f"Final Security Score: {final_score}%")

    y -= 20
    pdf.drawString(60, y, f"Overall Risk Level: {final_level}")

    y -= 30
    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(50, y, "Scores")

    pdf.setFont("Helvetica", 11)

    for name, score in scores.items():
        y -= 18
        pdf.drawString(60, y, f"{name.title()} Score: {score}%")

    y -= 35
    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(50, y, "Key Findings")

    pdf.setFont("Helvetica", 10)

    for finding in findings:
        y -= 16

        if y < 80:
            pdf.showPage()
            y = 750
            pdf.setFont("Helvetica", 10)

        pdf.drawString(60, y, f"- {finding[:95]}")

    sections = [
        ("Port Scan Summary", port_results),
        ("Nmap Advanced Scan Summary", nmap_results or []),
        ("CVE Detection Summary", cve_results or []),
        ("Security Headers Summary", headers_results),
        ("SSL Summary", ssl_results),
        ("DNS Summary", dns_results),
        ("Technology Detection Summary", tech_results)
    ]

    for title, data in sections:
        pdf.showPage()
        y = 750

        pdf.setFont("Helvetica-Bold", 15)
        pdf.drawString(50, y, title)

        y -= 30
        pdf.setFont("Helvetica", 9)

        if not data:
            pdf.drawString(60, y, "No data available.")
            continue

        for item in data:
            if y < 80:
                pdf.showPage()
                y = 750
                pdf.setFont("Helvetica", 9)

            line = " | ".join([f"{k}: {v}" for k, v in item.items()])
            pdf.drawString(60, y, line[:110])
            y -= 16

    pdf.showPage()
    y = 750
    pdf.setFont("Helvetica-Bold", 15)
    pdf.drawString(50, y, "Recommendations")

    recommendations = [
        "Close unnecessary open ports.",
        "Restrict sensitive services using firewall rules, VPN, or IP allowlisting.",
        "Add missing security headers such as CSP, HSTS, X-Frame-Options, and Referrer-Policy.",
        "Avoid exposing server technologies and framework versions.",
        "Keep web servers, frameworks, and services updated.",
        "Repeat this audit regularly and compare results over time."
    ]

    y -= 30
    pdf.setFont("Helvetica", 11)

    for rec in recommendations:
        pdf.drawString(60, y, f"- {rec}")
        y -= 18

    pdf.save()
    buffer.seek(0)
    return buffer


# =========================
# UI
# =========================
def run_company_mode():
    create_company_tables()

    st.title("Company Mode - Security Audit")

    tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
        "Automatic Audit",
        "Domain Verification",
        "Company Dashboard",
        "Company Report",
        "Monitoring Plan",
        "Monitoring Alerts",
        "Advanced Tools"
    ])

    if "company_audit" not in st.session_state:
        st.session_state.company_audit = None

    if "verification_token" not in st.session_state:
        st.session_state.verification_token = ""

    username = st.session_state.get("username", "unknown")

    with tab1:
        st.subheader("Automated Company Security Audit")

        audit_domain = st.text_input(
            "Enter company domain",
            placeholder="example.com",
            key="automatic_audit_domain"
        )

        clean_audit_domain = clean_domain(audit_domain) if audit_domain else ""

        permission = st.checkbox(
            "I confirm that I own this domain or have permission to audit it.",
            key="automatic_audit_permission"
        )

        require_verification = st.checkbox(
            "Require domain verification before audit",
            value=True,
            key="require_domain_verification"
        )

        if clean_audit_domain:
            if is_domain_verified(username, clean_audit_domain):
                st.success("Domain is verified.")
            else:
                st.warning("Domain is not verified yet.")

        if st.button("Run Automatic Full Audit"):
            if audit_domain.strip() == "":
                st.warning("Please enter a domain.")
            elif not permission:
                st.warning("You must confirm permission before scanning.")
            elif require_verification and not is_domain_verified(username, clean_audit_domain):
                st.error("Domain verification is required before running this audit.")
                st.info("Go to Domain Verification tab, generate a token, place it on your site, then verify.")
            else:
                with st.spinner("Running automated passive company security audit..."):
                    audit = run_full_audit(audit_domain)

                st.session_state.company_audit = audit

                save_company_audit(
                    username,
                    audit["domain"],
                    audit["scores"],
                    audit["final_score"],
                    audit["final_level"],
                    audit["findings"]
                )

                previous_result = load_latest_monitoring_result(username, audit["domain"])
                alerts = compare_with_previous(previous_result, audit)
                save_monitoring_result(username, audit, alerts)

                company_status, risk_level = risk_status(audit["final_score"])

                st.success("Automatic audit completed.")

                if company_status == "SAFE":
                    st.success("Company Status: SAFE")
                elif company_status == "MEDIUM RISK":
                    st.warning("Company Status: MEDIUM RISK")
                else:
                    st.error("Company Status: HIGH RISK")

                st.metric("Final Company Security Score", f"{audit['final_score']}%")
                st.write(f"Risk Level: *{audit['final_level']}*")

                st.subheader("Scores")
                col1, col2, col3, col4, col5, col6, col7 = st.columns(7)
                col1.metric("Ports", f"{audit['scores']['ports']}%")
                col2.metric("Nmap", f"{audit['scores'].get('nmap', 100)}%")
                col3.metric("CVE", f"{audit['scores'].get('cve', 100)}%")
                col4.metric("Headers", f"{audit['scores']['headers']}%")
                col5.metric("SSL", f"{audit['scores']['ssl']}%")
                col6.metric("DNS", f"{audit['scores']['dns']}%")
                col7.metric("Tech", f"{audit['scores']['tech']}%")

                st.subheader("Nmap Advanced Scan")
                st.dataframe(audit.get("nmap_results", []), use_container_width=True)

                st.subheader("CVE Detection")
                st.dataframe(audit.get("cve_results", []), use_container_width=True)

                st.subheader("Technical Recommendations")
                for rec in audit.get("technical_recommendations", []):
                    st.success(rec)

                st.subheader("Monitoring Alerts")
                for alert in alerts:
                    if "No dangerous" in alert or "First monitoring" in alert:
                        st.info(alert)
                    else:
                        st.warning(alert)

                ai_analysis = generate_ai_security_analysis(audit)

                st.subheader("AI Security Analysis")
                st.markdown(ai_analysis["summary"])

                st.subheader("AI Explanation")
                for item in ai_analysis["analysis"]:
                    st.info(item)

                st.subheader("AI Recommendations")
                for rec in ai_analysis["recommendations"]:
                    st.success(rec)

                st.subheader("Key Findings")
                for finding in audit["findings"]:
                    if "Missing" in finding or "Open port" in finding or "failed" in finding or "issue" in finding:
                        st.warning(finding)
                    else:
                        st.write("- " + finding)

    with tab2:
        st.subheader("Domain Ownership Verification")

        domain = st.text_input("Enter company domain", placeholder="example.com", key="verify_domain")
        domain_clean = clean_domain(domain) if domain else ""

        if st.button("Generate Verification Token"):
            if not domain_clean:
                st.warning("Enter a domain first.")
            else:
                token = generate_verification_token(username, domain_clean)
                st.session_state.verification_token = token
                save_verification(username, domain_clean, token, "No")
                st.success("Verification token generated.")
                st.code(token)

        if st.session_state.verification_token and domain_clean:
            st.write("Place this token inside this file on your website:")
            st.code(f"https://{domain_clean}/.well-known/security-verification.txt")
            st.write("File content should be:")
            st.code(st.session_state.verification_token)

        if st.button("Verify Domain"):
            if not domain_clean or not st.session_state.verification_token:
                st.warning("Generate a token first.")
            else:
                verified = verify_domain_file(domain_clean, st.session_state.verification_token)

                if verified:
                    update_verification_status(username, domain_clean, st.session_state.verification_token, "Yes")
                    st.success("Domain verified successfully.")
                else:
                    update_verification_status(username, domain_clean, st.session_state.verification_token, "No")
                    st.error("Domain verification failed.")

    with tab3:
        st.subheader("Company Dashboard")

        history = load_company_history(username)

        if history.empty:
            st.info("No company audits yet.")
        else:
            latest = history.iloc[0]

            col1, col2, col3, col4 = st.columns(4)
            col1.metric("Total Audits", len(history))
            col2.metric("Latest Score", f"{latest['final_score']}%")
            col3.metric("Latest Risk", latest["risk_level"])
            col4.metric("Domains", history["domain"].nunique())

            fig = px.line(
                history.sort_values("checked_at"),
                x="checked_at",
                y="final_score",
                color="domain",
                markers=True,
                title="Company Security Score Over Time"
            )
            st.plotly_chart(fig, use_container_width=True)

            risk_counts = history["risk_level"].value_counts().reset_index()
            risk_counts.columns = ["risk_level", "count"]

            fig2 = px.pie(
                risk_counts,
                names="risk_level",
                values="count",
                title="Risk Level Distribution"
            )
            st.plotly_chart(fig2, use_container_width=True)

            st.subheader("Audit History")
            st.dataframe(history, use_container_width=True)

    with tab4:
        st.subheader("Company Security Report")

        audit = st.session_state.company_audit

        if not audit:
            st.info("Run a full audit first.")
        else:
            st.metric("Final Score", f"{audit['final_score']}%")
            st.write(f"Risk Level: *{audit['final_level']}*")

            ai_analysis = generate_ai_security_analysis(audit)

            st.subheader("AI Security Analysis")
            st.markdown(ai_analysis["summary"])

            st.subheader("AI Explanation")
            for item in ai_analysis["analysis"]:
                st.info(item)

            st.subheader("AI Recommendations")
            for rec in ai_analysis["recommendations"]:
                st.success(rec)

            st.subheader("Port Results")
            st.dataframe(audit["port_results"], use_container_width=True)

            st.subheader("Nmap Advanced Scan")
            st.dataframe(audit.get("nmap_results", []), use_container_width=True)

            st.subheader("CVE Detection")
            st.dataframe(audit.get("cve_results", []), use_container_width=True)

            st.subheader("Technical Recommendations")
            for rec in audit.get("technical_recommendations", []):
                st.success(rec)

            st.subheader("Security Headers")
            st.dataframe(audit["headers_results"], use_container_width=True)

            st.subheader("SSL Results")
            st.dataframe(audit["ssl_results"], use_container_width=True)

            st.subheader("DNS Results")
            st.dataframe(audit["dns_results"], use_container_width=True)

            st.subheader("Technology Detection")
            st.dataframe(audit["tech_results"], use_container_width=True)

            pdf_file = generate_company_pdf(
                audit["domain"],
                audit["scores"],
                audit["final_score"],
                audit["final_level"],
                audit["port_results"],
                audit["headers_results"],
                audit["ssl_results"],
                audit["dns_results"],
                audit["tech_results"],
                audit["findings"],
                audit.get("nmap_results", []),
                audit.get("cve_results", [])
            )

            st.download_button(
                label="Download Full Company PDF Report",
                data=pdf_file,
                file_name="company_security_audit_report.pdf",
                mime="application/pdf"
            )

    with tab5:
        st.subheader("Monitoring Plan")

        st.info("This saves a monitoring plan. True automatic scheduled scans require a backend server, cron job, or Streamlit scheduled deployment.")

        monitor_domain = st.text_input("Domain to monitor", placeholder="example.com")
        frequency = st.selectbox("Scan Frequency", ["Daily", "Weekly", "Monthly"])
        alert_email = st.text_input("Alert email")

        if st.button("Save Monitoring Plan"):
            if monitor_domain.strip() == "":
                st.warning("Enter domain.")
            else:
                save_monitoring_plan(username, clean_domain(monitor_domain), frequency, alert_email)
                st.success("Monitoring plan saved.")
                st.write("Saved details:")
                st.write(f"- Domain: {clean_domain(monitor_domain)}")
                st.write(f"- Frequency: {frequency}")
                st.write(f"- Alert Email: {alert_email}")

        plans = load_monitoring_plans(username)
        if not plans.empty:
            st.subheader("Saved Monitoring Plans")
            st.dataframe(plans, use_container_width=True)

    with tab6:
        st.subheader("Monitoring Alerts")

        results = load_monitoring_results(username)

        if results.empty:
            st.info("No monitoring results yet. Run an Automatic Audit first.")
        else:
            latest = results.iloc[0]
            col1, col2, col3 = st.columns(3)
            col1.metric("Latest Domain", latest["domain"])
            col2.metric("Latest Score", f"{latest['final_score']}%")
            col3.metric("Latest Risk", latest["risk_level"])

            st.subheader("Latest Alerts")
            latest_alerts = json_loads(latest["alerts_json"]) or []
            for alert in latest_alerts:
                if "No dangerous" in alert or "First monitoring" in alert:
                    st.info(alert)
                else:
                    st.warning(alert)

            st.subheader("Monitoring History")
            st.dataframe(
                results[["id", "domain", "final_score", "risk_level", "alerts_json", "checked_at"]],
                use_container_width=True
            )

            chart_df = results.copy()
            chart_df["checked_at"] = pd.to_datetime(chart_df["checked_at"], errors="coerce")
            fig = px.line(
                chart_df.sort_values("checked_at"),
                x="checked_at",
                y="final_score",
                color="domain",
                markers=True,
                title="Monitoring Score Changes Over Time"
            )
            st.plotly_chart(fig, use_container_width=True)

    with tab7:
        st.subheader("Advanced Tools")

        st.write("Implemented:")
        st.write("- Automated full company audit")
        st.write("- Domain verification workflow")
        st.write("- Verification requirement before audit")
        st.write("- Port exposure scanner")
        st.write("- Nmap advanced service scan")
        st.write("- CVE detection from Nmap results")
        st.write("- CVE and Nmap scores included in final risk engine")
        st.write("- Technical recommendations generated from audit findings")
        st.write("- Security headers scanner")
        st.write("- SSL certificate check")
        st.write("- DNS resolution check")
        st.write("- Technology detection")
        st.write("- Smart company risk engine")
        st.write("- AI Security Assistant")
        st.write("- AI risk explanation")
        st.write("- AI recommendations")
        st.write("- Company dashboard")
        st.write("- Full PDF report")
        st.write("- Monitoring plan storage")
        st.write("- Real-time monitoring comparison")
        st.write("- Monitoring alerts")
        st.write("- Score drop detection")
        st.write("- New open port detection")
        st.write("- New missing header detection")
        st.write("- SSL failure detection")

        st.divider()

        st.write("Still future work:")
        st.write("- Email alerts")
        st.write("- Threat Intelligence API")
        st.write("- Real scheduled automatic scans")
        st.write("- Nikto / OWASP ZAP integrations")