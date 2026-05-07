import streamlit as st
import socket
import ssl
import requests
import sqlite3
import pandas as pd
import plotly.express as px
import io
import hashlib
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
            "Check": "Expiration",
            "Status": "Info",
            "Details": not_after
        })

        level = "Low Risk"

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
    port_score, port_level = calculate_port_score(port_results)

    headers_results, headers_score, headers_level, headers_error = check_security_headers(clean)

    ssl_results, ssl_score, ssl_level = check_ssl(clean)

    dns_results, dns_score, dns_level = check_dns(clean)

    tech_results, tech_score, tech_level = detect_technologies(clean)

    scores = {
        "ports": port_score,
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

    return {
        "domain": clean,
        "port_results": port_results,
        "headers_results": headers_results,
        "ssl_results": ssl_results,
        "dns_results": dns_results,
        "tech_results": tech_results,
        "scores": scores,
        "final_score": final_score,
        "final_level": final_level,
        "findings": findings
    }


# =========================
# PDF REPORT
# =========================
def generate_company_pdf(domain, scores, final_score, final_level, port_results, headers_results, ssl_results, dns_results, tech_results, findings):
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

    st.title(" Company Mode - Security Audit")

    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
        " Automatic Audit",
        " Domain Verification",
        " Company Dashboard",
        " Company Report",
        " Monitoring Plan",
        " Advanced Tools"
    ])

    if "company_audit" not in st.session_state:
        st.session_state.company_audit = None

    if "verification_token" not in st.session_state:
        st.session_state.verification_token = ""

    username = st.session_state.get("username", "unknown")

    with tab1:
        st.subheader(" Automated Company Security Audit")

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
                st.success(" Domain is verified.")
            else:
                st.warning(" Domain is not verified yet.")

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

                company_status, risk_level = risk_status(audit["final_score"])

                st.success("Automatic audit completed.")

                if company_status == "SAFE":
                    st.success(" Company Status: SAFE")
                elif company_status == "MEDIUM RISK":
                    st.warning(" Company Status: MEDIUM RISK")
                else:
                    st.error(" Company Status: HIGH RISK")

                st.metric("Final Company Security Score", f"{audit['final_score']}%")
                st.write(f"Risk Level: *{audit['final_level']}*")

                st.subheader("Scores")
                col1, col2, col3, col4, col5 = st.columns(5)
                col1.metric("Ports", f"{audit['scores']['ports']}%")
                col2.metric("Headers", f"{audit['scores']['headers']}%")
                col3.metric("SSL", f"{audit['scores']['ssl']}%")
                col4.metric("DNS", f"{audit['scores']['dns']}%")
                col5.metric("Tech", f"{audit['scores']['tech']}%")

                st.subheader("Key Findings")
                for finding in audit["findings"]:
                    if "Missing" in finding or "Open port" in finding or "failed" in finding or "issue" in finding:
                        st.warning(finding)
                    else:
                        st.write("- " + finding)

    with tab2:
        st.subheader(" Domain Ownership Verification")

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
        st.subheader(" Company Dashboard")

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
        st.subheader(" Company Security Report")

        audit = st.session_state.company_audit

        if not audit:
            st.info("Run a full audit first.")
        else:
            st.metric("Final Score", f"{audit['final_score']}%")
            st.write(f"Risk Level: *{audit['final_level']}*")

            st.subheader("Port Results")
            st.dataframe(audit["port_results"], use_container_width=True)

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
                audit["findings"]
            )

            st.download_button(
                label=" Download Full Company PDF Report",
                data=pdf_file,
                file_name="company_security_audit_report.pdf",
                mime="application/pdf"
            )

    with tab5:
        st.subheader(" Monitoring Plan")

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

    with tab6:
        st.subheader(" Advanced Tools")

        st.write("Implemented:")
        st.write("- Automated full company audit")
        st.write("- Domain verification workflow")
        st.write("- Verification requirement before audit")
        st.write("- Port exposure scanner")
        st.write("- Security headers scanner")
        st.write("- SSL certificate check")
        st.write("- DNS resolution check")
        st.write("- Technology detection")
        st.write("- Smart company risk engine")
        st.write("- Company dashboard")
        st.write("- Full PDF report")
        st.write("- Monitoring plan storage")

        st.divider()

        st.write("Still future work:")
        st.write("- Real scheduled automatic monitoring")
        st.write("- Email alerts")
        st.write("- Real Nmap / Nikto / OWASP ZAP integrations")