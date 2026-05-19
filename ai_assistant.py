
import streamlit as st


def _cyber_ai_answer(question: str) -> str:
    q = (question or "").lower().strip()

    if not q:
        return "Please write a cybersecurity question."

    if any(word in q for word in ["url", "link", "phishing", "رابط", "تصيد"]):
        return (
            "URL Scanner checks the link using machine learning and rule-based indicators such as HTTPS, suspicious words, "
            "domain structure, IP usage, long URL length, subdomains, and special symbols. "
            "If the score is high, the link may be phishing or suspicious. Always verify the domain before entering passwords."
        )

    if any(word in q for word in ["qr", "barcode", "باركود", "كيو ار"]):
        return (
            "QR Scanner reads the content inside the QR code using the camera or uploaded image. "
            "If the QR contains a URL, the system sends it to the same URL Scanner engine and explains why it is safe, suspicious, or phishing."
        )

    if any(word in q for word in ["file", "malware", "virus", "ملف", "فايروس"]):
        return (
            "File Checker performs local static analysis. It checks the file signature, MIME type, extension mismatch, hash, size, entropy, "
            "macro indicators, scripts, executable indicators, and suspicious text patterns. "
            "It is risk-based analysis, not a full antivirus sandbox."
        )

    if any(word in q for word in ["password", "pass", "كلمة", "باسورد"]):
        return (
            "Password Analyzer evaluates password strength based on length, uppercase letters, lowercase letters, numbers, special characters, "
            "common passwords, and repeated patterns. Strong passwords should be long, unique, and not reused."
        )

    if any(word in q for word in ["email", "message", "sms", "whatsapp", "ايميل", "رسالة"]):
        return (
            "Email / Message Analyzer searches for phishing indicators such as urgent language, suspicious links, login requests, account warnings, "
            "payment requests, OTP requests, and repeated click instructions."
        )

    if any(word in q for word in ["nmap", "port", "ports", "ssh", "ftp", "rdp", "بورت"]):
        return (
            "Nmap Advanced Scan detects open ports, services, protocols, and versions. "
            "Open ports are not always dangerous, but sensitive services such as SSH, FTP, MySQL, and RDP should be restricted using firewall rules, VPN, or IP allowlisting."
        )

    if any(word in q for word in ["cve", "vulnerability", "ثغرة", "ثغرات"]):
        return (
            "CVE Detection checks detected services and versions against known vulnerability indicators. "
            "The system uses Nmap results and vulnerability intelligence to show possible CVEs, severity, CVSS score, and recommendations."
        )

    if any(word in q for word in ["ssl", "https", "certificate", "شهادة"]):
        return (
            "SSL protects communication between the user and the website. "
            "The system checks certificate validity and HTTPS availability. SSL problems may indicate expired certificates or unsafe encrypted communication."
        )

    if any(word in q for word in ["headers", "header", "csp", "hsts"]):
        return (
            "Security headers protect websites from browser-based attacks. Important headers include CSP, HSTS, X-Frame-Options, "
            "X-Content-Type-Options, Referrer-Policy, and Permissions-Policy."
        )

    if any(word in q for word in ["monitor", "alert", "dashboard", "تنبيه", "مراقبة"]):
        return (
            "Monitoring compares current scans with previous scans. It can detect score drops, new open ports, missing headers, SSL failures, "
            "and risk level changes. Dashboards show trends, statistics, and history."
        )

    if any(word in q for word in ["report", "pdf", "تقرير"]):
        return (
            "PDF Reports summarize scan results, risk scores, detected issues, Nmap services, CVE results, key findings, and recommendations "
            "in a format suitable for review and documentation."
        )

    if any(word in q for word in ["company", "audit", "شركة"]):
        return (
            "Company Mode performs a security audit for a domain. It checks ports, security headers, SSL, DNS, technologies, Nmap services, CVEs, "
            "monitoring alerts, and generates a security score with recommendations."
        )

    return (
        "I can help with all project features: URL Scanner, Email Analyzer, Password Analyzer, File Checker, QR Scanner, "
        "Company Audit, Nmap, CVE Detection, SSL, Security Headers, Monitoring, Dashboards, and PDF Reports. "
        "Ask me about any result or feature and I will explain it."
    )


def render_cyber_ai_assistant():
    if "cyber_ai_messages" not in st.session_state:
        st.session_state.cyber_ai_messages = [
            ("AI", "Hi, I am your Cyber AI Assistant. Ask me about any feature in the platform.")
        ]

    with st.sidebar.expander("Cyber AI Assistant", expanded=True):
        st.caption("Ask about URL, QR, files, passwords, Nmap, CVE, SSL, reports, or monitoring.")

        for sender, message in st.session_state.cyber_ai_messages[-6:]:
            if sender == "You":
                st.markdown(f"**You:** {message}")
            else:
                st.info(message)

        question = st.text_area(
            "Ask a cybersecurity question",
            key="cyber_ai_question",
            height=90,
            placeholder="Example: Why is SSH risky?"
        )

        col1, col2 = st.columns(2)

        with col1:
            if st.button("Ask AI", key="cyber_ai_ask_btn"):
                if question.strip():
                    answer = _cyber_ai_answer(question)
                    st.session_state.cyber_ai_messages.append(("You", question))
                    st.session_state.cyber_ai_messages.append(("AI", answer))
                    st.rerun()
                else:
                    st.warning("Write a question first.")

        with col2:
            if st.button("Clear", key="cyber_ai_clear_btn"):
                st.session_state.cyber_ai_messages = [
                    ("AI", "Chat cleared. Ask me about any tool in the cybersecurity platform.")
                ]
                st.rerun()
