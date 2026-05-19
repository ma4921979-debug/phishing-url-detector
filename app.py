import streamlit as st
import sqlite3
import pandas as pd
import requests
import joblib
import io
import os
import hashlib
import mimetypes
import re
import math
import ipaddress
from urllib.parse import urlparse, quote
import zipfile
import plotly.express as px
import numpy as np
try:
    import cv2
except Exception:
    cv2 = None
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader
from playwright.sync_api import sync_playwright
from company_mode import run_company_mode
from ai_assistant import render_cyber_ai_assistant
st.set_page_config(page_title="AI Cybersecurity Platform", layout="wide")

# =========================
# 🎨 GLOBAL DESIGN
# =========================
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

.stApp {
    background:
        radial-gradient(circle at 15% 15%, rgba(0, 180, 255, 0.28), transparent 28%),
        radial-gradient(circle at 85% 85%, rgba(0, 255, 180, 0.22), transparent 30%),
        linear-gradient(135deg, #020814 0%, #06162b 45%, #02050d 100%);
    color: #f4f8ff;
}

[data-testid="stHeader"] {
    background: transparent;
}

.block-container {
    padding-top: 2rem;
    max-width: 1250px;
}

.cyber-logo {
    text-align: center;
    margin-bottom: 35px;
}

.cyber-logo-icon {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 58px;
    height: 58px;
    border-radius: 18px;
    background: linear-gradient(135deg, #008cff, #00e5ff);
    box-shadow: 0 0 30px rgba(0, 200, 255, 0.45);
    font-size: 28px;
    margin-right: 12px;
}

.cyber-logo-title {
    display: inline-block;
    font-size: 30px;
    font-weight: 800;
    vertical-align: middle;
    color: #ffffff;
}

.cyber-card {
    background: rgba(8, 24, 44, 0.82);
    border: 1px solid rgba(120, 180, 255, 0.14);
    box-shadow: 0 25px 80px rgba(0, 0, 0, 0.45);
    border-radius: 24px;
    padding: 42px;
    backdrop-filter: blur(18px);
}

.center-card {
    max-width: 580px;
    margin: 0 auto;
}

.cyber-title {
    font-size: 40px;
    font-weight: 800;
    text-align: center;
    margin-bottom: 8px;
    color: #ffffff;
}

.cyber-subtitle {
    text-align: center;
    color: #9fb0c7;
    font-size: 17px;
    margin-bottom: 35px;
}

.mode-title {
    font-size: 46px;
    font-weight: 800;
    text-align: center;
    margin-top: 10px;
    color: #ffffff;
}

.mode-subtitle {
    text-align: center;
    color: #9fb0c7;
    font-size: 18px;
    margin-bottom: 45px;
}

.mode-card {
    min-height: 455px;
    background: rgba(8, 24, 44, 0.86);
    border: 1px solid rgba(120, 180, 255, 0.14);
    border-radius: 24px;
    padding: 34px;
    box-shadow: 0 25px 80px rgba(0, 0, 0, 0.42);
}

.mode-icon-blue {
    width: 72px;
    height: 72px;
    border-radius: 20px;
    background: linear-gradient(135deg, #008cff, #00e5ff);
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 34px;
    margin-bottom: 20px;
}

.mode-icon-green {
    width: 72px;
    height: 72px;
    border-radius: 20px;
    background: linear-gradient(135deg, #00b47a, #00e5d4);
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 34px;
    margin-bottom: 20px;
}

.mode-label {
    color: #9fb0c7;
    font-weight: 800;
    letter-spacing: 1px;
    font-size: 13px;
}

.mode-heading {
    font-size: 30px;
    font-weight: 800;
    margin-bottom: 25px;
    color: #ffffff;
}

.feature-line {
    font-size: 17px;
    margin: 12px 0;
    color: #e8f2ff;
}

.feature-dot {
    color: #00d8ff;
    font-weight: 800;
    margin-right: 8px;
}

.feature-dot-green {
    color: #00d69f;
    font-weight: 800;
    margin-right: 8px;
}

.stButton > button {
    width: 100%;
    height: 58px;
    border-radius: 17px;
    border: none;
    background: linear-gradient(90deg, #008cff, #00e5ff);
    color: #03111f;
    font-weight: 800;
    font-size: 17px;
    box-shadow: 0 12px 35px rgba(0, 195, 255, 0.28);
}

.stButton > button:hover {
    transform: translateY(-1px);
    box-shadow: 0 18px 45px rgba(0, 195, 255, 0.38);
}

.stTextInput label, .stTextArea label, .stFileUploader label {
    color: #a9b8cc !important;
    font-weight: 700 !important;
    letter-spacing: .5px;
}

.stTextInput input, .stTextArea textarea {
    background: rgba(20, 39, 62, 0.88) !important;
    color: #f4f8ff !important;
    border: 1px solid rgba(0, 210, 255, 0.25) !important;
    border-radius: 16px !important;
}

.stTabs [data-baseweb="tab-list"] {
    gap: 10px;
    background: rgba(8, 24, 44, 0.5);
    border-radius: 18px;
    padding: 8px;
}

.stTabs [data-baseweb="tab"] {
    border-radius: 14px;
    color: #b9c7d8;
    font-weight: 700;
}

.stTabs [aria-selected="true"] {
    background: linear-gradient(90deg, #008cff, #00e5ff);
    color: #06111f !important;
}

[data-testid="stMetric"] {
    background: rgba(8, 24, 44, 0.75);
    border: 1px solid rgba(120, 180, 255, 0.12);
    border-radius: 18px;
    padding: 18px;
}

[data-testid="stSidebar"] {
    background: rgba(3, 12, 25, 0.96);
}

h1, h2, h3 {
    color: #ffffff;
}

hr {
    border-color: rgba(255,255,255,.1);
}
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="cyber-logo">
    <span class="cyber-logo-icon">🛡️</span>
    <span class="cyber-logo-title">AI Cybersecurity Platform</span>
</div>
""", unsafe_allow_html=True)

# =========================
# CONFIG
# =========================
ADMIN_PASSWORD = "admin123"

model = joblib.load("model.pkl")
feature_columns = joblib.load("feature_columns.pkl")


# =========================
# DATABASE
# =========================
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def create_db():
    conn = sqlite3.connect("phishing_history.db")
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            created_at TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS url_checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            url TEXT,
            risk_score INTEGER,
            label TEXT,
            reasons TEXT,
            checked_at TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tool_checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            tool_name TEXT,
            input_summary TEXT,
            risk_score INTEGER,
            label TEXT,
            reasons TEXT,
            checked_at TEXT
        )
    """)

    conn.commit()
    conn.close()


create_db()


def register_user(username, password):
    conn = sqlite3.connect("phishing_history.db")
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO users (username, password, created_at)
            VALUES (?, ?, ?)
        """, (
            username,
            hash_password(password),
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        conn.close()
        return False


def login_user(username, password):
    conn = sqlite3.connect("phishing_history.db")
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM users
        WHERE username = ? AND password = ?
    """, (username, hash_password(password)))

    user = cursor.fetchone()
    conn.close()
    return user is not None


def save_tool_activity(username, tool_name, input_summary, risk_score, label, reasons):
    conn = sqlite3.connect("phishing_history.db")
    cursor = conn.cursor()

    checked_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        INSERT INTO tool_checks (username, tool_name, input_summary, risk_score, label, reasons, checked_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        username,
        tool_name,
        input_summary,
        risk_score,
        label,
        ", ".join(reasons),
        checked_at
    ))

    conn.commit()
    conn.close()
    return checked_at


def save_result(username, url, risk_score, label, reasons):
    conn = sqlite3.connect("phishing_history.db")
    cursor = conn.cursor()

    checked_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        INSERT INTO url_checks (username, url, risk_score, label, reasons, checked_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        username,
        url,
        risk_score,
        label,
        ", ".join(reasons),
        checked_at
    ))

    conn.commit()
    conn.close()

    save_tool_activity(username, "URL Scanner", url, risk_score, label, reasons)

    return checked_at


def load_user_history(username):
    conn = sqlite3.connect("phishing_history.db")
    df = pd.read_sql_query(
        "SELECT * FROM url_checks WHERE username = ? ORDER BY id DESC",
        conn,
        params=(username,)
    )
    conn.close()
    return df


def load_all_history():
    conn = sqlite3.connect("phishing_history.db")
    df = pd.read_sql_query("SELECT * FROM url_checks ORDER BY id DESC", conn)
    conn.close()
    return df


def load_all_tool_activity():
    conn = sqlite3.connect("phishing_history.db")
    df = pd.read_sql_query("SELECT * FROM tool_checks ORDER BY id DESC", conn)
    conn.close()
    return df


def delete_record(record_id):
    conn = sqlite3.connect("phishing_history.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM url_checks WHERE id = ?", (record_id,))
    conn.commit()
    conn.close()


# =========================
# USER MODE ANALYSIS FUNCTIONS
# =========================
def extract_features(url):
    features = {}
    url_lower = url.lower()

    features["having_IP_Address"] = 1 if any(c.isdigit() for c in url) else -1
    features["URLURL_Length"] = -1 if len(url) < 54 else 0 if len(url) <= 75 else 1
    features["Shortining_Service"] = 1 if "bit.ly" in url_lower or "tinyurl" in url_lower else -1
    features["having_At_Symbol"] = 1 if "@" in url else -1
    features["double_slash_redirecting"] = 1 if "//" in url[8:] else -1
    features["Prefix_Suffix"] = 1 if "-" in url else -1
    features["having_Sub_Domain"] = 1 if url.count(".") > 2 else -1
    features["SSLfinal_State"] = 1 if url_lower.startswith("https://") else -1

    for col in feature_columns:
        if col not in features:
            features[col] = 0

    return pd.DataFrame([features])[feature_columns]


def normalize_url(url):
    url = (url or "").strip()
    if url and not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def _safe_parse_url(url):
    normalized = normalize_url(url)
    try:
        parsed = urlparse(normalized)
        return normalized, parsed
    except Exception:
        return normalized, urlparse("")


def _looks_like_ip(hostname):
    try:
        ipaddress.ip_address(hostname)
        return True
    except Exception:
        return False


def explain_url(url):
    """
    Explainable URL risk analysis.
    Returns: risk_score, reasons, recommendations, positive_signals.
    """
    normalized, parsed = _safe_parse_url(url)
    url_lower = normalized.lower()
    hostname = (parsed.hostname or "").lower()
    query = parsed.query or ""

    risk = 0
    reasons = []
    recommendations = []
    positive_signals = []

    if not hostname:
        risk += 50
        reasons.append("URL structure could not be parsed correctly.")
        recommendations.append("Use a complete URL with a valid domain name.")
    else:
        positive_signals.append(f"Domain parsed successfully: {hostname}")

    if parsed.scheme == "http":
        risk += 25
        reasons.append("Uses HTTP instead of HTTPS, so traffic is not encrypted.")
        recommendations.append("Avoid entering sensitive data on HTTP pages.")
    elif parsed.scheme == "https":
        positive_signals.append("HTTPS is used, which supports encrypted communication.")
    else:
        risk += 10
        reasons.append("URL scheme is missing or unusual.")

    if "@" in normalized:
        risk += 30
        reasons.append("Contains @ symbol, which can hide the real destination domain.")
        recommendations.append("Avoid URLs containing @ unless you fully trust the source.")
    else:
        positive_signals.append("No @ symbol was found in the URL.")

    if hostname and _looks_like_ip(hostname):
        risk += 25
        reasons.append("Uses an IP address instead of a normal domain name.")
        recommendations.append("Be careful with direct IP links because they are often used to hide identity.")
    elif hostname:
        positive_signals.append("The URL uses a domain name instead of a raw IP address.")

    if "-" in hostname:
        risk += 10
        reasons.append("Domain contains a dash, which is sometimes used in fake login domains.")
    else:
        positive_signals.append("No dash was detected in the domain name.")

    if len(normalized) > 120:
        risk += 25
        reasons.append("URL is very long, which may hide redirects or tracking parameters.")
    elif len(normalized) > 80:
        risk += 15
        reasons.append("URL is longer than normal and should be reviewed carefully.")
    else:
        positive_signals.append("URL length is within a normal range.")

    dot_count = hostname.count(".")
    if dot_count > 3:
        risk += 20
        reasons.append("Domain contains many subdomains, which may be used to imitate trusted websites.")
    elif hostname:
        positive_signals.append("Subdomain count looks normal.")

    suspicious_words = [
        "login", "verify", "account", "bank", "paypal", "update", "secure",
        "wallet", "signin", "password", "confirm", "billing", "support", "free",
        "gift", "prize", "limited", "unlock", "suspended"
    ]
    found_words = sorted({word for word in suspicious_words if word in url_lower})
    if found_words:
        risk += min(35, 8 * len(found_words))
        reasons.append("Suspicious keyword(s) detected: " + ", ".join(found_words))
        recommendations.append("Verify the link from the official website instead of opening it directly.")
    else:
        positive_signals.append("No common phishing keywords were detected.")

    shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "cutt.ly"]
    if any(shortener in hostname for shortener in shorteners):
        risk += 25
        reasons.append("URL uses a shortening service, which can hide the final destination.")
        recommendations.append("Expand shortened URLs before opening them.")

    if query and len(query) > 80:
        risk += 10
        reasons.append("URL contains a long query string that may hide tracking or redirect parameters.")

    suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top"]
    if any(hostname.endswith(tld) for tld in suspicious_tlds):
        risk += 10
        reasons.append("Domain uses a TLD commonly seen in suspicious campaigns.")

    if not reasons:
        reasons.append("No obvious suspicious indicators were detected by rule-based analysis.")

    if not recommendations:
        recommendations.append("Still verify the source before entering passwords, payment data, or personal information.")

    risk = max(0, min(risk, 100))
    return risk, reasons, recommendations, positive_signals


def analyze_message(text):
    text_lower = text.lower()
    risk = 0
    reasons = []

    suspicious_words = [
        "urgent", "verify", "account", "bank", "password",
        "click", "login", "update", "confirm", "security",
        "suspended", "limited", "winner", "prize", "otp",
        "payment", "paypal", "reset", "unlock"
    ]

    for word in suspicious_words:
        if word in text_lower:
            risk += 10
            reasons.append(f"Suspicious word: {word}")

    if "http://" in text_lower or "https://" in text_lower:
        risk += 20
        reasons.append("Message contains a link")

    if "!" in text:
        risk += 5
        reasons.append("Urgency punctuation detected")

    if text_lower.count("click") >= 2:
        risk += 10
        reasons.append("Repeated click instruction")

    risk = min(risk, 100)

    if risk >= 60:
        label = "High Risk / Scam"
    elif risk >= 30:
        label = "Medium Risk / Suspicious"
    else:
        label = "Low Risk / Safe"

    if not reasons:
        reasons.append("No suspicious patterns detected")

    return label, risk, reasons


def analyze_password(password):
    score = 0
    reasons = []
    tips = []

    if len(password) >= 12:
        score += 30
    elif len(password) >= 8:
        score += 20
        tips.append("Use at least 12 characters for stronger protection.")
    else:
        reasons.append("Password is too short.")
        tips.append("Make the password at least 12 characters long.")

    if any(c.islower() for c in password):
        score += 10
    else:
        reasons.append("No lowercase letters found.")
        tips.append("Add lowercase letters.")

    if any(c.isupper() for c in password):
        score += 15
    else:
        reasons.append("No uppercase letters found.")
        tips.append("Add uppercase letters.")

    if any(c.isdigit() for c in password):
        score += 15
    else:
        reasons.append("No numbers found.")
        tips.append("Add numbers.")

    special_chars = "!@#$%^&*()-_=+[]{};:,.?/|\\"
    if any(c in special_chars for c in password):
        score += 20
    else:
        reasons.append("No special characters found.")
        tips.append("Add special characters like @, #, $, or !.")

    common_passwords = [
        "123456", "password", "qwerty", "admin", "123456789",
        "111111", "letmein", "welcome", "iloveyou"
    ]

    if password.lower() in common_passwords:
        score = 5
        reasons.append("Password is very common.")
        tips.append("Avoid common passwords.")

    repeated_patterns = ["123", "abc", "qwe", "111", "000"]
    for pattern in repeated_patterns:
        if pattern in password.lower():
            score -= 10
            reasons.append(f"Common pattern detected: {pattern}")
            tips.append("Avoid predictable patterns.")

    score = max(0, min(score, 100))

    if score >= 75:
        label = "Strong Password"
    elif score >= 45:
        label = "Medium Password"
    else:
        label = "Weak Password"

    if not reasons:
        reasons.append("Password has good complexity.")

    if not tips:
        tips.append("Your password looks strong. Keep it unique and do not reuse it.")

    return label, score, reasons, tips



def _file_entropy(data, max_bytes=200000):
    sample = data[:max_bytes]
    if not sample:
        return 0.0
    counts = [0] * 256
    for b in sample:
        counts[b] += 1
    entropy = 0.0
    length = len(sample)
    for count in counts:
        if count:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 2)


def _detect_magic_type(file_bytes):
    signatures = [
        (b"MZ", "Windows Executable (PE)", "executable"),
        (b"\x7fELF", "Linux Executable (ELF)", "executable"),
        (b"\xcf\xfa\xed\xfe", "macOS Mach-O Executable", "executable"),
        (b"\xfe\xed\xfa\xcf", "macOS Mach-O Executable", "executable"),
        (b"%PDF", "PDF Document", "document"),
        (b"PK\x03\x04", "ZIP / Office Open XML Archive", "archive"),
        (b"\x89PNG\r\n\x1a\n", "PNG Image", "image"),
        (b"\xff\xd8\xff", "JPEG Image", "image"),
        (b"GIF87a", "GIF Image", "image"),
        (b"GIF89a", "GIF Image", "image"),
        (b"Rar!", "RAR Archive", "archive"),
        (b"7z\xbc\xaf\x27\x1c", "7-Zip Archive", "archive"),
    ]
    for sig, name, category in signatures:
        if file_bytes.startswith(sig):
            return name, category
    return "Unknown / Plain Data", "unknown"


def _extension_category(ext):
    executable = {".exe", ".dll", ".scr", ".com", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar"}
    macro_docs = {".docm", ".xlsm", ".pptm"}
    archives = {".zip", ".rar", ".7z"}
    documents = {".pdf", ".docx", ".xlsx", ".pptx", ".txt", ".csv"}
    images = {".png", ".jpg", ".jpeg", ".gif"}
    if ext in executable:
        return "executable"
    if ext in macro_docs:
        return "macro_document"
    if ext in archives:
        return "archive"
    if ext in documents:
        return "document"
    if ext in images:
        return "image"
    return "unknown"


def _scan_zip_for_macros(file_bytes):
    indicators = []
    try:
        with zipfile.ZipFile(io.BytesIO(file_bytes)) as z:
            names = z.namelist()
            lowered = [n.lower() for n in names]
            if any("vbaproject.bin" in n for n in lowered):
                indicators.append("Office VBA macro project detected inside the file.")
            if any(n.endswith(".exe") or n.endswith(".dll") or n.endswith(".js") or n.endswith(".vbs") for n in lowered):
                indicators.append("Archive contains executable or script files.")
            if len(names) > 200:
                indicators.append("Archive contains a large number of files, which should be reviewed carefully.")
    except Exception:
        pass
    return indicators


def _scan_text_indicators(file_bytes):
    indicators = []
    sample = file_bytes[:250000]
    try:
        text_sample = sample.decode("utf-8", errors="ignore").lower()
    except Exception:
        text_sample = ""

    patterns = {
        "powershell": "PowerShell command detected.",
        "cmd.exe": "Windows command execution reference detected.",
        "wscript": "Windows script host reference detected.",
        "createobject": "Script object creation pattern detected.",
        "eval(": "JavaScript eval() pattern detected.",
        "base64": "Base64-related keyword detected.",
        "http://": "External HTTP link detected inside file content.",
        "https://": "External HTTPS link detected inside file content.",
        "document.write": "JavaScript document.write pattern detected.",
        "shell.application": "Shell execution object reference detected.",
    }

    for pattern, message in patterns.items():
        if pattern in text_sample:
            indicators.append(message)

    return list(dict.fromkeys(indicators))


def analyze_file(uploaded_file):
    risk = 0
    reasons = []
    tips = []

    file_name = uploaded_file.name
    file_size = uploaded_file.size
    file_extension = os.path.splitext(file_name)[1].lower()
    mime_type, _ = mimetypes.guess_type(file_name)

    file_bytes = uploaded_file.getvalue()
    file_hash = hashlib.sha256(file_bytes).hexdigest()
    magic_type, magic_category = _detect_magic_type(file_bytes)
    extension_category = _extension_category(file_extension)
    entropy = _file_entropy(file_bytes)

    reasons.append(f"Detected file signature: {magic_type}")
    reasons.append("SHA-256 hash calculated for integrity tracking.")

    if file_size == 0:
        risk += 20
        reasons.append("File is empty, which is unusual and should be verified.")

    if file_size > 10 * 1024 * 1024:
        risk += 10
        reasons.append("Large file size detected.")
        tips.append("Verify large files carefully before opening them.")

    if extension_category == "executable":
        risk += 55
        reasons.append(f"Executable/script extension detected: {file_extension}")
        tips.append("Do not run executable or script files unless they come from a trusted source.")
    elif extension_category == "macro_document":
        risk += 40
        reasons.append(f"Macro-enabled Office extension detected: {file_extension}")
        tips.append("Disable macros unless the document source is fully trusted.")
    elif extension_category == "archive":
        risk += 20
        reasons.append(f"Archive extension detected: {file_extension}")
        tips.append("Extract archives only in a safe environment and scan their contents.")
    elif extension_category in {"document", "image"}:
        reasons.append("File extension category is commonly used for normal documents/images.")
    else:
        risk += 10
        reasons.append("Unknown or uncommon file extension detected.")
        tips.append("Unknown file types should be verified before opening.")

    if magic_category == "executable":
        risk += 70
        reasons.append("Executable binary signature detected from file content, not only from the file name.")
        tips.append("Treat this file as high risk unless it is expected and trusted.")

    if magic_category == "archive":
        zip_indicators = _scan_zip_for_macros(file_bytes)
        for indicator in zip_indicators:
            risk += 25
            reasons.append(indicator)
            tips.append("Review archive contents and scan them before opening.")

    if magic_category == "executable" and extension_category != "executable":
        risk += 35
        reasons.append("File content looks executable but the extension does not match. This may indicate disguised malware.")
        tips.append("Do not open files whose content type does not match their extension.")

    if extension_category == "executable" and magic_category not in {"executable", "archive", "unknown"}:
        risk += 25
        reasons.append("Executable extension does not match the detected file signature.")

    content_indicators = _scan_text_indicators(file_bytes)
    for indicator in content_indicators:
        risk += 10
        reasons.append(indicator)

    if entropy >= 7.5 and file_size > 1024:
        risk += 15
        reasons.append(f"High entropy detected ({entropy}), which may indicate packing/encryption.")
        tips.append("Packed or encrypted files should be scanned with an antivirus engine.")
    else:
        reasons.append(f"Entropy level: {entropy}")

    risk = max(0, min(risk, 100))

    if risk >= 70:
        label = "High Risk File"
    elif risk >= 35:
        label = "Medium Risk File"
    else:
        label = "Low Risk File"

    if not tips:
        tips.append("No strong local risk indicators were found, but this is not a full antivirus scan.")

    tips.append("For final malware confirmation, scan the SHA-256 hash or file with a trusted antivirus or VirusTotal-like service.")

    return label, risk, reasons, tips, file_hash, mime_type or "Unknown"



def decode_qr_image(uploaded_file):
    if cv2 is None:
        return None, "OpenCV is not installed. Run: python -m pip install opencv-python pillow"

    try:
        file_bytes = uploaded_file.getvalue()
        np_arr = np.frombuffer(file_bytes, np.uint8)
        image = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)

        if image is None:
            return None, "Could not read the uploaded image."

        detector = cv2.QRCodeDetector()
        data, bbox, _ = detector.detectAndDecode(image)

        if data:
            return data.strip(), None

        return None, "No QR code was detected in this image."

    except Exception as e:
        return None, str(e)



def analyze_url_logic(url):
    features = extract_features(url)
    prediction = model.predict(features)[0]
    rule_risk, reasons, recommendations, positive_signals = explain_url(url)

    model_reason = "Machine learning model classified the URL as phishing." if prediction == -1 else "Machine learning model classified the URL as legitimate."

    if prediction == -1:
        final_risk = max(rule_risk, 70)
    else:
        final_risk = rule_risk

    final_risk = max(0, min(final_risk, 100))

    if final_risk >= 70:
        label = "High Risk / Phishing"
    elif final_risk >= 35:
        label = "Medium Risk / Suspicious"
    else:
        label = "Low Risk / Safe"

    reasons = [model_reason] + reasons

    if label == "Low Risk / Safe":
        recommendations.insert(0, "No major URL indicators were found, but continue to verify the sender/source before sharing sensitive data.")
    elif label == "Medium Risk / Suspicious":
        recommendations.insert(0, "Do not enter credentials until the domain is manually verified.")
    else:
        recommendations.insert(0, "Do not open this link or enter sensitive information unless verified through an official source.")

    return label, final_risk, reasons, recommendations, positive_signals


def capture_screenshot(url):
    """
    Returns a screenshot source.

    Priority:
    1. Local Playwright screenshot when available.
    2. Cloud-compatible screenshot URL using image.thum.io.

    Streamlit can display both local file paths and remote image URLs using st.image().
    """
    normalized_url = normalize_url(url)

    os.makedirs("screenshots", exist_ok=True)
    safe_name = st.session_state.username.replace(" ", "_")
    path = f"screenshots/{safe_name}.png"

    # Local desktop / VS Code execution
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=True, viewport={"width": 1366, "height": 900})
            page = context.new_page()
            page.goto(normalized_url, timeout=25000, wait_until="domcontentloaded")
            page.screenshot(path=path, full_page=False)
            browser.close()

        if os.path.exists(path) and os.path.getsize(path) > 0:
            return path

    except Exception:
        pass

    # Streamlit Cloud / mobile deployment fallback
    try:
        encoded_url = quote(normalized_url, safe="")
        return f"https://image.thum.io/get/width/1366/crop/900/noanimate/{encoded_url}"
    except Exception:
        return None


def _draw_screenshot_on_pdf(pdf, screenshot_source, x, y, width=500, height=200):
    """
    Adds either a local screenshot file or a remote screenshot URL to the PDF.
    """
    if not screenshot_source:
        pdf.drawString(x + 10, y + height - 20, "No screenshot available.")
        return

    try:
        if str(screenshot_source).startswith("http://") or str(screenshot_source).startswith("https://"):
            response = requests.get(screenshot_source, timeout=15)
            response.raise_for_status()
            image = ImageReader(io.BytesIO(response.content))
            pdf.drawImage(image, x, y, width=width, height=height, preserveAspectRatio=True, mask="auto")
        elif os.path.exists(screenshot_source):
            pdf.drawImage(screenshot_source, x, y, width=width, height=height, preserveAspectRatio=True, mask="auto")
        else:
            pdf.drawString(x + 10, y + height - 20, "Screenshot source was not available.")
    except Exception:
        pdf.drawString(x + 10, y + height - 20, "Screenshot could not be added to the PDF.")


def generate_pdf(url, risk, label, reasons, checked_at, screenshot_path, username):
    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)

    y = 750
    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(50, y, "Phishing URL Analysis Report")

    y -= 40
    pdf.setFont("Helvetica", 12)
    pdf.drawString(50, y, f"User: {username}")
    y -= 20
    pdf.drawString(50, y, f"URL: {url}")
    y -= 20
    pdf.drawString(50, y, f"Result: {label}")
    y -= 20
    pdf.drawString(50, y, f"Risk Score: {risk}%")
    y -= 20
    pdf.drawString(50, y, f"Checked At: {checked_at}")

    y -= 30
    pdf.drawString(50, y, "Reasons:")

    for reason in reasons:
        y -= 15
        pdf.drawString(60, y, f"- {reason}")

    y -= 30
    pdf.drawString(50, y, "Website Screenshot:")
    y -= 210

    _draw_screenshot_on_pdf(
        pdf,
        screenshot_path,
        50,
        y,
        width=500,
        height=200
    )

    pdf.save()
    buffer.seek(0)
    return buffer


# =========================
# DASHBOARD / ADMIN HELPERS
# =========================
def convert_df_to_excel(df):
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="All URL Checks")
    output.seek(0)
    return output


def prepare_dashboard_data(df):
    df = df.copy()
    df["checked_at"] = pd.to_datetime(df["checked_at"], errors="coerce")
    df["date"] = df["checked_at"].dt.date
    return df


def show_advanced_dashboard(df, title="Dashboard"):
    st.subheader(title)

    if df.empty:
        st.info("No URL checks yet.")
        return

    df = prepare_dashboard_data(df)

    total = len(df)
    phishing = len(df[df["label"] == "High Risk / Phishing"])
    safe = len(df[df["label"] == "Low Risk / Safe"])
    avg = round(df["risk_score"].mean(), 2)
    max_risk = df["risk_score"].max()

    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("Total Checks", total)
    col2.metric("High Risk", phishing)
    col3.metric("Safe URLs", safe)
    col4.metric("Average Risk", f"{avg}%")
    col5.metric("Highest Risk", f"{max_risk}%")

    col_a, col_b = st.columns(2)

    with col_a:
        fig_pie = px.pie(df, names="label", title="URL Risk Classification")
        st.plotly_chart(fig_pie, use_container_width=True)

    with col_b:
        fig_bar = px.bar(
            df.sort_values("checked_at"),
            x="checked_at",
            y="risk_score",
            color="label",
            title="Risk Score Over Time"
        )
        st.plotly_chart(fig_bar, use_container_width=True)

    daily = df.groupby("date").size().reset_index(name="checks")
    fig_line = px.line(
        daily,
        x="date",
        y="checks",
        markers=True,
        title="Number of URL Checks per Day"
    )
    st.plotly_chart(fig_line, use_container_width=True)

    st.subheader("Full History")
    show_cols = ["id", "username", "url", "risk_score", "label", "reasons", "checked_at"]
    existing_cols = [col for col in show_cols if col in df.columns]
    st.dataframe(df[existing_cols], use_container_width=True)


def show_admin_panel():
    st.divider()
    st.subheader("👑 Admin Panel")

    password = st.text_input("Enter Admin Password", type="password")

    if password != ADMIN_PASSWORD:
        st.warning("Admin access only.")
    else:
        st.success("Welcome Admin")

        all_df = load_all_history()
        activity_df = load_all_tool_activity()

        st.subheader("URL Scanner Data")

        if all_df.empty:
            st.info("No URL data yet.")
        else:
            users = all_df["username"].nunique()
            st.metric("Registered Active Users", users)

            show_advanced_dashboard(all_df, "Admin URL Dashboard")

            excel_file = convert_df_to_excel(all_df)

            st.download_button(
                label="📥 Export URL Data as Excel",
                data=excel_file,
                file_name="all_phishing_checks.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            )

            st.subheader("Delete URL Check")

            delete_id = st.number_input(
                "Enter URL record ID to delete:",
                min_value=1,
                step=1
            )

            if st.button("Delete URL Record"):
                delete_record(delete_id)
                st.success(f"Record ID {delete_id} deleted successfully.")
                st.rerun()

        st.divider()

        st.subheader("All User Tool Activity")

        if activity_df.empty:
            st.info("No tool activity yet.")
        else:
            tool_counts = activity_df["tool_name"].value_counts().reset_index()
            tool_counts.columns = ["tool_name", "count"]

            fig_tools = px.bar(
                tool_counts,
                x="tool_name",
                y="count",
                title="Tool Usage Count"
            )
            st.plotly_chart(fig_tools, use_container_width=True)

            st.dataframe(
                activity_df[[
                    "id", "username", "tool_name", "input_summary",
                    "risk_score", "label", "reasons", "checked_at"
                ]],
                use_container_width=True
            )

            activity_excel = convert_df_to_excel(activity_df)

            st.download_button(
                label="📥 Export All Tool Activity as Excel",
                data=activity_excel,
                file_name="all_tool_activity.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            )


# =========================
# SESSION STATE
# =========================
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if "username" not in st.session_state:
    st.session_state.username = ""

if "mode" not in st.session_state:
    st.session_state.mode = None


# =========================
# LOGIN / REGISTER
# =========================
if not st.session_state.logged_in:
    st.markdown("""
    <div class="cyber-card center-card">
        <div class="cyber-title">Welcome Back</div>
        <div class="cyber-subtitle">Sign in to access your protection dashboard</div>
    """, unsafe_allow_html=True)

    auth_tab1, auth_tab2 = st.tabs(["Login", "Register"])

    with auth_tab1:
        login_username = st.text_input("USERNAME", key="login_username", placeholder="Enter your username")
        login_password = st.text_input("PASSWORD", type="password", key="login_password", placeholder="Enter your password")

        if st.button("Sign In →"):
            if login_user(login_username, login_password):
                st.session_state.logged_in = True
                st.session_state.username = login_username
                st.session_state.mode = None
                st.success("Login successful")
                st.rerun()
            else:
                st.error("Invalid username or password")

    with auth_tab2:
        reg_username = st.text_input("CHOOSE USERNAME", key="reg_username", placeholder="Create username")
        reg_password = st.text_input("CHOOSE PASSWORD", type="password", key="reg_password", placeholder="Create password")

        if st.button("Create Account →"):
            if reg_username.strip() == "" or reg_password.strip() == "":
                st.warning("Please fill all fields")
            else:
                created = register_user(reg_username, reg_password)

                if created:
                    st.success("Account created. Please login.")
                else:
                    st.error("Username already exists")

    st.markdown("""
        <p style="text-align:center;color:#8da0b8;margin-top:25px;">
            Protected by enterprise-grade encryption
        </p>
    </div>
    """, unsafe_allow_html=True)

    st.stop()


# =========================
# SIDEBAR
# =========================
st.sidebar.success(f"Logged in as: {st.session_state.username}")
render_cyber_ai_assistant()
if st.sidebar.button("Logout"):
    st.session_state.logged_in = False
    st.session_state.username = ""
    st.session_state.mode = None
    st.rerun()

if st.sidebar.button("🔄 Change Mode"):
    st.session_state.mode = None
    st.rerun()


# =========================
# MODE SELECTION
# =========================
if st.session_state.mode is None:
    st.markdown('<div class="mode-title">Choose Your Mode</div>', unsafe_allow_html=True)
    st.markdown('<div class="mode-subtitle">Pick the experience tailored to your needs.</div>', unsafe_allow_html=True)

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("""
        <div class="mode-card">
            <div class="mode-icon-blue">👤</div>
            <div class="mode-label">PERSONAL MODE</div>
            <div class="mode-heading">Protect Myself</div>
            <p style="color:#a9b8cc;font-size:17px;">
                Use personal cybersecurity tools to protect yourself.
            </p>
            <div class="feature-line"><span class="feature-dot">🛡️</span> URL Scanner</div>
            <div class="feature-line"><span class="feature-dot">🛡️</span> Email / Message Analyzer</div>
            <div class="feature-line"><span class="feature-dot">🛡️</span> Password Analyzer</div>
            <div class="feature-line"><span class="feature-dot">🛡️</span> File Checker</div>
            <div class="feature-line"><span class="feature-dot">🛡️</span> Personal Dashboard</div>
            <br>
        </div>
        """, unsafe_allow_html=True)

        if st.button("Enter Protect Myself  →"):
            st.session_state.mode = "user"
            st.rerun()

    with col2:
        st.markdown("""
        <div class="mode-card">
            <div class="mode-icon-green">🏢</div>
            <div class="mode-label">ENTERPRISE MODE</div>
            <div class="mode-heading">Protect My Company</div>
            <p style="color:#a9b8cc;font-size:17px;">
                Run a full passive company security audit with reports and monitoring setup.
            </p>
            <div class="feature-line"><span class="feature-dot-green">🛡️</span> Domain Verification</div>
            <div class="feature-line"><span class="feature-dot-green">🛡️</span> Full Company Audit</div>
            <div class="feature-line"><span class="feature-dot-green">🛡️</span> Company Dashboard</div>
            <div class="feature-line"><span class="feature-dot-green">🛡️</span> PDF Reports</div>
            <div class="feature-line"><span class="feature-dot-green">🛡️</span> Monitoring Plan</div>
            <br>
        </div>
        """, unsafe_allow_html=True)

        if st.button("Enter Protect My Company  →"):
            st.session_state.mode = "company"
            st.rerun()

    st.stop()


# =========================
# COMPANY MODE — FULL PAGE
# =========================
if st.session_state.mode == "company":
    run_company_mode()
    show_admin_panel()
    st.stop()


# =========================
# USER MODE — LEVEL 1
# =========================
tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "URL Scanner",
    "Dashboard",
    "Email Analyzer",
    "Password Analyzer",
    "File Checker",
    "QR Scanner"
])


with tab1:
    st.subheader("🔗 URL Scanner")

    url = st.text_input("Enter URL")

    if st.button("Analyze URL"):
        if url.strip() == "":
            st.warning("Enter URL")
        else:
            label, risk, reasons, recommendations, positive_signals = analyze_url_logic(url)

            if risk >= 70:
                st.error(f"⚠️ {label}")
            elif risk >= 35:
                st.warning(f"⚠️ {label}")
            else:
                st.success(f"✅ {label}")

            checked_at = save_result(st.session_state.username, normalize_url(url), risk, label, reasons + recommendations)

            st.metric("Risk Score", f"{risk}%")

            st.subheader("Why this result?")
            for reason in reasons:
                st.write("- " + reason)

            st.subheader("Positive Signals")
            for signal in positive_signals:
                st.write("- " + signal)

            st.subheader("Recommendations")
            for rec in recommendations:
                st.write("- " + rec)

            st.subheader("Website Screenshot")
            screenshot_path = capture_screenshot(url)

            if screenshot_path:
                st.image(screenshot_path, caption="Website Preview", use_container_width=True)
                if str(screenshot_path).startswith("http"):
                    st.caption("Screenshot generated using a cloud-compatible preview service.")
            else:
                st.warning("Screenshot could not be generated for this website.")

            pdf = generate_pdf(
                url,
                risk,
                label,
                reasons + recommendations,
                checked_at,
                screenshot_path,
                st.session_state.username
            )

            st.download_button(
                label="Download PDF Report",
                data=pdf,
                file_name="phishing_url_report.pdf",
                mime="application/pdf"
            )


with tab2:
    user_df = load_user_history(st.session_state.username)
    show_advanced_dashboard(user_df, "Your Advanced Dashboard")


with tab3:
    st.subheader("📧 Email / Message Analyzer")

    message = st.text_area(
        "Paste an email, SMS, or WhatsApp message here:",
        height=180
    )

    if st.button("Analyze Message"):
        if message.strip() == "":
            st.warning("Please enter a message first.")
        else:
            label, risk, reasons = analyze_message(message)

            if risk >= 60:
                st.error(f"⚠️ {label}")
            elif risk >= 30:
                st.warning(f"⚠️ {label}")
            else:
                st.success(f"✅ {label}")

            st.metric("Message Risk Score", f"{risk}%")

            st.subheader("Analysis Reasons")
            for reason in reasons:
                st.write("- " + reason)

            summary = message[:120] + "..." if len(message) > 120 else message
            save_tool_activity(
                st.session_state.username,
                "Email Analyzer",
                summary,
                risk,
                label,
                reasons
            )


with tab4:
    st.subheader("🔐 Password Strength Analyzer")

    password_input = st.text_input(
        "Enter a password to analyze:",
        type="password"
    )

    if st.button("Analyze Password"):
        if password_input.strip() == "":
            st.warning("Please enter a password first.")
        else:
            label, score, reasons, tips = analyze_password(password_input)

            if score >= 75:
                st.success(f"✅ {label}")
            elif score >= 45:
                st.warning(f"⚠️ {label}")
            else:
                st.error(f"❌ {label}")

            st.metric("Password Strength Score", f"{score}%")

            st.subheader("Findings")
            for reason in reasons:
                st.write("- " + reason)

            st.subheader("Recommendations")
            for tip in tips:
                st.write("- " + tip)

            password_summary = f"Password length: {len(password_input)} characters"
            all_notes = reasons + tips

            save_tool_activity(
                st.session_state.username,
                "Password Analyzer",
                password_summary,
                score,
                label,
                all_notes
            )


with tab5:
    st.subheader("📁 File Risk Checker")
    st.info("This checker performs local static analysis using file signature, MIME guess, hash, size, entropy, extension mismatch, archive/macro indicators, and suspicious content patterns. It is not a full antivirus replacement.")

    uploaded_file = st.file_uploader("Upload a file to analyze:")

    if uploaded_file is not None:
        if st.button("Analyze File"):
            label, risk, reasons, tips, file_hash, mime_type = analyze_file(uploaded_file)

            if risk >= 60:
                st.error(f"⚠️ {label}")
            elif risk >= 30:
                st.warning(f"⚠️ {label}")
            else:
                st.success(f"✅ {label}")

            st.metric("File Risk Score", f"{risk}%")

            st.subheader("File Information")
            st.write(f"Name: {uploaded_file.name}")
            st.write(f"Size: {round(uploaded_file.size / 1024, 2)} KB")
            st.write(f"MIME Type: {mime_type}")
            st.write(f"SHA-256 Hash: {file_hash}")

            st.subheader("Why this result?")
            for reason in reasons:
                st.write("- " + reason)

            st.subheader("Recommendations")
            for tip in tips:
                st.write("- " + tip)

            summary = f"{uploaded_file.name} | {round(uploaded_file.size / 1024, 2)} KB"

            save_tool_activity(
                st.session_state.username,
                "File Checker",
                summary,
                risk,
                label,
                reasons + tips
            )


with tab6:
    st.subheader("QR Code Scanner")

    st.write("Scan QR codes by uploading an image or using your camera.")

    scan_method = st.radio(
        "Choose scan method:",
        ["Upload QR Image", "Use Camera"],
        horizontal=True
    )

    qr_source = None

    if scan_method == "Upload QR Image":
        qr_source = st.file_uploader(
            "Upload QR Code Image",
            type=["png", "jpg", "jpeg"],
            key="qr_uploader"
        )

        if qr_source is not None:
            st.image(qr_source, caption="Uploaded QR Code", use_container_width=True)

    else:
        st.info("Open this project from your phone or laptop and allow camera permission.")
        qr_source = st.camera_input("Take a QR Code Photo", key="qr_camera")

        if qr_source is not None:
            st.image(qr_source, caption="Captured QR Code", use_container_width=True)

    if qr_source is not None:
        decoded_text, error = decode_qr_image(qr_source)

        if error:
            st.error(error)
        elif not decoded_text:
            st.warning("No readable QR code was detected. Try a clearer image or move the camera closer.")
        else:
            st.success("QR Code decoded successfully.")
            st.write("Decoded Content:")
            st.code(decoded_text)

            if decoded_text.startswith("http://") or decoded_text.startswith("https://"):
                label, risk, reasons, recommendations, positive_signals = analyze_url_logic(decoded_text)

                if risk >= 70:
                    st.error(label)
                elif risk >= 35:
                    st.warning(label)
                else:
                    st.success(label)

                st.metric("QR URL Risk Score", f"{risk}%")

                st.subheader("Why this result?")
                for reason in reasons:
                    st.write("- " + reason)

                st.subheader("Positive Signals")
                for signal in positive_signals:
                    st.write("- " + signal)

                st.subheader("Recommendations")
                for rec in recommendations:
                    st.write("- " + rec)

                checked_at = save_result(
                    st.session_state.username,
                    normalize_url(decoded_text),
                    risk,
                    label,
                    reasons + recommendations
                )

                st.session_state.last_url_scan = {
                    "source": "QR Scanner",
                    "url": decoded_text,
                    "risk_score": risk,
                    "label": label,
                    "reasons": reasons,
                    "checked_at": checked_at
                }

                st.info("The QR link was saved in your URL history and dashboard.")
            else:
                st.warning("The QR code does not contain a URL. It contains text only.")

                save_tool_activity(
                    st.session_state.username,
                    "QR Scanner",
                    decoded_text[:120],
                    0,
                    "Text QR",
                    ["QR code contains text, not a URL."]
                )

