import streamlit as st
import sqlite3
import pandas as pd
import joblib
import io
import os
import hashlib
import mimetypes
import plotly.express as px
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from playwright.sync_api import sync_playwright
from company_mode import run_company_mode

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


def explain_url(url):
    risk = 0
    reasons = []
    url_lower = url.lower()

    if url_lower.startswith("http://"):
        risk += 25
        reasons.append("Uses HTTP instead of HTTPS")

    if "@" in url:
        risk += 25
        reasons.append("Contains @ symbol")

    if "-" in url:
        risk += 10
        reasons.append("Contains dash symbol")

    if len(url) > 80:
        risk += 15
        reasons.append("URL is too long")

    if url.count(".") > 3:
        risk += 15
        reasons.append("Too many subdomains")

    suspicious_words = ["login", "verify", "account", "bank", "paypal", "update", "secure"]

    for word in suspicious_words:
        if word in url_lower:
            risk += 10
            reasons.append(f"Suspicious word: {word}")

    risk = min(risk, 100)

    if not reasons:
        reasons.append("No clear suspicious indicators found")

    return risk, reasons


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


def analyze_file(uploaded_file):
    risk = 0
    reasons = []
    tips = []

    file_name = uploaded_file.name
    file_size = uploaded_file.size
    file_extension = os.path.splitext(file_name)[1].lower()
    mime_type, _ = mimetypes.guess_type(file_name)

    dangerous_extensions = [
        ".exe", ".bat", ".cmd", ".scr", ".js", ".vbs",
        ".ps1", ".jar", ".msi", ".dll", ".com"
    ]

    suspicious_extensions = [
        ".zip", ".rar", ".7z", ".docm", ".xlsm", ".pptm"
    ]

    if file_extension in dangerous_extensions:
        risk += 60
        reasons.append(f"Dangerous file extension: {file_extension}")
        tips.append("Do NOT open executable files from unknown sources.")

    elif file_extension in suspicious_extensions:
        risk += 35
        reasons.append(f"Suspicious file extension: {file_extension}")
        tips.append("Scan compressed or macro-enabled files before opening.")

    else:
        reasons.append("File extension looks normal.")

    if file_size > 10 * 1024 * 1024:
        risk += 15
        reasons.append("Large file size detected.")
        tips.append("Large files should be verified carefully.")

    file_bytes = uploaded_file.getvalue()
    file_hash = hashlib.sha256(file_bytes).hexdigest()

    risk = min(risk, 100)

    if risk >= 60:
        label = "High Risk File"
    elif risk >= 30:
        label = "Medium Risk File"
    else:
        label = "Low Risk File"

    if not tips:
        tips.append("File seems safe, but always verify the source before opening.")

    return label, risk, reasons, tips, file_hash, mime_type


def capture_screenshot(url):
    os.makedirs("screenshots", exist_ok=True)
    safe_name = st.session_state.username.replace(" ", "_")
    path = f"screenshots/{safe_name}.png"

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=True)
            page = context.new_page()
            page.goto(url, timeout=20000, wait_until="domcontentloaded")
            page.screenshot(path=path, full_page=True)
            browser.close()
        return path
    except Exception:
        return None


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

    if screenshot_path and os.path.exists(screenshot_path):
        try:
            pdf.drawImage(
                screenshot_path,
                50,
                y,
                width=500,
                height=200,
                preserveAspectRatio=True,
                mask="auto"
            )
        except Exception:
            pdf.drawString(60, y + 180, "Screenshot could not be added.")
    else:
        pdf.drawString(60, y + 180, "No screenshot available.")

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
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "URL Scanner",
    "Dashboard",
    "Email Analyzer",
    "Password Analyzer",
    "File Checker"
])


with tab1:
    st.subheader("🔗 URL Scanner")

    url = st.text_input("Enter URL")

    if st.button("Analyze URL"):
        if url.strip() == "":
            st.warning("Enter URL")
        else:
            features = extract_features(url)
            prediction = model.predict(features)[0]

            rule_risk, reasons = explain_url(url)

            if prediction == -1:
                label = "High Risk / Phishing"
                risk = max(rule_risk, 70)
                st.error("⚠️ High Risk / Phishing")
            else:
                label = "Low Risk / Safe"
                risk = min(rule_risk, 20)
                st.success("✅ Low Risk / Safe")

            checked_at = save_result(st.session_state.username, url, risk, label, reasons)

            st.metric("Risk Score", f"{risk}%")

            st.subheader("Analysis Reasons")
            for reason in reasons:
                st.write("- " + reason)

            st.subheader("Website Screenshot")
            screenshot_path = capture_screenshot(url)

            if screenshot_path:
                st.image(screenshot_path, caption="Website Preview", use_container_width=True)
            else:
                st.warning("Screenshot failed or website could not be opened.")

            pdf = generate_pdf(
                url,
                risk,
                label,
                reasons,
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

            st.subheader("Analysis Reasons")
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