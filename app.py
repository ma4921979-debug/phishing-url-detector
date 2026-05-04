import streamlit as st
import sqlite3
import pandas as pd
import joblib
import io
import os
import hashlib
import plotly.express as px
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from playwright.sync_api import sync_playwright

st.set_page_config(page_title="Phishing Detector", layout="wide")
st.title("🛡️ AI Phishing URL Detector")

ADMIN_PASSWORD = "admin123"  # غيّرها

model = joblib.load("model.pkl")
feature_columns = joblib.load("feature_columns.pkl")


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

    cursor.execute("PRAGMA table_info(url_checks)")
    columns = [col[1] for col in cursor.fetchall()]

    if "username" not in columns:
        cursor.execute("ALTER TABLE url_checks ADD COLUMN username TEXT")

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


def delete_record(record_id):
    conn = sqlite3.connect("phishing_history.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM url_checks WHERE id = ?", (record_id,))
    conn.commit()
    conn.close()


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

    pdf.showPage()

    history_df = load_user_history(username)

    y = 750
    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(50, y, "Dashboard Summary - Current User")

    y -= 35
    pdf.setFont("Helvetica", 12)

    if not history_df.empty:
        total = len(history_df)
        phishing = len(history_df[history_df["label"] == "High Risk / Phishing"])
        safe = len(history_df[history_df["label"] == "Low Risk / Safe"])
        avg = round(history_df["risk_score"].mean(), 2)

        pdf.drawString(60, y, f"Total Checks: {total}")
        y -= 20
        pdf.drawString(60, y, f"High Risk URLs: {phishing}")
        y -= 20
        pdf.drawString(60, y, f"Safe URLs: {safe}")
        y -= 20
        pdf.drawString(60, y, f"Average Risk Score: {avg}%")
    else:
        pdf.drawString(60, y, "No dashboard data available.")

    pdf.save()
    buffer.seek(0)
    return buffer


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

    col_c, col_d = st.columns(2)

    with col_c:
        st.subheader("Top 5 Risky URLs")
        top_risky = df.sort_values("risk_score", ascending=False).head(5)
        st.dataframe(
            top_risky[["url", "risk_score", "label", "checked_at"]],
            use_container_width=True
        )

    with col_d:
        st.subheader("Latest 10 Checks")
        latest = df.sort_values("checked_at", ascending=False).head(10)
        st.dataframe(
            latest[["url", "risk_score", "label", "checked_at"]],
            use_container_width=True
        )

    st.subheader("Full History")

    show_cols = ["id", "username", "url", "risk_score", "label", "reasons", "checked_at"]
    existing_cols = [col for col in show_cols if col in df.columns]

    st.dataframe(df[existing_cols], use_container_width=True)


if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if "username" not in st.session_state:
    st.session_state.username = ""


if not st.session_state.logged_in:
    auth_tab1, auth_tab2 = st.tabs(["Login", "Register"])

    with auth_tab1:
        st.subheader("Login")
        login_username = st.text_input("Username", key="login_username")
        login_password = st.text_input("Password", type="password", key="login_password")

        if st.button("Login"):
            if login_user(login_username, login_password):
                st.session_state.logged_in = True
                st.session_state.username = login_username
                st.success("Login successful")
                st.rerun()
            else:
                st.error("Invalid username or password")

    with auth_tab2:
        st.subheader("Register")
        reg_username = st.text_input("Choose username", key="reg_username")
        reg_password = st.text_input("Choose password", type="password", key="reg_password")

        if st.button("Create Account"):
            if reg_username.strip() == "" or reg_password.strip() == "":
                st.warning("Please fill all fields")
            else:
                created = register_user(reg_username, reg_password)

                if created:
                    st.success("Account created. Please login.")
                else:
                    st.error("Username already exists")

    st.stop()


st.sidebar.success(f"Logged in as: {st.session_state.username}")

if st.sidebar.button("Logout"):
    st.session_state.logged_in = False
    st.session_state.username = ""
    st.rerun()


tab1, tab2, tab3 = st.tabs(["Scanner", "Dashboard", "Admin Panel"])

with tab1:
    url = st.text_input("Enter URL")

    if st.button("Analyze"):
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
    st.subheader("Admin Panel")

    password = st.text_input("Enter Admin Password", type="password")

    if password != ADMIN_PASSWORD:
        st.warning("Admin access only.")
    else:
        st.success("Welcome Admin")

        all_df = load_all_history()

        if all_df.empty:
            st.info("No data yet.")
        else:
            users = all_df["username"].nunique()

            st.metric("Registered Active Users", users)

            show_advanced_dashboard(all_df, "Admin Advanced Dashboard")

            excel_file = convert_df_to_excel(all_df)

            st.download_button(
                label="📥 Export All Data as Excel",
                data=excel_file,
                file_name="all_phishing_checks.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            )

            st.subheader("Delete URL Check")

            delete_id = st.number_input(
                "Enter record ID to delete:",
                min_value=1,
                step=1
            )

            if st.button("Delete Record"):
                delete_record(delete_id)
                st.success(f"Record ID {delete_id} deleted successfully.")
                st.rerun()