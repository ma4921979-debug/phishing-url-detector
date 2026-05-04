import streamlit as st
import sqlite3
import pandas as pd
import joblib
import io
import os
import uuid
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from playwright.sync_api import sync_playwright

# ---------------- CONFIG ----------------
st.set_page_config(page_title="Phishing Detector", layout="wide")
st.title("🛡️ AI Phishing URL Detector")

ADMIN_PASSWORD = "MOHAMMAD20@04"  

# ---------------- SESSION ----------------
if "session_id" not in st.session_state:
    st.session_state.session_id = str(uuid.uuid4())

session_id = st.session_state.session_id

# ---------------- LOAD MODEL ----------------
model = joblib.load("model.pkl")
feature_columns = joblib.load("feature_columns.pkl")

# ---------------- DATABASE ----------------
def create_db():
    conn = sqlite3.connect("phishing_history.db")
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS url_checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT,
            url TEXT,
            risk_score INTEGER,
            label TEXT,
            reasons TEXT,
            checked_at TEXT
        )
    """)

    cursor.execute("PRAGMA table_info(url_checks)")
    columns = [col[1] for col in cursor.fetchall()]

    if "session_id" not in columns:
        cursor.execute("ALTER TABLE url_checks ADD COLUMN session_id TEXT")

    conn.commit()
    conn.close()


create_db()


def save_result(session_id, url, risk_score, label, reasons):
    conn = sqlite3.connect("phishing_history.db")
    cursor = conn.cursor()

    checked_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        INSERT INTO url_checks (session_id, url, risk_score, label, reasons, checked_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        session_id,
        url,
        risk_score,
        label,
        ", ".join(reasons),
        checked_at
    ))

    conn.commit()
    conn.close()
    return checked_at


def load_user_history(session_id):
    conn = sqlite3.connect("phishing_history.db")
    df = pd.read_sql_query(
        "SELECT * FROM url_checks WHERE session_id = ? ORDER BY id DESC",
        conn,
        params=(session_id,)
    )
    conn.close()
    return df


def load_all_history():
    conn = sqlite3.connect("phishing_history.db")
    df = pd.read_sql_query("SELECT * FROM url_checks ORDER BY id DESC", conn)
    conn.close()
    return df


# ---------------- FEATURE EXTRACTION ----------------
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


# ---------------- EXPLANATION ----------------
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


# ---------------- SCREENSHOT ----------------
def capture_screenshot(url):
    os.makedirs("screenshots", exist_ok=True)
    path = f"screenshots/{session_id}.png"

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


# ---------------- PDF ----------------
def generate_pdf(url, risk, label, reasons, checked_at, screenshot_path, session_id):
    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)

    y = 750
    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(50, y, "Phishing URL Analysis Report")

    y -= 40
    pdf.setFont("Helvetica", 12)
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

    history_df = load_user_history(session_id)

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


# ---------------- UI ----------------
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

            checked_at = save_result(session_id, url, risk, label, reasons)

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

            pdf = generate_pdf(url, risk, label, reasons, checked_at, screenshot_path, session_id)

            st.download_button(
                label="Download PDF Report",
                data=pdf,
                file_name="phishing_url_report.pdf",
                mime="application/pdf"
            )


with tab2:
    st.subheader("Dashboard")

    history_df = load_user_history(session_id)

    if history_df.empty:
        st.info("No URL checks yet for your session.")
    else:
        total = len(history_df)
        phishing = len(history_df[history_df["label"] == "High Risk / Phishing"])
        safe = len(history_df[history_df["label"] == "Low Risk / Safe"])
        avg = round(history_df["risk_score"].mean(), 2)

        col1, col2, col3, col4 = st.columns(4)

        col1.metric("Total Checks", total)
        col2.metric("High Risk", phishing)
        col3.metric("Safe URLs", safe)
        col4.metric("Average Risk", f"{avg}%")

        st.subheader("Risk Distribution")
        st.bar_chart(history_df["label"].value_counts())

        st.subheader("Your Check History")
        st.dataframe(
            history_df[["url", "risk_score", "label", "reasons", "checked_at"]],
            use_container_width=True
        )


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
            total = len(all_df)
            phishing = len(all_df[all_df["label"] == "High Risk / Phishing"])
            safe = len(all_df[all_df["label"] == "Low Risk / Safe"])
            avg = round(all_df["risk_score"].mean(), 2)
            users = all_df["session_id"].nunique()

            col1, col2, col3, col4, col5 = st.columns(5)

            col1.metric("Total Checks", total)
            col2.metric("Users", users)
            col3.metric("High Risk", phishing)
            col4.metric("Safe URLs", safe)
            col5.metric("Average Risk", f"{avg}%")

            st.subheader("All Users Risk Distribution")
            st.bar_chart(all_df["label"].value_counts())

            st.subheader("All Checked URLs")
            st.dataframe(
                all_df[["session_id", "url", "risk_score", "label", "reasons", "checked_at"]],
                use_container_width=True
            )