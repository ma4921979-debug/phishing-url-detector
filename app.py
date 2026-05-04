import streamlit as st
import sqlite3
import pandas as pd
import joblib
import io
import os
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from playwright.sync_api import sync_playwright

# ---------------- CONFIG ----------------
st.set_page_config(page_title="Phishing Detector", layout="wide")
st.title("🛡️ AI Phishing URL Detector")

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
            url TEXT,
            risk_score INTEGER,
            label TEXT,
            reasons TEXT,
            checked_at TEXT
        )
    """)
    conn.commit()
    conn.close()

create_db()

def save_result(url, risk_score, label, reasons):
    conn = sqlite3.connect("phishing_history.db")
    cursor = conn.cursor()
    time_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        INSERT INTO url_checks (url, risk_score, label, reasons, checked_at)
        VALUES (?, ?, ?, ?, ?)
    """, (url, risk_score, label, ", ".join(reasons), time_now))

    conn.commit()
    conn.close()
    return time_now

def load_history():
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
    features["Shortining_Service"] = 1 if "bit.ly" in url_lower else -1
    features["having_At_Symbol"] = 1 if "@" in url else -1
    features["double_slash_redirecting"] = 1 if "//" in url[8:] else -1
    features["Prefix_Suffix"] = 1 if "-" in url else -1
    features["having_Sub_Domain"] = 1 if url.count(".") > 2 else -1
    features["SSLfinal_State"] = 1 if url_lower.startswith("https://") else -1

    for col in feature_columns:
        if col not in features:
            features[col] = 0

    return pd.DataFrame([features])[feature_columns]

# ---------------- EXPLAIN ----------------
def explain_url(url):
    risk = 0
    reasons = []

    if url.startswith("http://"):
        risk += 25
        reasons.append("Uses HTTP")

    if "@" in url:
        risk += 25
        reasons.append("Contains @")

    if "-" in url:
        risk += 10
        reasons.append("Contains -")

    if len(url) > 80:
        risk += 15
        reasons.append("Long URL")

    words = ["login", "verify", "account", "bank", "paypal"]
    for w in words:
        if w in url.lower():
            risk += 10
            reasons.append(f"Suspicious word: {w}")

    return min(risk, 100), reasons

# ---------------- SCREENSHOT ----------------
def capture_screenshot(url):
    os.makedirs("screenshots", exist_ok=True)
    path = "screenshots/site.png"

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=True)
            page = context.new_page()

            page.goto(url, timeout=20000)
            page.screenshot(path=path, full_page=True)

            browser.close()

        return path
    except:
        return None

# ---------------- PDF ----------------
def generate_pdf(url, risk, label, reasons, time_now, screenshot_path):
    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)

    y = 750
    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(50, y, "Phishing Report")

    y -= 40
    pdf.setFont("Helvetica", 12)

    pdf.drawString(50, y, f"URL: {url}")
    y -= 20
    pdf.drawString(50, y, f"Result: {label}")
    y -= 20
    pdf.drawString(50, y, f"Risk: {risk}%")
    y -= 20
    pdf.drawString(50, y, f"Time: {time_now}")

    y -= 30
    pdf.drawString(50, y, "Reasons:")

    for r in reasons:
        y -= 15
        pdf.drawString(60, y, f"- {r}")

    # Screenshot
    y -= 200
    pdf.drawString(50, y + 180, "Screenshot:")

    if screenshot_path and os.path.exists(screenshot_path):
        try:
            pdf.drawImage(screenshot_path, 50, y, width=500, height=200)
        except:
            pdf.drawString(60, y + 150, "Could not load image")
    else:
        pdf.drawString(60, y + 150, "No screenshot")

    pdf.save()
    buffer.seek(0)
    return buffer

# ---------------- UI ----------------
tab1, tab2 = st.tabs(["Scanner", "Dashboard"])

with tab1:
    url = st.text_input("Enter URL")

    if st.button("Analyze"):
        if url == "":
            st.warning("Enter URL")
        else:
            features = extract_features(url)
            pred = model.predict(features)[0]

            risk, reasons = explain_url(url)

            if pred == -1:
                label = "Phishing"
                st.error("⚠️ Phishing URL")
            else:
                label = "Safe"
                st.success("✅ Safe URL")

            time_now = save_result(url, risk, label, reasons)

            st.metric("Risk", f"{risk}%")

            st.subheader("Reasons")
            for r in reasons:
                st.write("- " + r)

            # Screenshot
            st.subheader("Screenshot")
            img = capture_screenshot(url)

            if img:
                st.image(img)
            else:
                st.warning("Screenshot failed")

            # PDF
            pdf = generate_pdf(url, risk, label, reasons, time_now, img)

            st.download_button("Download PDF", pdf)

with tab2:
    df = load_history()

    if df.empty:
        st.write("No data")
    else:
        st.dataframe(df)
        st.bar_chart(df["label"].value_counts())