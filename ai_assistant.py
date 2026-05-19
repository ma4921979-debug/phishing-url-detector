
import streamlit as st
import streamlit.components.v1 as components


def render_cyber_ai_assistant():
    components.html(
        """
        <style>
        .ai-float-btn {
            position: fixed;
            right: 40px;
            bottom: 90px;
            width: 95px;
            height: 95px;
            border-radius: 24px;
            background: linear-gradient(135deg, #020814, #0f172a);
            border: 1px solid rgba(0, 229, 255, 0.35);
            box-shadow: 0 0 30px rgba(0, 229, 255, 0.45);
            z-index: 999999;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 13px;
            font-weight: 800;
            flex-direction: column;
            transition: 0.25s;
        }

        .ai-float-btn:hover {
            transform: scale(1.05);
            box-shadow: 0 0 38px rgba(0, 229, 255, 0.6);
        }

        .ai-float-btn span {
            font-size: 30px;
            margin-bottom: 3px;
        }

        .ai-chat-box {
            position: fixed;
            right: 24px;
            bottom: 1px;
            width: 390px;
            height: 560px;
            background: rgba(8, 20, 40, 0.98);
            border: 1px solid rgba(0, 229, 255, 0.22);
            border-radius: 24px;
            box-shadow: 0 0 45px rgba(0, 0, 0, 0.65);
            z-index: 999999;
            display: none;
            overflow: hidden;
            font-family: Arial, sans-serif;
        }

        .ai-top {
            padding: 18px;
            background: linear-gradient(90deg, #06172c, #0f172a);
            border-bottom: 1px solid rgba(0,229,255,0.15);
        }

        .ai-chat-title {
            font-size: 20px;
            font-weight: 800;
            color: white;
        }

        .ai-chat-sub {
            color: #9fb0c7;
            font-size: 13px;
            margin-top: 6px;
            line-height: 1.4;
        }

        .ai-messages {
            height: 340px;
            overflow-y: auto;
            padding: 16px;
            color: white;
            font-size: 13px;
            line-height: 1.6;
            background: rgba(255,255,255,0.02);
        }

        .ai-user {
            margin-top: 14px;
            background: rgba(0,140,255,0.18);
            padding: 10px;
            border-radius: 12px;
        }

        .ai-bot {
            margin-top: 10px;
            background: rgba(255,255,255,0.06);
            padding: 10px;
            border-radius: 12px;
        }

        .ai-bottom {
            padding: 14px;
            border-top: 1px solid rgba(255,255,255,0.08);
            background: rgba(6,16,32,0.98);
        }

        .ai-input {
            width: 100%;
            height: 62px;
            border-radius: 14px;
            border: 1px solid rgba(0,229,255,0.28);
            background: rgba(20,39,62,0.95);
            color: white;
            padding: 10px;
            resize: none;
            outline: none;
            font-size: 13px;
        }

        .ai-send {
            margin-top: 10px;
            width: 100%;
            height: 44px;
            border-radius: 14px;
            border: none;
            background: linear-gradient(90deg, #008cff, #00e5ff);
            font-weight: 800;
            cursor: pointer;
            transition: 0.25s;
        }

        .ai-send:hover {
            transform: scale(1.01);
        }
        </style>

        <div class="ai-float-btn" onclick="toggleAI()">
            <span>✦</span>
            Cyber AI
        </div>

        <div class="ai-chat-box" id="aiChatBox">

            <div class="ai-top">
                <div class="ai-chat-title">Cyber AI Assistant</div>

                <div class="ai-chat-sub">
                    Ask me about phishing, ports, SSL, CVE, QR scans, passwords,
                    file analysis, monitoring, dashboards, Nmap, or project features.
                </div>
            </div>

            <div class="ai-messages" id="aiMessages">
                <div class="ai-bot">
                    <b>AI:</b><br>
                    Hello, I am your AI Cybersecurity Assistant.<br><br>
                    I can help explain:
                    <ul>
                        <li>URL Scanner</li>
                        <li>Email Analyzer</li>
                        <li>Password Security</li>
                        <li>File Checker</li>
                        <li>QR Scanner</li>
                        <li>Nmap Results</li>
                        <li>CVE Vulnerabilities</li>
                        <li>Company Audits</li>
                        <li>Monitoring Alerts</li>
                    </ul>
                </div>
            </div>

            <div class="ai-bottom">
                <textarea class="ai-input" id="aiInput" placeholder="Ask your cybersecurity question..."></textarea>
                <button class="ai-send" onclick="sendAI()">Send</button>
            </div>

        </div>

        <script>
        function toggleAI() {
            const box = document.getElementById("aiChatBox");

            if (box.style.display === "none" || box.style.display === "") {
                box.style.display = "block";
            } else {
                box.style.display = "none";
            }
        }

        function generateAIAnswer(q) {

            let lower = q.toLowerCase();

            if (lower.includes("url") || lower.includes("phishing")) {
                return `
                The URL Scanner analyzes websites using:
                <ul>
                    <li>HTTPS detection</li>
                    <li>Suspicious keywords</li>
                    <li>URL structure</li>
                    <li>Subdomains</li>
                    <li>Machine learning prediction</li>
                </ul>

                High-risk URLs may indicate phishing attempts or fake login pages.
                `;
            }

            if (lower.includes("password")) {
                return `
                The Password Analyzer checks:
                <ul>
                    <li>Password length</li>
                    <li>Uppercase and lowercase characters</li>
                    <li>Numbers</li>
                    <li>Special symbols</li>
                    <li>Common patterns</li>
                </ul>

                Strong passwords reduce brute-force attack risks.
                `;
            }

            if (lower.includes("file")) {
                return `
                The File Checker performs risk-based analysis using:
                <ul>
                    <li>File extension</li>
                    <li>MIME type</li>
                    <li>File signatures</li>
                    <li>Entropy analysis</li>
                    <li>Script and macro detection</li>
                </ul>

                Executable and suspicious script files are classified with higher risk.
                `;
            }

            if (lower.includes("qr")) {
                return `
                The QR Scanner extracts URLs from QR codes and automatically analyzes them using the phishing detection engine.
                It also supports live camera scanning from mobile devices.
                `;
            }

            if (lower.includes("ssl") || lower.includes("https")) {
                return `
                SSL certificates protect encrypted communication between users and websites.

                The system checks:
                <ul>
                    <li>Certificate validity</li>
                    <li>Expiration dates</li>
                    <li>Encryption trust</li>
                </ul>

                Invalid SSL may expose users to man-in-the-middle attacks.
                `;
            }

            if (lower.includes("port") || lower.includes("nmap")) {
                return `
                Nmap scanning identifies:
                <ul>
                    <li>Open ports</li>
                    <li>Running services</li>
                    <li>Detected versions</li>
                    <li>Exposed protocols</li>
                </ul>

                Sensitive services such as SSH, FTP, MySQL, and RDP should be protected.
                `;
            }

            if (lower.includes("cve") || lower.includes("vulnerability")) {
                return `
                CVE Detection compares detected service versions against known vulnerability databases.

                The platform uses:
                <ul>
                    <li>NVD API</li>
                    <li>Heuristic analysis</li>
                    <li>Version-based detection</li>
                </ul>

                This helps identify potentially vulnerable services.
                `;
            }

            if (lower.includes("monitor") || lower.includes("alert")) {
                return `
                The monitoring system compares scans over time and detects:
                <ul>
                    <li>New open ports</li>
                    <li>SSL failures</li>
                    <li>Risk score changes</li>
                    <li>Missing security headers</li>
                </ul>
                `;
            }

            if (lower.includes("dashboard")) {
                return `
                The dashboard visualizes:
                <ul>
                    <li>Risk statistics</li>
                    <li>Audit history</li>
                    <li>Monitoring trends</li>
                    <li>Security scores</li>
                </ul>
                `;
            }

            if (lower.includes("recommend")) {
                return `
                General security recommendations:
                <ul>
                    <li>Enable HTTPS and HSTS</li>
                    <li>Close unnecessary ports</li>
                    <li>Use strong passwords</li>
                    <li>Keep services updated</li>
                    <li>Restrict SSH and RDP access</li>
                </ul>
                `;
            }

            return `
            I can help explain:
            <ul>
                <li>Phishing detection</li>
                <li>QR scanning</li>
                <li>Password security</li>
                <li>File risk analysis</li>
                <li>Nmap scanning</li>
                <li>CVE vulnerabilities</li>
                <li>SSL certificates</li>
                <li>Monitoring alerts</li>
                <li>Dashboard statistics</li>
            </ul>

            Try asking:
            <ul>
                <li>What is phishing?</li>
                <li>Why is SSH dangerous?</li>
                <li>Explain CVE vulnerabilities</li>
                <li>How does QR scanning work?</li>
            </ul>
            `;
        }

        function sendAI() {

            const input = document.getElementById("aiInput");
            const messages = document.getElementById("aiMessages");

            const q = input.value.trim();

            if (!q) return;

            const answer = generateAIAnswer(q);

            messages.innerHTML += `
                <div class="ai-user">
                    <b>You:</b><br>${q}
                </div>

                <div class="ai-bot">
                    <b>AI:</b><br>${answer}
                </div>
            `;

            input.value = "";

            messages.scrollTop = messages.scrollHeight;
        }
        </script>
        """,
        height=0,
        width=0
    )
