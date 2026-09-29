import streamlit as st
import requests
import pandas as pd

st.set_page_config(
    page_title="Phishing Email Detection & Awareness Dashboard",
    page_icon="🛡️",
    layout="wide"
)

API_URL = "http://localhost:5000/api"

st.sidebar.title("🛡️ Navigation")
menu = st.sidebar.selectbox("Select Module", ["Dashboard & Analytics", "Email Analyzer", "Analysis History", "Phishing Awareness Training"])

# ----------------- DASHBOARD & ANALYTICS -----------------
if menu == "Dashboard & Analytics":
    st.title("🛡️ SOC Threat Intelligence & Analytics Dashboard")
    st.markdown("Real-time metrics and detection analytics for inbound email security triage.")
    
    try:
        stats_res = requests.get(f"{API_URL}/dashboard/stats").json()
        col1, col2, col3, col4, col5 = st.columns(5)
        col1.metric("Total Analyzed", stats_res.get("total_emails", 0))
        col2.metric("High Risk / Phish", stats_res.get("high_risk", 0))
        col3.metric("Suspicious", stats_res.get("suspicious", 0))
        col4.metric("Safe / Low Risk", stats_res.get("safe_count", 0))
        col5.metric("Avg Risk Score", f"{stats_res.get('average_risk_score', 0)}/100")
    except Exception as e:
        st.warning("[!] Backend API not reachable. Make sure Flask app.py is running on port 5000.")

    st.markdown("---")
    st.subheader("📊 System Telemetry & Detection Distribution")
    try:
        analyses_res = requests.get(f"{API_URL}/analyses").json()
        if analyses_res:
            df = pd.DataFrame(analyses_res)
            st.bar_chart(df['classification'].value_counts())
            st.line_chart(df.set_index('created_at')['risk_score'])
        else:
            st.info("No analysis history recorded yet. Use the Email Analyzer tab to analyze samples.")
    except:
        st.info("Start the backend API to view analytics charts.")

# ----------------- EMAIL ANALYZER -----------------
elif menu == "Email Analyzer":
    st.title("✉️ Phishing Email Analyzer")
    st.markdown("Paste email metadata and content to evaluate risk, inspect URLs, and generate explainable findings.")
    
    with st.form("email_form"):
        sender = st.text_input("Sender Email Address", "security-alert@account-check.invalid.test")
        subject = st.text_input("Email Subject", "URGENT: Verify Your Account Immediately")
        body = st.text_area("Email Body Content", "Dear user, unusual sign-in activity was detected. Verify your password immediately or your account will be suspended within 24 hours.")
        urls = st.text_input("Extracted URLs (separated by |)", "http://198.51.100.10/verify-account")
        attachment = st.text_input("Attachment Filename (Optional)", "invoice.pdf.exe")
        
        submitted = st.form_submit_button("ANALYZE EMAIL")
        
        if submitted:
            payload = {
                "sender": sender,
                "subject": subject,
                "body": body,
                "urls": urls,
                "attachment_name": attachment
            }
            try:
                res = requests.post(f"{API_URL}/analyze", json=payload)
                if res.status_code == 200:
                    data = res.json()
                    score = data["risk_score"]
                    classification = data["classification"]
                    
                    st.markdown("---")
                    st.subheader("🔍 Analysis Results")
                    
                    if "HIGH RISK" in classification:
                        st.error(f"**CLASSIFICATION: {classification}** (Risk Score: {score}/100)")
                    elif "SUSPICIOUS" in classification:
                        st.warning(f"**CLASSIFICATION: {classification}** (Risk Score: {score}/100)")
                    else:
                        st.success(f"**CLASSIFICATION: {classification}** (Risk Score: {score}/100)")
                        
                    st.markdown("### Why? (Explained Findings)")
                    for finding in data["findings"]:
                        st.markdown(f"- ⚠️ {finding}")
                        
                    st.markdown("### 🛡️ Recommended Security Actions")
                    st.markdown("""
                    - Do not click any links or download attachments.
                    - Verify the sender independently through a known trusted channel.
                    - Report this email to your organization's SOC/Security team.
                    - Access services directly via official bookmarks or applications.
                    """)
                else:
                    st.error("Error connecting to detection engine API.")
            except Exception as ex:
                st.error(f"Failed to reach backend API: {ex}")

# ----------------- ANALYSIS HISTORY -----------------
elif menu == "Analysis History":
    st.title("📂 Threat Analysis History")
    st.markdown("Past email analysis metadata stored in secure local SQLite database.")
    try:
        res = requests.get(f"{API_URL}/analyses").json()
        if res:
            df = pd.DataFrame(res)
            st.dataframe(df, use_container_width=True)
        else:
            st.info("No records found.")
    except:
        st.warning("Backend API not reachable.")

# ----------------- PHISHING AWARENESS MODULE -----------------
elif menu == "Phishing Awareness Training":
    st.title("🎓 Security Awareness & Training Module")
    st.markdown("Learn how to identify social engineering attacks and protect your organization.")
    
    st.subheader("10 Golden Rules to Spot Phishing")
    st.markdown("""
    1. **Check the Sender Address:** Look beyond the display name. Check for slight domain typos (e.g., `rnicrosoft.com`).
    2. **Watch for Urgency:** Attackers use artificial deadlines ("within 24 hours") to bypass critical thinking.
    3. **Inspect Links Carefully:** Hover over links to preview destinations. Beware of IP addresses and URL shorteners.
    4. **Generic Greetings:** Legitimate institutions address you by name; phishing emails often say *Dear Customer*.
    5. **Unexpected Attachments:** Never open executable files (`.exe`, `.scr`, `.js`) or double extensions (`.pdf.exe`).
    6. **Credential Requests:** Official IT teams will never ask for your password via email.
    7. **Financial Pressure:** Unsolicited invoices or wire transfer requests demand dual-verification.
    8. **Too Good to Be True:** Prizes and unexpected rewards are classic bait.
    9. **Inconsistent Branding:** Low-resolution logos and poor grammar signal fraudulent communications.
    10. **Verify Out-of-Band:** When in doubt, call the sender or IT desk using a verified phone number.
    """)
    
    st.markdown("### 🛑 Before You Click Checklist")
    st.checkbox("Did I independently verify the sender?")
    st.checkbox("Are the links pointing to the official corporate domain?")
    st.checkbox("Is there unwarranted pressure or threat?")
    st.checkbox("Am I being asked to log in or supply credentials from an email link?")
