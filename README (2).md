
# Phishing Email Detection & Awareness Dashboard

A professional, end-to-end defensive cybersecurity system and interactive dashboard for automated phishing email triage, heuristic risk scoring, static URL/attachment inspection, machine learning classification, and security awareness training.




## Overview 

The Phishing Email Detection & Awareness Dashboard is a comprehensive, production-grade cybersecurity project designed to simulate enterprise email security gateways and Security Operations Center (SOC) triage workflows. Built with Python, Flask, and Streamlit, this application ingests raw email metadata and content, evaluates multi-vector threat indicators, generates transparent explainable security findings, stores analysis history in a secure local database, and provides an interactive awareness training module.

## Problem statement 

Email remains the #1 initial access vector for enterprise cyberattacks, including phishing, credential harvesting, malware distribution, and ransomware deployments.

•Organizations face two major challenges:

-SOC Alert Fatigue: Security analysts are overwhelmed by high volumes of manual email triage and false-positive user reports.

-End-User Vulnerability: Employees often lack real-time visibility into why an email is suspicious, falling victim to social engineering pressure tactics like fake urgency and credential requests.
##  Objectives 

-Build a modular, beginner-friendly yet industry-oriented defensive security application.

-Implement robust static heuristics for sender spoofing, content manipulation, URL inspection, and attachment safety.

-Train an optional TF-IDF + Logistic Regression machine learning classifier on a synthetic dataset.

-Provide transparent, explainable security findings and actionable remediation playbooks.

-Store analysis telemetry securely and visualize metrics via a real-time web dashboard.

## Features

-Multi-Vector Analysis Engine: Inspects senders, body content, URLs, and attachments independently.

-Rule-Based & Hybrid Scoring: Aggregates deterministic heuristics with machine learning probability (0–100 risk score).

-Interactive Web Dashboard: Built with Streamlit for real-time email analysis, telemetry charts, and historical triage.

-Explainable Security Outputs: Clear "Why?" bullet points detailing exact threat indicators.
Security Awareness Module: Educational guides and a "Before You Click" checklist to reinforce user security hygiene.

-Secure Local Persistence: SQLite database storing sanitized analysis metadata and indicator findings.
RESTful API Backend: Modular Flask API endpoints supporting programmatic integration.
## Cybersecurity Relevance 

•This project demonstrates technical proficiency aligned with core cybersecurity roles:

-SOC Analyst: Automating alert triage, extracting indicators of compromise (IOCs), and determining risk classifications.

-Email Security Analyst: Evaluating SMTP sender domains, domain matching, URL anomalies, and malicious attachment patterns.

-Cybersecurity Engineer: Designing defense-in-depth architectures, integrating rule engines with machine learning, and writing secure, modular Python code.
## Architecture 

User / Browser
      │
      ▼
Streamlit Frontend Dashboard (Dashboard | Analyzer | History | Awareness)
      │ HTTP / JSON
      ▼
Flask Backend REST API (backend/app.py)
      │
      ├───────────────────────┬───────────────────────┐
      ▼                       ▼                       ▼
Sender Analyzer        Content Classifier      URL & Attachment Analyzers
      │                       │                       │
      └───────────────────────┼───────────────────────┘
                              ▼
                 Risk Scoring & Hybrid Engine
                              ▼
                 SQLite Persistence Database
## Technology stack

-Language: Python 3.10+
-Backend Framework: Flask (REST API)
-Frontend / Dashboard: Streamlit (Web UI & Analytics)
-Machine Learning: Scikit-Learn (TF-IDF Vectorizer, Logistic Regression), Joblib
-Data Manipulation: Pandas
-Database: SQLite3
-Testing: Pytest

## Dataset

-The application uses a programmatically generated synthetic dataset (data/phishing_email_dataset.csv) containing 550+ balanced records of legitimate and phishing emails.

-Legitimate Categories: University notices, HR updates, project reminders, IT maintenance notices, invoice confirmations.

-Phishing Patterns: Fake account suspensions, fake invoices, prize/reward claims, password expirations, and executive wire requests.

-Safety Guarantee: Uses strictly fictional domains (example.com, example.org, invalid.test) and non-malicious reserve IP addresses.
## Phishing Indicator 

The system evaluates multiple indicators across email components:

-Sender: Lookalike/typosquatting domains, excessive subdomains, display-name vs. domain mismatches.

-Subject/Body: Urgent language, fear/threats, financial pressure, credential requests, generic greetings.

-URLs: Raw IP addresses, non-HTTPS schemes, URL shorteners (bit.ly), credential keywords in paths.

-Attachments: High-risk executable extensions (.exe, .scr, .js), double extensions (.pdf.exe).
## Sender Analysis 


The sender analyzer (sender_analyzer.py) evaluates sender strings for syntactic anomalies, excessive subdomains, lookalike brand spoofing (e.g., micros0ft), and free-webmail mismatch when display names imply official support.
## E-mail content Analysis 

The content classifier (content_classifier.py) scans subjects and bodies for specific social engineering categories: Urgency, Fear/Threats, Financial Pressure, Credential Requests, Rewards, and Personal Information Requests.
## URL analysis 


•The URL analyzer (url_analyzer.py) performs strict static string analysis without visiting or rendering links:

-Detects non-secure HTTP schemes (Note: HTTPS does not guarantee legitimacy).

-Identifies raw IP address usage in hostnames.

-Detects URL shortener patterns designed to obfuscate destinations.
## Risk scoring 

The risk engine (risk_engine.py) calculates a weighted score from 0 to 100:
0–20: SAFE
21–40: LOW RISK
41–70: SUSPICIOUS
71–100: HIGH RISK / LIKELY PHISHING

## Machine learning 

An optional machine learning module (train_model.py) trains a TF-IDF Vectorizer combined with a Logistic Regression classifier on email text features, achieving robust generalization when combined with heuristic rules in the hybrid scoring engine.
## Explainable Detection 


Instead of a black-box percentage, the system outputs explicit reasoning:

Risk Score & Classification
Bulleted "Why?" findings (e.g., Credential request detected, Raw IP address in URL)
Actionable security remediation steps.
## Dashboard 

The interactive Streamlit dashboard (dashboard_app.py) features:

Top Metric Cards: Total emails analyzed, high-risk counts, suspicious counts, and average risk score.
Analytics Charts: Classification distribution and risk trend over time.

Email Analyzer Form: Interactive input for custom email triage.

History Viewer: SQLite analysis logs.
## Security Awareness 

Includes a dedicated educational module outlining the 10 Golden Rules to Spot Phishing and an interactive "Before You Click" checklist for users.

## Installation 

# 1. Clone or create project directory
cd Phishing-Email-Detection-Dashboard

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\Activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Generate dataset & train ML model
python data/generate_dataset.py
python ml/train_model.py
## API documentation 

-POST /api/analyze — Analyze email payload and return risk score, classification, and findings.


-GET /api/dashboard/stats — Retrieve top summary metrics.


-GET /api/analyses — Retrieve recent analysis history records.
## Security & Privacy 


Static Analysis Only: No external URLs are visited; no attachments are executed.

Sanitization: All inputs are safely validated and escaped.

Local Storage: All telemetry remains stored locally in an SQLite database.
## Results 
Rule Engine Accuracy: Highly interpretable heuristics successfully flag known synthetic phishing patterns.
ML Generalization: TF-IDF + Logistic Regression provides rapid classification on unseen email body phrasings.

## False Positives & False Negatives 

-False Positives: Legitimate automated notifications containing words like "urgent" or "verify" may trigger heuristic rules. Contextual review mitigates this.

-False Negatives: Highly tailored spear-phishing emails lacking standard trigger keywords can bypass static rules, highlighting the need for continuous indicator refinement and ML integration.
## Learning outcomes 

-Understanding SMTP email headers, social engineering vectors, and IOC extraction.
Building modular Python web applications with Flask and Streamlit.

-Combining rule-based heuristics with machine learning for threat detection.

-Designing secure, defensive, and explainable cybersecurity systems.

## Disclaimer 

Educational & Defensive Use Only: This project is built solely for academic evaluation, portfolio demonstration, and security awareness training. Do not use this code against real targets, external domains, or non-consenting users.



## Author

* **GitHub:** [nandiniveram2009](https://github.com)
* **LinkedIn:** [Nandini Verma](https://linkedin.com)


