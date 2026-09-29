def analyze_email_content(subject, body):
    text = f"{subject} {body}".lower()
    categories_detected = []
    findings = []
    
    urgency_terms = ["immediately", "urgent", "act now", "expire", "24 hours", "quick"]
    fear_terms = ["suspended", "locked", "terminate", "penalty", "lawsuit", "action required"]
    financial_terms = ["invoice", "payment", "wire", "balance", "outstanding", "$"]
    credential_terms = ["verify your password", "confirm your account", "sign in here", "credentials"]
    reward_terms = ["won", "prize", "gift card", "congratulations", "selected"]
    personal_terms = ["personal details", "social security", "credit card", "identity"]
    
    if any(t in text for t in urgency_terms):
        categories_detected.append("URGENCY")
        findings.append("Urgent time-sensitive language detected.")
        
    if any(t in text for t in fear_terms):
        categories_detected.append("FEAR / THREAT")
        findings.append("Threatening or account-suspension language detected.")
        
    if any(t in text for t in financial_terms):
        categories_detected.append("FINANCIAL PRESSURE")
        findings.append("Financial or payment-related pressure detected.")
        
    if any(t in text for t in credential_terms):
        categories_detected.append("CREDENTIAL REQUEST")
        findings.append("Explicit or implied request for credentials/login verification.")
        
    if any(t in text for t in reward_terms):
        categories_detected.append("REWARD / PRIZE")
        findings.append("Unsolicited reward or prize claim detected.")
        
    if any(t in text for t in personal_terms):
        categories_detected.append("PERSONAL INFORMATION")
        findings.append("Request for sensitive personal or financial details.")
        
    return {
        "categories_detected": categories_detected,
        "content_findings": findings
      }
