import re

def analyze_sender(sender, display_name=None):
    risk_score = 0
    findings = []
    
    if not sender or "@" not in sender:
        return {"sender_risk_score": 30, "sender_findings": ["Invalid or missing sender email format"]}
        
    local_part, domain = sender.split("@", 1)
    
    # Check for excessive subdomains
    subdomain_count = domain.count(".")
    if subdomain_count > 2:
        risk_score += 15
        findings.append(f"Excessive subdomains detected in sender domain ({domain})")
        
    # Check for suspicious characters or numbers mimicking brands (e.g., micros0ft)
    brand_spoof_pattern = re.compile(r'(micros[o0]ft|paypa[l1]|amaz[o0]n|goog[l1]e|apple-id)', re.IGNORECASE)
    if brand_spoof_pattern.search(domain):
        risk_score += 25
        findings.append(f"Possible lookalike / typosquatting domain pattern detected: {domain}")
        
    # Check domain length anomalies
    if len(domain) > 30:
        risk_score += 10
        findings.append("Unusually long sender domain string")
        
    # Free webmail vs corporate impersonation check
    free_mail_providers = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com"]
    if display_name and any(brand in display_name.lower() for brand in ["support", "security", "admin", "billing", "it"]):
        if domain.lower() in free_mail_providers:
            risk_score += 20
            findings.append(f"Display name indicates authority/support, but domain uses free webmail ({domain})")

    if not findings:
        findings.append("Sender domain appears syntactically standard")

    return {
        "sender_risk_score": min(risk_score, 100),
        "sender_findings": findings
    }
