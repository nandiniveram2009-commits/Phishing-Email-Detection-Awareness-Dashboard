import re
from urllib.parse import urlparse

URGENT_KEYWORDS = ["urgent", "immediate", "act now", "expires", "today", "hurry", "critical"]
CREDENTIAL_KEYWORDS = ["password", "login", "verify", "credential", "account", "signin", "authenticate"]
FINANCIAL_KEYWORDS = ["invoice", "payment", "wire", "billing", "bank", "transfer", "$", "usd"]
THREAT_KEYWORDS = ["suspended", "locked", "penalty", "lawsuit", "terminate", "blocked", "action required"]
GENERIC_GREETINGS = ["dear customer", "dear user", "valued user", "attention user", "dear account holder"]

def extract_email_features(sender, subject, body, urls_str, attachment_name):
    full_text = f"{subject} {body}".lower()
    
    # Keyword counts
    urgent_count = sum(full_text.count(kw) for kw in URGENT_KEYWORDS)
    cred_count = sum(full_text.count(kw) for kw in CREDENTIAL_KEYWORDS)
    fin_count = sum(full_text.count(kw) for kw in FINANCIAL_KEYWORDS)
    threat_count = sum(full_text.count(kw) for kw in THREAT_KEYWORDS)
    
    # URL parsing
    urls = [u.strip() for u in urls_str.split("|") if u.strip()]
    url_count = len(urls)
    
    suspicious_url_count = 0
    has_ip = 0
    has_shortener = 0
    
    ip_pattern = re.compile(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    shortener_patterns = ['bit.ly', 'tinyurl', 't.co', 'goo.gl', 'ow.ly']
    
    for url in urls:
        if ip_pattern.match(url):
            has_ip = 1
            suspicious_url_count += 1
        if any(short in url for short in shortener_patterns):
            has_shortener = 1
            suspicious_url_count += 1
        if not url.startswith("https://"):
            suspicious_url_count += 1

    # Sender domain analysis
    sender_domain = sender.split("@")[-1] if "@" in sender else ""
    domain_length = len(sender_domain)
    subdomain_count = sender_domain.count(".")
    
    # Attachment analysis
    high_risk_exts = ['.exe', '.scr', '.bat', '.cmd', '.js', '.vbs', '.ps1', '.pif']
    susp_att = 0
    if attachment_name:
        att_lower = attachment_name.lower()
        if any(att_lower.endswith(ext) for ext in high_risk_exts) or att_lower.count('.') > 1:
            susp_att = 1
            
    # Greetings & Formatting
    generic_greeting = 1 if any(g in full_text for g in GENERIC_GREETINGS) else 0
    exclamation_count = body.count("!")
    upper_letters = sum(1 for c in body if c.isupper())
    uppercase_ratio = (upper_letters / len(body)) if len(body) > 0 else 0.0
    
    features = {
        "urgent_keyword_count": urgent_count,
        "credential_keyword_count": cred_count,
        "financial_keyword_count": fin_count,
        "threat_keyword_count": threat_count,
        "url_count": url_count,
        "suspicious_url_count": suspicious_url_count,
        "has_ip_url": has_ip,
        "has_shortened_url_pattern": has_shortener,
        "sender_domain_length": domain_length,
        "subdomain_count": subdomain_count,
        "suspicious_attachment": susp_att,
        "generic_greeting": generic_greeting,
        "exclamation_count": exclamation_count,
        "uppercase_ratio": round(uppercase_ratio, 3),
        "body_length": len(body),
        "subject_length": len(subject)
    }
    
    return features
