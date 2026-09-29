import re
from urllib.parse import urlparse

def analyze_url(url_string):
    risk_score = 0
    findings = []
    
    if not url_string:
        return {"url_risk_score": 0, "url_findings": ["No URLs present in email"]}
        
    parsed = urlparse(url_string)
    scheme = parsed.scheme
    hostname = parsed.hostname or ""
    path = parsed.path
    
    # Check scheme
    if scheme != "https":
        risk_score += 20
        findings.append(f"Non-secure HTTP scheme used (scheme: {scheme})")
    else:
        findings.append("Uses HTTPS scheme (Note: SSL does not guarantee site legitimacy)")
        
    # Check raw IP usage
    ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    if ip_pattern.match(hostname):
        risk_score += 40
        findings.append(f"Raw IP address used in hostname instead of domain name ({hostname})")
        
    # Check URL shorteners
    shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'buff.ly']
    if any(sh in hostname.lower() for sh in shorteners):
        risk_score += 25
        findings.append(f"URL shortener service detected ({hostname}), hiding true destination")
        
    # Check suspicious keywords in path/query
    suspicious_url_keywords = ['login', 'verify', 'account', 'update', 'signin', 'secure', 'banking', 'confirm']
    if any(kw in url_string.lower() for kw in suspicious_url_keywords):
        risk_score += 15
        findings.append("Credential or verification keyword found within URL path")
        
    # Excessive subdomains
    if hostname.count('.') > 3:
        risk_score += 15
        findings.append("Excessive subdomains in URL hostname")

    return {
        "url_risk_score": min(risk_score, 100),
        "url_findings": findings
    }
