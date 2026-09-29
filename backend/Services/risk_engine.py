from backend.services.sender_analyzer import analyze_sender
from backend.services.content_classifier import analyze_email_content
from backend.services.url_analyzer import analyze_url
from backend.services.attachment_analyzer import analyze_attachment

def calculate_phishing_score(sender, subject, body, urls_str, attachment_name):
    # Run sub-analyzers
    sender_res = analyze_sender(sender)
    content_res = analyze_email_content(subject, body)
    url_res = analyze_url(urls_str)
    att_res = analyze_attachment(attachment_name)
    
    # Weighted calculation
    sender_score = sender_res["sender_risk_score"] * 0.25
    url_score = url_res["url_risk_score"] * 0.35
    att_score = att_res["attachment_risk_score"] * 0.25
    
    # Content heuristic score
    content_score = 0
    if len(content_res["categories_detected"]) > 0:
        content_score = min(len(content_res["categories_detected"]) * 15, 100)
    content_weighted = content_score * 0.15
    
    total_score = int(sender_score + url_score + att_score + content_weighted)
    total_score = max(0, min(total_score, 100))
    
    # Classification thresholds
    if total_score <= 20:
        classification = "SAFE"
    elif total_score <= 40:
        classification = "LOW RISK"
    elif total_score <= 70:
        classification = "SUSPICIOUS"
    else:
        classification = "HIGH RISK / LIKELY PHISHING"
        
    all_findings = (
        sender_res["sender_findings"] + 
        content_res["content_findings"] + 
        url_res["url_findings"] + 
        att_res["attachment_findings"]
    )
    
    return {
        "risk_score": total_score,
        "classification": classification,
        "findings": all_findings,
        "categories": content_res["categories_detected"]
      }
