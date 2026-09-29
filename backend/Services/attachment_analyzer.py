def analyze_attachment(filename):
    if not filename:
        return {"attachment_risk_score": 0, "attachment_findings": ["No attachment included"]}
        
    risk_score = 0
    findings = []
    
    filename_lower = filename.lower()
    
    high_risk_extensions = ['.exe', '.scr', '.bat', '.cmd', '.js', '.vbs', '.ps1', '.pif', '.hta']
    archive_extensions = ['.zip', '.rar', '.7z', '.iso', '.img']
    
    # Check double extensions (e.g. invoice.pdf.exe)
    if filename_lower.count('.') > 1:
        risk_score += 40
        findings.append(f"Double extension detected in attachment filename ({filename}), a common malware obfuscation technique.")
        
    if any(filename_lower.endswith(ext) for ext in high_risk_extensions):
        risk_score += 50
        findings.append(f"High-risk executable/script extension detected ({filename}). Do not open.")
    elif any(filename_lower.endswith(ext) for ext in archive_extensions):
        risk_score += 20
        findings.append(f"Compressed archive attachment ({filename}); exercise caution if password-protected.")
    else:
        findings.append(f"Standard document/file format extension ({filename}).")

    return {
        "attachment_risk_score": min(risk_score, 100),
        "attachment_findings": findings
    }
