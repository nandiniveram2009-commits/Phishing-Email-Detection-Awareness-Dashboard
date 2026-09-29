import os
import joblib
from flask import Flask, request, jsonify
from flask_cors import CORS
from backend.services.risk_engine import calculate_phishing_score
from backend.models.database import init_db, DB_PATH
import sqlite3

app = Flask(__name__)
CORS(app)
init_db()

# Load optional ML model if available
ml_model = None
vectorizer = None
if os.path.exists("models/phishing_logistic_model.pkl") and os.path.exists("models/tfidf_vectorizer.pkl"):
    ml_model = joblib.load("models/phishing_logistic_model.pkl")
    vectorizer = joblib.load("models/tfidf_vectorizer.pkl")

@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    data = request.json or {}
    sender = data.get('sender', '')
    subject = data.get('subject', '')
    body = data.get('body', '')
    urls = data.get('urls', '')
    attachment = data.get('attachment_name', '')
    
    if not sender or not subject or not body:
        return jsonify({"error": "Missing required fields: sender, subject, body"}), 400
        
    result = calculate_phishing_score(sender, subject, body, urls, attachment)
    
    # Optional ML integration boost
    if ml_model and vectorizer:
        combined = f"{subject} {body} {sender}"
        vec = vectorizer.transform([combined])
        ml_prob = ml_model.predict_proba(vec)[0][1] # Probability of phish
        # Hybrid combination
        result['risk_score'] = int((result['risk_score'] * 0.6) + (ml_prob * 100 * 0.4))
        result['ml_probability'] = round(float(ml_prob) * 100, 2)

    # Save to database
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO analyses (sender, sender_domain, subject, risk_score, classification) VALUES (?, ?, ?, ?, ?)",
        (sender, sender.split("@")[-1] if "@" in sender else "unknown", subject, result['risk_score'], result['classification'])
    )
    analysis_id = cursor.lastrowid
    
    for finding in result['findings']:
        cursor.execute("INSERT INTO indicators (analysis_id, description) VALUES (?, ?)", (analysis_id, finding))
        
    conn.commit()
    conn.close()
    
    result['analysis_id'] = analysis_id
    return jsonify(result), 200

@app.route('/api/dashboard/stats', methods=['GET'])
def api_stats():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM analyses")
    total = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM analyses WHERE classification = 'HIGH RISK / LIKELY PHISHING'")
    high_risk = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM analyses WHERE classification = 'SUSPICIOUS'")
    suspicious = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM analyses WHERE classification IN ('SAFE', 'LOW RISK')")
    safe = cursor.fetchone()[0]
    
    cursor.execute("SELECT AVG(risk_score) FROM analyses")
    avg_score = cursor.fetchone()[0] or 0.0
    
    conn.close()
    
    return jsonify({
        "total_emails": total,
        "high_risk": high_risk,
        "suspicious": suspicious,
        "safe_count": safe,
        "average_risk_score": round(avg_score, 1)
    }), 200

@app.route('/api/analyses', methods=['GET'])
def api_get_analyses():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM analyses ORDER BY created_at DESC LIMIT 50")
    rows = cursor.fetchall()
    conn.close()
    
    return jsonify([dict(row) for row in rows]), 200

if __name__ == '__main__':
    app.run(debug=True, port=5000)
