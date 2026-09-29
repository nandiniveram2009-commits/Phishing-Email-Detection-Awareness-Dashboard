import sqlite3
import os

DB_PATH = "backend/phishing_dashboard.db"

def init_db():
    os.makedirs("backend", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS analyses (
            analysis_id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT,
            sender_domain TEXT,
            subject TEXT,
            risk_score INTEGER,
            classification TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS indicators (
            indicator_id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id INTEGER,
            description TEXT,
            FOREIGN KEY(analysis_id) REFERENCES analyses(analysis_id)
        )
    ''')
    
    conn.commit()
    conn.close()
