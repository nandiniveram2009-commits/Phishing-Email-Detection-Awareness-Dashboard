import os
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

def train_phishing_model():
    dataset_path = "data/phishing_email_dataset.csv"
    if not os.path.exists(dataset_path):
        print("[!] Dataset not found. Please run generate_dataset.py first.")
        return
        
    df = pd.read_csv(dataset_path)
    df['combined_text'] = df['subject'].fillna('') + " " + df['body'].fillna('') + " " + df['sender'].fillna('')
    df['target'] = df['label'].apply(lambda x: 1 if x == 'PHISHING' else 0)
    
    X_train, X_test, y_train, y_test = train_test_split(df['combined_text'], df['target'], test_size=0.2, random_state=42)
    
    vectorizer = TfidfVectorizer(max_features=3000, stop_words='english', ngram_range=(1, 2))
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)
    
    model = LogisticRegression(max_iter=1000)
    model.fit(X_train_vec, y_train)
    
    y_pred = model.predict(X_test_vec)
    
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred)
    
    print("=== MODEL EVALUATION METRICS ===")
    print(f"Accuracy:  {acc:.4f}")
    print(f"Precision: {prec:.4f}")
    print(f"Recall:    {rec:.4f}")
    print(f"F1 Score:  {f1:.4f}")
    print("Confusion Matrix:\n", cm)
    
    os.makedirs("models", exist_ok=True)
    joblib.dump(model, "models/phishing_logistic_model.pkl")
    joblib.dump(vectorizer, "models/tfidf_vectorizer.pkl")
    print("[+] Model and vectorizer successfully saved to models/")

if __name__ == "__main__":
    train_phishing_model()
