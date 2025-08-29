"""
Phishing Detection Application
- Trains an ML model (if not already trained) from phishing_data.csv
- Saves/loads trained model (phishing_model.pkl)
- Provides a Tkinter GUI for common users to check if a URL is safe or phishing
"""

import os
import re
import joblib
import numpy as np
import pandas as pd
from urllib.parse import urlparse

# ML imports
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

# GUI imports
import tkinter as tk
from tkinter import messagebox

# -------------------------
# 1) Feature extractor utils
# -------------------------
IP_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
SUSPICIOUS_KEYWORDS = [
    "verify your account", "update password", "urgent", "limited time",
    "banking alert", "click here", "login immediately", "confirm your account",
    "security alert", "suspend", "account suspended", "wire transfer", "password reset"
]

def has_ip(netloc: str) -> int:
    host = netloc.split(':')[0]
    return int(bool(IP_RE.match(host)))

def count_digits(s: str) -> int:
    return sum(c.isdigit() for c in s)

# -------------------------
# 2) Custom transformers
# -------------------------
class URLFeatureExtractor(BaseEstimator, TransformerMixin):
    """Extract lexical features from a URL"""
    def fit(self, X, y=None):
        return self

    def transform(self, X):
        features = []
        for url in pd.Series(X).fillna('').astype(str):
            parsed = urlparse(url if url.startswith('http') else ('http://' + url))
            netloc = parsed.netloc
            path = parsed.path or ''
            query = parsed.query or ''
            full = url

            f = {
                'url_len': len(full),
                'netloc_len': len(netloc),
                'path_len': len(path),
                'query_len': len(query),
                'count_dots': netloc.count('.'),
                'count_hyphen': netloc.count('-'),
                'count_at': full.count('@'),
                'count_question': full.count('?'),
                'count_percent': full.count('%'),
                'count_slash': full.count('/'),
                'count_digits': count_digits(full),
                'has_https': int(full.lower().startswith('https')),
                'has_ip': has_ip(netloc)
            }
            features.append(list(f.values()))
        return np.array(features)

class KeywordCountExtractor(BaseEstimator, TransformerMixin):
    """Count suspicious keywords in subject+body"""
    def __init__(self, keywords=None):
        self.keywords = keywords or SUSPICIOUS_KEYWORDS

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        out = []
        for row in X:
            doc = " ".join([str(x) for x in row]) if isinstance(row, (list, tuple, np.ndarray)) else str(row)
            doc_l = doc.lower()
            counts = [doc_l.count(k.lower()) for k in self.keywords]
            out.append(counts + [sum(counts)])
        return np.array(out)

# -------------------------
# 3) Build ML pipeline
# -------------------------
def build_pipeline():
    url_feat = Pipeline([
        ('url_extractor', URLFeatureExtractor()),
        ('scaler', StandardScaler())
    ])

    keyword_feat = Pipeline([
        ('kw', KeywordCountExtractor()),
        ('scaler_kw', StandardScaler())
    ])

    text_tfidf = Pipeline([
        ('tfidf', TfidfVectorizer(max_features=5000, ngram_range=(1,2)))
    ])

    preprocessor = ColumnTransformer(transformers=[
        ('url', url_feat, 'url'),
        ('kw', keyword_feat, ('email_subject','email_body')),
        ('text', text_tfidf, 'text_combined'),
    ])

    pipeline = Pipeline([
        ('prep', preprocessor),
        ('clf', RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1))
    ])
    return pipeline

# -------------------------
# 4) Train model (if needed)
# -------------------------
def train_and_save_model(csv_path="phishing_data.csv", model_path="phishing_model.pkl"):
    if not os.path.exists(csv_path):
        print("Dataset not found! Please provide phishing_data.csv")
        return None

    df = pd.read_csv(csv_path)
    for c in ['url','email_subject','email_body']:
        if c not in df.columns:
            df[c] = ''
    df['text_combined'] = (df['email_subject'].fillna('') + ' ' + df['email_body'].fillna('')).astype(str)

    X = df[['url', 'email_subject', 'email_body', 'text_combined']]
    y = df['label'].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)

    pipeline = build_pipeline()
    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)
    print("Accuracy:", accuracy_score(y_test, y_pred))
    print("Precision:", precision_score(y_test, y_pred))
    print("Recall:", recall_score(y_test, y_pred))
    print("F1-score:", f1_score(y_test, y_pred))

    joblib.dump(pipeline, model_path)
    print(f"Model saved to {model_path}")
    return pipeline

# -------------------------
# 5) Inference
# -------------------------
def predict_single(pipeline, url, subject="", body="", threshold=0.5):
    text_combined = (subject or '') + ' ' + (body or '')
    X = pd.DataFrame([{
        'url': url or '',
        'email_subject': subject or '',
        'email_body': body or '',
        'text_combined': text_combined
    }])
    prob = pipeline.predict_proba(X)[:,1][0]
    label = int(prob >= threshold)

    # Simple explainability
    reasons = []
    parsed = urlparse(url if url else '')
    if url and url.startswith('http') and not url.lower().startswith('https'):
        reasons.append("URL not HTTPS")
    if url and has_ip(parsed.netloc):
        reasons.append("URL uses IP address")
    doc = text_combined.lower()
    kw_hits = [k for k in SUSPICIOUS_KEYWORDS if k in doc]
    if kw_hits:
        reasons.append(f"Suspicious keywords found: {', '.join(kw_hits[:5])}")

    return {'label': label, 'score': float(prob), 'reasons': reasons}

# -------------------------
# 6) GUI Application
# -------------------------
def launch_gui(pipeline):
    def check_link():
        url = url_entry.get().strip()
        if not url:
            messagebox.showwarning("Input Error", "Please enter a URL to check.")
            return

        result = predict_single(pipeline, url, subject="", body="")
        label = "SAFE ✅" if result["label"] == 0 else "PHISHING ⚠️"
        score = f"Confidence: {result['score']:.2f}"
        reasons = "\n".join(result["reasons"]) if result["reasons"] else "No strong red flags."
        messagebox.showinfo("Result", f"URL: {url}\n\nResult: {label}\n{score}\n\nReasons:\n{reasons}")

    root = tk.Tk()
    root.title("Phishing Link Detector")
    root.geometry("500x250")

    title = tk.Label(root, text="🔍 Phishing Link Detector", font=("Arial", 16, "bold"))
    title.pack(pady=10)

    instruction = tk.Label(root, text="Enter a URL below to check if it is safe or phishing:")
    instruction.pack()

    global url_entry
    url_entry = tk.Entry(root, width=50, font=("Arial", 12))
    url_entry.pack(pady=10)

    check_button = tk.Button(root, text="Check Link", command=check_link,
                             bg="#4CAF50", fg="white", font=("Arial", 12, "bold"))
    check_button.pack(pady=10)

    quit_button = tk.Button(root, text="Exit", command=root.quit,
                            bg="#f44336", fg="white", font=("Arial", 12, "bold"))
    quit_button.pack(pady=5)

    root.mainloop()

# -------------------------
# 7) Main
# -------------------------
if __name__ == "__main__":
    MODEL_PATH = "phishing_model.pkl"

    if os.path.exists(MODEL_PATH):
        pipeline = joblib.load(MODEL_PATH)
        print("Loaded saved model.")
    else:
        pipeline = train_and_save_model()

    if pipeline:
        launch_gui(pipeline)
