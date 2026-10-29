
from flask import Flask, render_template, request, redirect, url_for
from urllib.parse import urlparse
from rapidfuzz import fuzz
import re
import sqlite3
import joblib

app = Flask(__name__)

DATABASE = "phishing_scans.db"
MODEL_FILE = "phishing_model.pkl"

model = joblib.load(MODEL_FILE)

POPULAR_DOMAINS = [
    "google.com", "youtube.com", "facebook.com",
    "instagram.com", "amazon.com", "microsoft.com",
    "apple.com", "linkedin.com", "whatsapp.com", "netflix.com"
]

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "account", "update", "secure",
    "banking", "password", "signin", "confirm", "wallet",
    "free", "gift"
]


# -----------------------------
# Database
# -----------------------------
def init_database():
    with sqlite3.connect(DATABASE) as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                result TEXT NOT NULL,
                risk_score INTEGER,
                scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)


init_database()


# -----------------------------
# ML feature extraction
# Must match train_model.py
# -----------------------------
def extract_features(url):
    return [
        len(url),
        url.count("."),
        url.count("-"),
        url.count("/"),
        1 if "@" in url else 0,
        1 if re.search(r"\d{1,3}(?:\.\d{1,3}){3}", url) else 0,
        1 if url.lower().startswith("https://") else 0
    ]


# -----------------------------
# Typosquatting detection
# -----------------------------
def detect_typosquatting(url):
    hostname = urlparse(url).hostname

    if not hostname:
        return None

    hostname = hostname.lower().rstrip(".")
    parts = hostname.split(".")
    candidates = [
        ".".join(parts[i:])
        for i in range(max(0, len(parts) - 2), len(parts))
    ]

    matches = []

    for candidate in candidates:
        for popular in POPULAR_DOMAINS:
            if candidate == popular:
                continue

            score = fuzz.ratio(candidate, popular)

            if score >= 75:
                matches.append({
                    "suspicious": True,
                    "domain": hostname,
                    "similar_to": popular,
                    "similarity": round(score, 1)
                })

    if matches:
        return max(matches, key=lambda item: item["similarity"])

    return {
        "suspicious": False,
        "domain": hostname,
        "similar_to": None,
        "similarity": 0
    }


# -----------------------------
# Dashboard statistics
# -----------------------------
def get_dashboard_stats():
    with sqlite3.connect(DATABASE) as connection:
        connection.row_factory = sqlite3.Row

        total_scans = connection.execute(
            "SELECT COUNT(*) FROM scans"
        ).fetchone()[0]

        normal_count = connection.execute(
            "SELECT COUNT(*) FROM scans WHERE result = 'Normal'"
        ).fetchone()[0]

        suspicious_count = connection.execute(
            "SELECT COUNT(*) FROM scans WHERE result = 'Suspicious'"
        ).fetchone()[0]

        rows = connection.execute("""
            SELECT id, url, result, risk_score, scanned_at
            FROM scans
            ORDER BY id DESC
            LIMIT 10
        """).fetchall()

        history = [dict(row) for row in rows]

    return history, total_scans, normal_count, suspicious_count


# -----------------------------
# URL analysis
# -----------------------------
def analyze_url(url):
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or "/"

    protocol = parsed.scheme.upper()

    has_ip = (
        "Yes"
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", hostname)
        else "No"
    )

    https_status = (
        "Yes" if parsed.scheme.lower() == "https" else "No"
    )

    found_keywords = [
        word for word in SUSPICIOUS_KEYWORDS
        if word in url.lower()
    ]

    url_intelligence = {
        "url_length": len(url),
        "dots": url.count("."),
        "hyphens": url.count("-"),
        "https_enabled": https_status,
        "suspicious_keywords": found_keywords
    }

    return (
        protocol, hostname, path, has_ip,
        https_status, found_keywords, url_intelligence
    )


# -----------------------------
# Home / scan route
# -----------------------------
@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    scan_result = None
    risk_score = 0
    protocol = ""
    domain = ""
    path = ""
    has_ip = "No"
    https_status = "No"
    url_intelligence = {}
    typo_result = None
    indicators = []
    investigation_details = []
    scanned_url = ""

    if request.method == "POST":
        url = request.form.get("url", "").strip()
        scanned_url = url
        parsed = urlparse(url)

        if (
            parsed.scheme.lower() not in ("http", "https")
            or not parsed.hostname
            or any(char.isspace() for char in url)
        ):
            result = (
                "❌ Invalid URL. Enter a complete URL beginning "
                "with http:// or https://"
            )
        else:
            (
                protocol, domain, path, has_ip, https_status,
                found_keywords, url_intelligence
            ) = analyze_url(url)

            typo_result = detect_typosquatting(url)

            features = extract_features(url)
            prediction = int(model.predict([features])[0])
            probabilities = model.predict_proba([features])[0]
            phishing_index = list(model.classes_).index(1)

            risk_score = round(
                float(probabilities[phishing_index]) * 100
            )

            scan_result = (
                "Suspicious" if prediction == 1 else "Normal"
            )

            result = (
                f"⚠️ Suspicious URL Detected — Risk Score: {risk_score}%"
                if prediction == 1
                else f"✅ URL classified as Normal — Risk Score: {risk_score}%"
            )

            # Investigation indicators
            if len(url) > 75:
                indicators.append("Long URL")

            if url.count(".") > 3:
                indicators.append("Many dots or subdomains")

            if url.count("-") >= 3:
                indicators.append("Many hyphens")

            if url.count("/") > 5:
                indicators.append("Many URL paths")

            if "@" in url:
                indicators.append("@ symbol detected")

            if has_ip == "Yes":
                indicators.append("IP address used")

            if https_status == "No":
                indicators.append("HTTPS not used")

            if found_keywords:
                indicators.append(
                    "Suspicious words: " + ", ".join(found_keywords)
                )

            if typo_result and typo_result.get("suspicious"):
                indicators.append(
                    "Domain resembles " + typo_result["similar_to"]
                    + " (" + str(typo_result["similarity"]) + "% similarity)"
                )

            investigation_details = list(indicators)

            if prediction == 1:
                investigation_details.insert(
                    0, "The ML model classified this URL as suspicious."
                )
            else:
                investigation_details.insert(
                    0,
                    "The ML model classified this URL as normal. "
                    "This does not guarantee the website is safe."
                )

            if not indicators:
                investigation_details.append(
                    "No additional warning indicators were detected."
                )

            # Save scan
            with sqlite3.connect(DATABASE) as connection:
                connection.execute("""
                    INSERT INTO scans (url, result, risk_score)
                    VALUES (?, ?, ?)
                """, (url, scan_result, risk_score))

    history, total_scans, normal_count, suspicious_count = (
        get_dashboard_stats()
    )

    return render_template(
        "index.html",
        result=result,
        scan_result=scan_result,
        risk_score=risk_score,
        url=scanned_url,
        history=history,
        protocol=protocol,
        domain=domain,
        path=path,
        has_ip=has_ip,
        https_status=https_status,
        url_intelligence=url_intelligence,
        typo_result=typo_result,
        indicators=indicators,
        investigation_details=investigation_details,
        total_scans=total_scans,
        normal_count=normal_count,
        suspicious_count=suspicious_count
    )


# -----------------------------
# Clear history
# -----------------------------
@app.route("/clear-history")
def clear_history():
    with sqlite3.connect(DATABASE) as connection:
        connection.execute("DELETE FROM scans")

    return redirect(url_for("home"))


# -----------------------------
# Run Flask
# -----------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
