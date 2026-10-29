import pandas as pd
import re
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix
)
import joblib


def extract_features(url):
    features = []

    features.append(len(url))
    features.append(url.count("."))
    features.append(url.count("-"))
    features.append(url.count("/"))
    features.append(1 if "@" in url else 0)

    ip_pattern = r"https?://(\d{1,3}\.){3}\d{1,3}"
    features.append(1 if re.search(ip_pattern, url) else 0)

    features.append(1 if url.lower().startswith("https://") else 0)

    return features


data = pd.read_csv("dataset.csv")

X = data["url"].apply(extract_features).tolist()
y = data["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

model.fit(X_train, y_train)

predictions = model.predict(X_test)

accuracy = accuracy_score(y_test, predictions)
precision = precision_score(y_test, predictions, zero_division=0)
recall = recall_score(y_test, predictions, zero_division=0)
f1 = f1_score(y_test, predictions, zero_division=0)
cm = confusion_matrix(y_test, predictions)
print("Model trained successfully!")
print("Accuracy:", accuracy)
print("Precision:", precision)
print("Recall:", recall)
print("F1-Score:", f1)
print("Confusion Matrix:")
print(cm)

joblib.dump(model, "phishing_model.pkl")

print("Model saved as phishing_model.pkl")  
metrics = {
    "accuracy": round(accuracy * 100, 2),
    "precision": round(precision * 100, 2),
    "recall": round(recall * 100, 2),
    "f1_score": round(f1 * 100, 2)
}

joblib.dump(metrics, "model_metrics.pkl")
print("Model metrics saved successfully!")