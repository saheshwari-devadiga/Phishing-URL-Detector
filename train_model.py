import pandas as pd
import re
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)
import joblib


def extract_features(url):
    features = []

    # URL length
    features.append(len(url))

    # Number of dots
    features.append(url.count("."))

    # Number of hyphens
    features.append(url.count("-"))

    # Number of slashes
    features.append(url.count("/"))

    # @ symbol
    features.append(1 if "@" in url else 0)

    # IP address detection
    ip_pattern = r"https?://(\d{1,3}\.){3}\d{1,3}"
    features.append(
        1 if re.search(ip_pattern, url) else 0
    )

    # HTTPS detection
    features.append(
        1 if url.lower().startswith("https://") else 0
    )

    return features


# Load dataset
data = pd.read_csv("dataset.csv")

# Extract features
X = data["url"].apply(extract_features).tolist()

# Target labels
y = data["label"]


# Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)


# Create Random Forest model
model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)


# Train model
model.fit(X_train, y_train)


# Make predictions
predictions = model.predict(X_test)


# Calculate accuracy
accuracy = accuracy_score(y_test, predictions)


print("====================================")
print("     PHISHING URL DETECTOR")
print("====================================")

print("\nModel trained successfully!")

print("\nAccuracy:", accuracy)


# Classification report
print("\nClassification Report:")
print(classification_report(y_test, predictions))


# Confusion matrix
print("Confusion Matrix:")
print(confusion_matrix(y_test, predictions))


# Save trained model
joblib.dump(model, "phishing_model.pkl")

print("\nModel saved as phishing_model.pkl")
print("====================================")