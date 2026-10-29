# Phishing URL Detector

A Python-based web app that detects phishing URLs using machine learning, with risk scoring, scan history, and downloadable reports.



## Features
- Checks a URL and classifies it as safe or phishing
- Risk score for each scanned URL
- Scan history stored in a local database
- Downloadable scan reports

## Tech Stack
- Python, Flask
- scikit-learn, pandas, joblib
- HTML, CSS
- SQLite

## Project Structure
- `app.py`: Flask web app
- `train_model.py`: trains the ML model
- `dataset.csv`: training dataset
- `phishing_model.pkl`: trained model
- `templates/`, `static/`: frontend files

## Setup
1. Clone the repo
2. Install dependencies: `pip install -r requirements.txt`
3. Train the model (optional): `python train_model.py`
4. Run the app: `python app.py`
5. Open `http://127.0.0.1:5000`

## Screenshots
<img width="1396" height="913" alt="image" src="https://github.com/user-attachments/assets/3539ba7d-909d-495e-a7e3-ea9dd5bf0cdd" />
<img width="1241" height="918" alt="image" src="https://github.com/user-attachments/assets/d7653f0a-994e-48ac-aeb3-4bb8e5f11e59" />


## Author
Saheshwari Devadiga
