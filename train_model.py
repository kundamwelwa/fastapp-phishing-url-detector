import pickle
import numpy as np
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from featureExtractor import featureExtraction
import sqlite3


# Load data from db.sqlite
def load_data():
    # Connect to the SQLite database
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()

    # Use the new table name 'url_data_new'
    cursor.execute("SELECT url, label FROM url_data_new")
    data = cursor.fetchall()
    conn.close()

    # Separate URLs and labels
    urls = [row[0] for row in data]
    labels = [row[1] for row in data]  # Assuming 1 = phishing, 0 = legitimate

    # Extract features
    features = [featureExtraction(url) for url in urls]
    return np.array(features), np.array(labels)

# Train the model
def train_model():
    # Load features and labels
    X, y = load_data()

    # Split data into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Initialize XGBoost classifier
    model = XGBClassifier(use_label_encoder=False, eval_metric="logloss")

    # Train the model
    model.fit(X_train, y_train)

    # Test model performance
    predictions = model.predict(X_test)
    accuracy = accuracy_score(y_test, predictions)
    print(f"Model accuracy: {accuracy * 100:.2f}%")

    # Save the trained model
    with open("XGBoostClassifier.pickle.dat", "wb") as model_file:
        pickle.dump(model, model_file)
    print("Model saved as 'XGBoostClassifier.pickle.dat'.")

if __name__ == "__main__":
    train_model()
