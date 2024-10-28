import pickle
from featureExtractor import featureExtraction, checkIsOnline
import numpy as np

# Load the XGBoost model once, outside the function for better performance
try:
    model = pickle.load(open("XGBoostClassifier.pickle.dat", "rb"))
except (FileNotFoundError, pickle.UnpicklingError) as e:
    model = None
    print(f"Error loading model: {e}")

async def predict_url(url: str) -> str:
    # Ensure model was loaded successfully
    if model is None:
        return "Model loading error!"

    try:
        # Check for internet connection
        if not checkIsOnline():
            return "An error occurred while connecting to the Internet!"

        # Extract features and reshape them
        feature = featureExtraction(url)
        reshape_feature = np.reshape(feature, (1, -1))  # Use -1 for automatic dimension sizing

        # Make the prediction
        prediction = model.predict(reshape_feature)
        return "phishing" if prediction[0] == 1 else "legitimate"

    except Exception as e:
        print(f"Prediction error: {e}")
        return "An error occurred during prediction!"
