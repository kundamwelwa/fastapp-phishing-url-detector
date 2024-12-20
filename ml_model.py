import pickle
import numpy as np
from featureExtractor import featureExtraction, checkIsOnline

# Load the XGBoost model once outside the function for efficiency
try:
    model = pickle.load(open("XGBoostClassifier.pickle.dat", "rb"))
except (FileNotFoundError, pickle.UnpicklingError) as e:
    model = None
    print(f"Error loading model: {e}")

async def predict_url(url: str) -> str:
    if model is None:
        return "Model could not be loaded!"

    try:
        # Check online status
        if not checkIsOnline():
            return "An error occurred while connecting to the Internet!"

        # Extract features and reshape for prediction
        feature = featureExtraction(url)
        if not feature or len(feature) == 0:
            return "Feature extraction failed!"

        reshape_feature = np.reshape(feature, (1, -1))

        # Predict phishing or legitimate
        prediction = model.predict(reshape_feature)

        # Correcting prediction index to match the expected output
        return "phishing" if prediction[0] == 0 else "legitimate"
    
    except Exception as e:
        print(f"Error in prediction: {e}")
        return f"An error occurred during prediction: {e}"
