import pickle
from featureExtractor import featureExtraction, checkIsOnline
import numpy as np

async def predict_url(url: str) -> str:
    # Load the XGBoost model
    model = pickle.load(open("XGBoostClassifier.pickle.dat", "rb"))

    if checkIsOnline():
        feature = featureExtraction(url)
        reshape_feature = np.reshape(feature, (1, -1))  # Reshape to match the model input
        print(reshape_feature)
        prediction = model.predict(reshape_feature)
        print(prediction)
        if prediction[0] == 1:
            return "phishing"
        else:
            return "legitimate"
    else:
        return "An error occurred while connecting to the Internet!"
