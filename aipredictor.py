import pickle
import numpy as np
from featureExtractor import featureExtraction, checkIsOnline
from sklearn.base import BaseEstimator
import requests
import ssl
import socket  # Import the socket module to handle SSL validation
from urllib.parse import urlparse

# Load the XGBoost model once, outside the function for better performance
try:
    model = pickle.load(open("XGBoostClassifier.pickle.dat", "rb"))
except (FileNotFoundError, pickle.UnpicklingError) as e:
    model = None
    print(f"Error loading model: {e}")

async def predict_url(url: str) -> dict:
    """
    Predict whether a URL is phishing or legitimate.

    Args:
        url (str): The URL to be analyzed.

    Returns:
        dict: A dictionary containing:
            - "features": Extracted features of the URL.
            - "is_phishing": Prediction result (True for phishing, False for legitimate).
            - "is_https": Boolean indicating if the URL uses HTTPS.
            - "ssl_error": Boolean indicating if there's an SSL certificate error.
    """
    # Ensure model was loaded successfully
    if model is None:
        return {"error": "Model loading error!"}

    try:
        # Check for internet connection
        if not checkIsOnline():
            return {"error": "An error occurred while connecting to the Internet!"}

        # Extract features from the URL
        features = featureExtraction(url)

        # Debug: Check the extracted features
        print(f"Extracted features: {features}")

        # Ensure the features are valid and have the correct length
        if not features or len(features) != 16:  # Update 16 with the correct expected feature count
            return {"error": "Feature extraction failed: Incorrect feature count."}

        # Reshape feature array for model prediction (must be 2D array)
        reshape_features = np.reshape(features, (1, -1))  # Use -1 for automatic dimension sizing

        # Make the prediction
        prediction = model.predict(reshape_features)

        # Check HTTPS and SSL validity
        is_https = url.startswith("https://")
        ssl_error = False

        # SSL certificate validation
        if is_https:
            try:
                hostname = urlparse(url).hostname
                context = ssl.create_default_context()
                with context.wrap_socket(socket.socket(), server_hostname=hostname) as sock:
                    sock.connect((hostname, 443))  # Check SSL certificate
            except ssl.SSLError:
                ssl_error = True
            except Exception as e:
                # Log any unexpected SSL or socket errors
                print(f"SSL validation error: {e}")
                ssl_error = True

        # Debug: Check the prediction result
        print(f"Prediction result: {prediction}")

        # Return the response with the extracted features, prediction result, and SSL/HTTPS info
        return {
            "features": features,                    # Extracted features of the URL
            "is_phishing": bool(prediction[0]),      # True if phishing, False otherwise
            "is_https": is_https,                    # Whether the URL uses HTTPS
            "ssl_error": ssl_error                    # Whether there was an SSL error
        }

    except requests.exceptions.RequestException as e:
        # Handle any errors related to request fetching or feature extraction
        print(f"Error during URL prediction request: {e}")
        return {"error": f"An error occurred during URL request: {e}"}

    except ValueError as e:
        # Handle issues with feature processing or predictions
        print(f"Error during prediction processing: {e}")
        return {"error": "Error processing prediction result."}

    except Exception as e:
        # Catch any unexpected errors
        print(f"Unexpected error: {e}")
        return {"error": f"An unexpected error occurred: {e}"}
