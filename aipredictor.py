import pickle

from featureExtractor import featureExtraction, checkIsOnline


async def predict_url(url):
    #Load the xgb model
    model = pickle.load(open("XGBoostClassifier.pickle.dat", "rb"))

    if checkIsOnline() :
        feature = featureExtraction(url)
        reshape_feature = feature.reshape(1,16)
        prediction = model.predict(reshape_feature)
        if prediction[0] == 1:
            return "phishing"
        else:
            return "legitimate"
    else:
        return "Error Connecting to the internet!"