from datetime import datetime
from time import sleep
from urllib.parse import urlparse
import ipaddress
import re
import requests
from bs4 import BeautifulSoup
import whois
import numpy as np

# Listing shortening services
shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"

# Check for internet connectivity
def checkIsOnline():
    try:
        response = requests.get('https://www.google.com', timeout=2)
        return response.status_code == 200
    except requests.exceptions.ConnectionError:
        return False

# 1. Domain of the URL (Domain)
def getDomain(url):
    domain = urlparse(url).netloc
    return domain.replace("www.", "")  # Remove 'www.' if present

# 2. Checks for IP address in URL (Have_IP)
def havingIP(url):
    try:
        ipaddress.ip_address(url)
        return 1
    except ValueError:
        return 0

# 3. Checks the presence of '@' in URL (Have_At)
def haveAtSign(url):
    return 1 if "@" in url else 0

# 4. Finding the length of URL and categorizing (URL_Length)
def getLength(url):
    return 0 if len(url) < 54 else 1

# 5. Gives number of '/' in URL (URL_Depth)
def getDepth(url):
    return len([part for part in urlparse(url).path.split('/') if part])

# 6. Checking for redirection '//' in the url (Redirection)
def redirection(url):
    pos = url.rfind('//')
    return 1 if pos > 6 and pos > 7 else 0

# 7. Existence of “HTTPS” Token in the Domain Part of the URL (https_Domain)
def httpDomain(url):
    """Neutralize suspicion for non-HTTPS (HTTP-only) URLs unless known phishing patterns exist."""
    return 0

# 8. Checking for Shortening Services in URL (Tiny_URL)
def tinyURL(url):
    """Lower sensitivity to URL shortening."""
    return 1 if re.search(shortening_services, url) else 0

# 9. Checking for Prefix or Suffix Separated by (-) in the Domain (Prefix/Suffix)
def prefixSuffix(url):
    return 1 if '-' in urlparse(url).netloc else 0

# Function to check web traffic
def web_traffic(url):
    domain = getDomain(url)
    base_url = f"https://www.semrush.com/website/{domain}/overview/"
    try:
        response = requests.get(base_url)
        response.raise_for_status()  # Raise an error for bad responses
        soup = BeautifulSoup(response.text, "html.parser")
        rank_elements = soup.find_all("b", class_="rank-card__SCRank-sc-2sba91-8")
        
        if rank_elements:
            rank = int(rank_elements[0].text.replace(',', ''))
            return 1 if rank < 100000 else 0
        else:
            print(f"Rank data not found for {url}; treating as neutral.")
            return 0  # Treat as neutral if rank data is missing
            
    except requests.HTTPError as e:
        if e.response.status_code == 404:
            print(f"Error 404: Page not found for {url}; treating as neutral.")
            return 0
        elif e.response.status_code == 403:
            print(f"Error 403: Access denied for {url}; treating as neutral.")
            return 0
        else:
            print(f"HTTP error occurred: {e}; treating as neutral.")
            return 0
    except Exception as e:
        print(f"General error fetching web traffic data for {url}: {e}; treating as neutral.")
        return 0  # Treat missing data neutrally


# Delay between requests
sleep(2)  # Adjust time as necessary

# 10. Survival time of domain (Domain_Age)
def domainAge(domain_name):
    """Treat unknown domain age neutrally."""
    creation_date = domain_name.creation_date
    expiration_date = domain_name.expiration_date

    # Ensure we are working with datetime objects
    if isinstance(creation_date, list):
        creation_date = creation_date[0]  # Take first date if it's a list
    if isinstance(expiration_date, list):
        expiration_date = expiration_date[0]  # Take first date if it's a list

    if isinstance(creation_date, str) or isinstance(expiration_date, str):
        try:
            creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
            expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
        except ValueError:
            return 0  # Treat as neutral if date parsing fails

    if expiration_date is None or creation_date is None:
        return 0  # Treat missing date as neutral

    age_of_domain = abs((expiration_date - creation_date).days)
    return 1 if (age_of_domain / 30) < 6 else 0

# 11. End time of domain (Domain_End)
def domainEnd(domain_name):
    """Treat unknown domain end date neutrally."""
    expiration_date = domain_name.expiration_date

    if isinstance(expiration_date, list):
        expiration_date = expiration_date[0]  # Take first date if it's a list

    if isinstance(expiration_date, str):
        try:
            expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
        except ValueError:
            return 0  # Treat as neutral if date parsing fails

    if expiration_date is None:
        return 0  # Treat missing date as neutral

    today = datetime.now()
    end = abs((expiration_date - today).days)
    return 0 if (end / 30) < 6 else 1

# 12. IFrame Redirection (iFrame)
def iframe(response):
    if not response:
        return 1
    return 0 if re.findall(r"<iframe>|<frameBorder>", response.text) else 1

# 13. Checks the effect of mouse over on status bar (Mouse_Over)
def mouseOver(response):
    if not response:
        return 1
    return 1 if re.findall("<script>.+onmouseover.+</script>", response.text) else 0

# 14. Checks the status of the right-click attribute (Right_Click)
def rightClick(response):
    if not response:
        return 1
    return 0 if re.findall(r"event.button ?== ?2", response.text) else 1

# 15. Checks the number of forwardings (Web_Forwards)
def forwarding(response):
    if not response:
        return 1
    return 1 if len(response.history) > 2 else 0

def check_https_security(url):
    try:
        response = requests.get(url, timeout=5)  # Set a timeout for the request
        # Check if the response is successful
        if response.status_code == 200:
            return 1  # Secure
    except requests.exceptions.SSLError:
        print(f"SSL error: The site {url} has an invalid certificate.")
    except requests.exceptions.RequestException as e:
        print(f"Request error: {e}")

    return 0  # Not secure
    

# Function to extract features
def featureExtraction(url):
    features = [
        havingIP(url),
        haveAtSign(url),
        getLength(url),
        getDepth(url),
        redirection(url),
        httpDomain(url),
        tinyURL(url),
        prefixSuffix(url),
    ]

    dns = 0
    try:
        domain_name = whois.whois(getDomain(url))
    except Exception:
        dns = 1

    features.append(dns)
    features.append(web_traffic(url))
    features.append(1 if dns == 1 else domainAge(domain_name))
    features.append(1 if dns == 1 else domainEnd(domain_name))

    # Check if the HTTPS connection is secure
    https_secure = check_https_security(url)
    features.append(https_secure)

    # HTML & Javascript based features
    try:
        response = requests.get(url)
    except:
        response = ""

    features.append(iframe(response))
    features.append(mouseOver(response))
    features.append(rightClick(response))
    features.append(forwarding(response))

    # Ensure the features match your model expectations
    expected_features_count = 16  # Adjust according to your model
    if len(features) != expected_features_count:
        print(f"Warning: Feature count mismatch! Expected {expected_features_count}, got {len(features)}.")
        return features[:expected_features_count]

    return features



def classify_url(url):
    """Classify the URL as phishing or legitimate."""
    features = featureExtraction(url)
    
    # Dummy classification logic
    if features[-1] == 0:  # Non-HTTPS
        print(f"Warning: The URL '{url}' is not HTTPS secure.")
        return "Phishing"
    
    # Placeholder for actual model prediction
    # Here you would use your model to classify based on features
    # Example:
    # prediction = model.predict(np.array(features).reshape(1, -1))

    print(f"URL Features: {features}")
    return "Legitimate"  # For the purpose of this demo

def main():
    if not checkIsOnline():
        print("No internet connection. Please check your connection and try again.")
        return

    while True:
        url = input("Enter a URL to classify (or 'exit' to quit): ")
        if url.lower() == 'exit':
            print("Exiting the program.")
            break
        elif not url.startswith(("http://", "https://")):
            print("Please enter a valid URL starting with 'http://' or 'https://'.")
            continue
        
        classification = classify_url(url)
        print(f"The URL '{url}' is classified as: {classification}")

if __name__ == "__main__":
    main()
