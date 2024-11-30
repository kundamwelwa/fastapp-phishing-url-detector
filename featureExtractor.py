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
                      r"tr\.im|link\.zip\.net|rebrandly\.com|t2mio\.com|bl\.ink|shrtco\.de|t\.ly|hyperurl\.co|" \
                      r"vrl\.me|tinycc\.com|clickmeter\.com|capsulink\.com|bit\.xyz|mcaf\.ee|sub2\.me|rb\.gy|" \
                      r"lnk\.fi|bitlyservices\.com|zpr\.io|shorturl\.at|fml\.li|getpocket\.com|mstr\.cd"

 
# Updated Feature Extractor Code

# 1. Check for Internet Connectivity
def checkIsOnline():
    try:
        response = requests.get('https://www.google.com', timeout=5)  # Increase timeout
        return response.status_code == 200
    except requests.exceptions.ConnectionError:
        return False
    except requests.exceptions.Timeout:
        print("Connection timed out. Retrying...")
        return False


# 2. Extract Domain
def getDomain(url):
    parsed = urlparse(url)
    domain_parts = parsed.netloc.split('.')
    return ".".join(domain_parts[-2:]) if len(domain_parts) > 2 else parsed.netloc.replace("www.", "")

# 3. Checks for IP Address in URL
def havingIP(url):
    try:
        ipaddress.ip_address(url)
        return 1
    except ValueError:
        return 0

# 4. Checks for '@' in URL
def haveAtSign(url):
    return 1 if "@" in url else 0

# 5. URL Length
def getLength(url):
    return 0 if len(url) < 54 else 1

# 6. URL Depth
def getDepth(url):
    return len([part for part in urlparse(url).path.split('/') if part])

# 7. Redirection '//' in URL
def redirection(url):
    pos = url.rfind('//')
    return 1 if pos > 6 else 0

# 8. HTTPS in Domain
def httpDomain(url):
    return 0

# 9. Shortened URL
def tinyURL(url):
    return 1 if re.search(shortening_services, url) else 0

# 10. Prefix/Suffix in Domain
def prefixSuffix(url):
    return 1 if '-' in urlparse(url).netloc else 0

# 11. Web Traffic Check
def web_traffic(url):
    domain = getDomain(url)
    base_url = f"https://www.semrush.com/website/{domain}/overview/"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }
    
    try:
        # Make the request with a timeout to avoid long hangs
        response = requests.get(base_url, headers=headers, timeout=5)
        response.raise_for_status()  # Check if the response was successful (status 200)
        
        soup = BeautifulSoup(response.text, "html.parser")
        # Adjust this to more general or reliable element class based on the website's structure
        rank_elements = soup.find_all("b", class_="rank-card__SCRank-sc-2sba91-8")
        
        if rank_elements:
            try:
                # Attempt to parse and return rank data if available
                rank = int(rank_elements[0].text.replace(',', ''))
                return 1 if rank < 100000 else 0
            except ValueError:
                # Handle case where rank cannot be converted to an integer
                print(f"Error parsing rank for {domain}. Rank value could not be converted.")
                return 0
        else:
            print(f"No rank data found for {domain}.")
            return 0  # Neutral if no rank data is found

    except requests.exceptions.Timeout:
        print(f"Timeout error fetching Semrush data for {domain}.")
        return 0  # Neutral if request times out

    except requests.exceptions.ConnectionError:
        print(f"Connection error fetching Semrush data for {domain}.")
        return 0  # Neutral if there is a connection issue

    except requests.exceptions.RequestException as e:
        # Catch other request errors and log them
        print(f"Error fetching Semrush data for {domain}: {e}")
        return 0  # Neutral in case of any other request errors

# 12. Domain Age
def domainAge(domain_name):
    try:
        creation_date = domain_name.creation_date
        expiration_date = domain_name.expiration_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        if creation_date and expiration_date:
            age = (expiration_date - creation_date).days // 30
            return 1 if age < 6 else 0
        return 1
    except Exception as e:
        print(f"Error during WHOIS lookup: {e}")
        return 1

# 13. Domain Expiration
def domainEnd(domain_name):
    try:
        expiration_date = domain_name.expiration_date
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        if expiration_date:
            end = (expiration_date - datetime.now()).days // 30
            return 1 if end < 6 else 0
        return 1
    except Exception as e:
        print(f"Error checking domain expiration: {e}")
        return 1

# 14. iFrame Redirection
def iframe(response):
    if not response:
        return 1
    return 0 if re.findall(r"<iframe>|<frameBorder>", response.text) else 1

# 15. Mouse Over Events
def mouseOver(response):
    if not response:
        return 1
    return 1 if re.findall("<script>.+onmouseover.+</script>", response.text) else 0

# 16. Right Click Disabled
def rightClick(response):
    if not response:
        return 1
    return 0 if re.findall(r"event.button ?== ?2", response.text) else 1

# 17. URL Forwarding
def forwarding(response):
    if not response:
        return 1
    return 1 if len(response.history) > 2 else 0

# 18. HTTPS Security
def check_https_security(url):
    headers = {
        "User-Agent": "Mozilla/5.0"
    }
    try:
        response = requests.get(url, timeout=5, headers=headers)
        return 1 if response.url.startswith("https://") else 0
    except requests.exceptions.RequestException as e:
        print(f"Error checking HTTPS: {e}")
        return 0

# Feature Extraction
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
    try:
        domain_name = whois.whois(getDomain(url))
        features.append(domainAge(domain_name))
        features.append(domainEnd(domain_name))
    except Exception as e:
        print(f"Error during WHOIS lookup: {e}")
        features.extend([1, 1])

    features.append(web_traffic(url))
    try:
        response = requests.get(url)
        features.append(iframe(response))
        features.append(mouseOver(response))
        features.append(rightClick(response))
        features.append(forwarding(response))
    except Exception as e:
        print(f"Error fetching URL content: {e}")
        features.extend([1, 1, 1, 1])

    features.append(check_https_security(url))
    return features
