#Certainly! Here's an example of a more advanced Python script that uses the Google Safe Browsing API to check whether a website is flagged as potentially dangerous:


import requests
import hashlib
import json

def check_website(url):
    # Insert your Google Safe Browsing API key here
    api_key = 'YOUR_API_KEY'

    # API endpoint for Google Safe Browsing
    safe_browsing_endpoint = 'https://safebrowsing.googleapis.com/v4/threatMatches:find'

    # Hash the URL using SHA256
    url_hash = hashlib.sha256(url.encode()).hexdigest()

    request_body = {
        "client": {
            "clientId": "your_client_id",
            "clientVersion": "1.5.2"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": url}
            ]
        }
    }

    params = {'key': api_key}

    try:
        response = requests.post(safe_browsing_endpoint, params=params, json=request_body)
        result = response.json()

        if 'matches' in result:
            print(f"The website '{url}' is flagged as potentially dangerous by Google Safe Browsing.")
        else:
            print(f"The website '{url}' is safe.")

    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")


# Test the script
website_url = 'https://www.example.com'
check_website(website_url)
