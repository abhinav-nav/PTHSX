
#Before running the script, make sure to replace 'YOUR_VIRUS_TOTAL_API_KEY' and 'YOUR_SAFE_BROWSING_API_KEY' with your actual API keys for VirusTotal and Google Safe Browsing respectively.
#This advanced script incorporates the following features:Fetches the website content using requests library.
#Extracts the text content from the HTML using BeautifulSoup.
#Checks for malware using the VirusTotal API, analyzing the extracted text content.
#Checks for potential malware using the Google Safe Browsing API.
#Allows you to perform additional analysis or checks based on your requirements. 
#Please note that this script relies on external APIs and their effectiveness depends on the accuracy and availability of those services. It's crucial to use multiple security measures and consult specialized tools and services for comprehensive website security analysis.


Fetches the website content using requests library.
Extracts the text content from the HTML using BeautifulSoup.
Checks for malware using the VirusTotal API, analyzing the extracted text content.
Checks for potential malware using the Google Safe Browsing API.
Allows you to perform additional analysis or checks based on your requirements.
Please note that this script relies on external APIs and their effectiveness depends on the accuracy and availability of those services. It's crucial to use multiple security measures and consult specialized tools and services for comprehensive website security analysis.
This advanced script incorporates the following features:

Fetches the website content using requests library.
Extracts the text content from the HTML using BeautifulSoup.
Checks for malware using the VirusTotal API, analyzing the extracted text content.
Checks for potential malware using the Google Safe Browsing API.
Allows you to perform additional analysis or checks based on your requirements.
Please note that this script relies on external APIs and their effectiveness depends on the accuracy and availability of those services. It's crucial to use multiple security measures and consult specialized tools and services for comprehensive website security analysis.

import requests
import urllib.parse
from bs4 import BeautifulSoup
from tldextract import extract
from virus_total_apis import PublicApi as VirusTotalPublicApi
from googleapiclient.discovery import build

# Define the VirusTotal API key
virus_total_api_key = 'YOUR_VIRUS_TOTAL_API_KEY'

# Define the Google Safe Browsing API key
safe_browsing_api_key = 'YOUR_SAFE_BROWSING_API_KEY'

def fetch_website_content(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return response.content
        else:
            print(f"Failed to fetch content for {url}")
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")

def extract_text(html):
    soup = BeautifulSoup(html, 'html.parser')
    text = soup.get_text(separator=' ')
    return text.strip()

def check_malware_with_virustotal(content):
    vt = VirusTotalPublicApi(virus_total_api_key)
    response = vt.scan_url(content)
    return response['results']['positives'] > 0

def check_safe_browsing(url):
    service = build("safebrowsing", "v4", developerKey=safe_browsing_api_key)
    threat_types = ['MALWARE', 'SOCIAL_ENGINEERING', 'POTENTIALLY_HARMFUL_APPLICATION', 'UNWANTED_SOFTWARE']
    request_body = {
        "client": {
            "clientId": "your_client_id",
            "clientVersion": "1.5.2"
        },
        "threatInfo": {
            "threatTypes": threat_types,
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": url}
            ]
        }
    }
    response = service.threatMatches().find(body=request_body).execute()
    return 'matches' in response

def analyze_website(url):
    content = fetch_website_content(url)
    if not content:
        return

    text_content = extract_text(content)

    # Check for malware using VirusTotal
    is_malware = check_malware_with_virustotal(text_content)
    if is_malware:
        print(f"The website '{url}' is flagged as potential malware by VirusTotal.")

    # Check for malware using Google Safe Browsing
    is_safe_browsing = check_safe_browsing(url)
    if is_safe_browsing:
        print(f"The website '{url}' is flagged as potential malware by Google Safe Browsing.")

    # Perform additional analysis or checks based on your requirements


# Test the script
website_url = 'https://www.example.com'
analyze_website(website_url)
