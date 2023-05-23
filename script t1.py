
import requests

def check_website(url):
    # Insert your VirusTotal API key here
    api_key = 'YOUR_API_KEY'

    # Endpoint for VirusTotal URL scan
    url_scan_endpoint = 'https://www.virustotal.com/vtapi/v2/url/report'

    params = {'apikey': api_key, 'resource': url}

    try:
        response = requests.get(url_scan_endpoint, params=params)
        result = response.json()

        if result['response_code'] == 1:
            # Website is checked successfully

            if result['positives'] > 0:
                print(f"The website '{url}' is flagged as potentially malicious.")
            else:
                print(f"The website '{url}' is safe.")

        elif result['response_code'] == -2:
            print("The website is still being analyzed. Please try again later.")

        else:
            print("No information available for the website.")

    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")


# Test the script
website_url = 'https://www.example.com'
check_website(website_url)
