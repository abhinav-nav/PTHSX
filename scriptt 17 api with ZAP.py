#This script uses the OWASP ZAP tool, which is an open-source web application security scanner, to perform an active scan on the provided API.
# It starts the ZAP daemon, configures ZAP as a proxy for requests, triggers traffic recording, and performs an active scan. Finally,
# it retrieves the scan results and prints any vulnerabilities found.

Before running the script, make sure you have ZAP installed on your system and adjust the paths in the subprocess.Popen calls accordingly.
import subprocess
import time
import requests

def start_zap():
    subprocess.Popen(['zap.sh', '-daemon'])

def shutdown_zap():
    subprocess.Popen(['zap.sh', '-shutdown'])

def scan_api(api_url):
    # Start ZAP
    start_zap()
    time.sleep(10)  # Wait for ZAP to initialize

    # Set up ZAP API endpoint
    zap_proxy = {'http': 'http://localhost:8080', 'https': 'http://localhost:8080'}
    zap_url = 'http://localhost:8080'

    # Configure ZAP as a proxy for requests
    proxies = {'http': 'http://localhost:8080', 'https': 'http://localhost:8080'}

    # Access the API to trigger ZAP to record traffic
    requests.get(api_url, proxies=proxies)

    # Perform active scanning on the API
    subprocess.Popen(['zap-api-scan.py', '-t', api_url, '-f', 'openapi'])

    # Wait for scanning to complete
    time.sleep(60)  # Adjust the time based on the complexity of your API

    # Retrieve the scan results
    response = requests.get(zap_url + '/JSON/core/view/alerts')
    alerts = response.json()['alerts']

    # Print the vulnerabilities found
    if len(alerts) > 0:
        print("Vulnerabilities found:")
        for alert in alerts:
            print(f"  - {alert['risk']} - {alert['name']}")
    else:
        print("No vulnerabilities found.")

    # Shutdown ZAP
    shutdown_zap()

# Usage example
api_url = "https://example.com/api/endpoint"
scan_api(api_url)
