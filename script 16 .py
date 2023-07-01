#Python script that uses the requests library to check for common vulnerabilities in an API:
#In this script, we are checking for three common vulnerabilities: SQL injection, Cross-Site Scripting (XSS), and Remote Code Execution (RCE).
# You can modify the payloads and customize the checks based on your specific requirements.

Please note that this script provides a basic example and may not cover all possible vulnerabilities. 

import requests

def check_api_vulnerability(api_url):
    # Check for SQL injection vulnerability
    payload = "' OR '1'='1'"
    response = requests.get(api_url + "?param=" + payload)
    if "error" in response.text:
        print("SQL Injection vulnerability detected!")

    # Check for Cross-Site Scripting (XSS) vulnerability
    payload = "<script>alert('XSS');</script>"
    response = requests.get(api_url + "?param=" + payload)
    if "<script>alert('XSS');</script>" in response.text:
        print("XSS vulnerability detected!")

    # Check for Remote Code Execution (RCE) vulnerability
    payload = "__import__('os').system('ls')"
    response = requests.get(api_url + "?param=" + payload)
    if "file1.txt" in response.text:
        print("RCE vulnerability detected!")

# Usage example
api_url = "https://example.com/api/endpoint"
check_api_vulnerability(api_url)
