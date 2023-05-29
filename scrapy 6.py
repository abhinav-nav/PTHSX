
import requests
import urllib.parse
import pymal

def analyze_website(url):
    # Fetch website content
    response = requests.get(url)
    if response.status_code != 200:
        print(f"Failed to fetch content for {url}")
        return

    content = response.content.decode('utf-8')

    # Analyze website for malware
    scanner = pymal.Scanner()
    results = scanner.scan(content)

    if results:
        print(f"The website '{url}' contains potential malware:")
        for result in results:
            print(f"- {result}")

    # Gather additional security information
    parsed_url = urllib.parse.urlparse(url)

    # Check SSL certificate
    ssl_info = pymal.check_ssl(parsed_url.netloc)
    if ssl_info['valid']:
        print(f"SSL certificate for {parsed_url.netloc} is valid and issued by {ssl_info['issuer']}")
    else:
        print(f"SSL certificate for {parsed_url.netloc} is not valid. Reason: {ssl_info['reason']}")

    # Check DNS records
    dns_records = pymal.check_dns(parsed_url.netloc)
    if dns_records:
        print(f"DNS records for {parsed_url.netloc}:")
        for record in dns_records:
            print(f"- {record}")
    else:
        print(f"No DNS records found for {parsed_url.netloc}")


# Test the script
website_url = 'https://www.example.com'
analyze_website(website_url)
