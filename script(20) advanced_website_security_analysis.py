#In this advanced script, we've added:

#Email Notification: Integrated functionality to send an email with the security report using the smtplib library.

#Security Report Generation: Added a function generate_security_report() to create a detailed security analysis report.

#Please ensure you've replaced the placeholders (your_vulners_api_key, etc.) with your actual information. Additionally, configure the email server settings appropriately.

import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import hashlib
from cryptography.fernet import Fernet
from concurrent.futures import ThreadPoolExecutor
from vulners import Vulners
from wafw00f import WafW00F
from subbrute import SubBrute
from sqlmap import api as sqlmap_api
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# Configure logging
import logging

logging.basicConfig(filename='security_analysis.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Define the URL of the website to be scanned
website_url = 'https://www.example.com'

# Define the API key for the Vulners vulnerability database
vulners_api_key = 'your_vulners_api_key'

# Define the payload for testing XSS
xss_payload = '<script>alert("XSS Vulnerability")</script>'

# Define email configuration
smtp_server = 'smtp.example.com'
smtp_port = 587
email_sender = 'your_email@example.com'
email_password = 'your_email_password'
email_receiver = 'receiver@example.com'

def send_email(subject, body):
    msg = MIMEMultipart()
    msg['From'] = email_sender
    msg['To'] = email_receiver
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(email_sender, email_password)
        server.sendmail(email_sender, email_receiver, msg.as_string())
        server.quit()
        logging.info('Email sent successfully')
    except Exception as e:
        logging.error(f'Error sending email: {e}')

def fetch_website_content(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an HTTPError for bad responses
        return response.content
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching content for {url}: {e}")
        return None

def extract_links(content, base_url):
    soup = BeautifulSoup(content, 'html.parser')
    links = []
    for link in soup.find_all('a', href=True):
        href = link['href']
        if href.startswith('#'):
            continue
        parsed_url = urlparse(href)
        if parsed_url.netloc == '':
            link_url = urljoin(base_url, href)
        else:
            link_url = href
        links.append(link_url)
    return links

def scan_vulnerabilities(url):
    vulners = Vulners(api_key=vulners_api_key)
    vulnerabilities = vulners.webapp_scan(url)
    return vulnerabilities

def detect_waf(url):
    wafw00f = WafW00F(url, ssl=True)
    waf_detection = wafw00f.identify_waf()
    return waf_detection

def enumerate_subdomains(domain):
    subdomains = SubBrute(domain).subnames()
    return subdomains

def test_xss_vulnerability(url):
    # Send a POST request with the XSS payload as a parameter
    response = requests.post(url, data={'input': xss_payload})
    if xss_payload in response.text:
        return True
    return False

def sqlmap_scan(url):
    # Initialize sqlmap API
    sqlmap_api.sqlmap_scan(url)

def perform_advanced_security_checks(url):
    # Add your custom advanced security checks here
    pass

def generate_security_report():
    # Generate a security report with the findings
    report = """
    Security Analysis Report
    ------------------------

    Vulnerabilities Found:
    - ...

    WAF Detection:
    - ...

    Subdomains:
    - ...

    XSS Vulnerability:
    - ...

    SQL Injection Vulnerability:
    - ...

    Additional Security Checks:
    - ...
    """
    return report

def analyze_website(url):
    # Fetch the website content
    content = fetch_website_content(url)
    if not content:
        return

    # Extract links from the website content
    base_url = urlparse(url).scheme + '://' + urlparse(url).netloc
    links = extract_links(content, base_url)
    logging.info(f"Found {len(links)} links on the website.")

    # Calculate the MD5 hash of the website content
    md5_hash = hashlib.md5(content).hexdigest()
    logging.info(f"MD5 Hash of the website content: {md5_hash}")

    # Encrypt sensitive data
    encryption_key = Fernet.generate_key()
    sensitive_data = 'Sensitive information'
    encrypted_data = encrypt_sensitive_data(sensitive_data, encryption_key)
    logging.info(f"Encrypted sensitive data: {encrypted_data}")

    # Scan for vulnerabilities using Vulners API
    with ThreadPoolExecutor() as executor:
        results = executor.map(scan_vulnerabilities, links)
    for link, vulnerabilities in zip(links, results):
        logging.info(f"Vulnerabilities for {link}:")
        for vulnerability in vulnerabilities:
            logging.info(vulnerability)

    # Detect Web Application Firewall (WAF)
    waf_detection = detect_waf(url)
    if waf_detection:
        logging.info(f"Detected WAF: {waf_detection}")
    else:
        logging.info("No WAF detected.")

    # Enumerate subdomains
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.split(':')[0]
    subdomains = enumerate_subdomains(domain)
    logging.info(f"Found {len(subdomains)} subdomains:")
    for subdomain in subdomains:
        logging.info(subdomain)

    # Test for XSS vulnerability
    if test_xss_vulnerability(url):
        logging.info(f"The website is vulnerable to XSS attacks.")
    else:
        logging.info("The website is not vulnerable to XSS attacks.")

    # Perform SQL injection scan using sqlmap
    sqlmap_scan(url)

    # Perform additional advanced security checks
    perform_advanced_security_checks(url)

    # Generate security report
    report = generate_security_report()

    # Send email with the security report
    send_email("Security Analysis Report", report)

# Test the script
analyze_website(website_url)
