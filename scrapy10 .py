




import requests
import urllib.parse
from bs4 import BeautifulSoup
import hashlib
from pykronalyze import analyze
from pykronalyze.utils import BehaviorPrinter
from virus_total_apis import PublicApi as VirusTotalPublicApi
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences

# Define the VirusTotal API key
virus_total_api_key = 'YOUR_VIRUS_TOTAL_API_KEY'

# Define the URL for the machine learning model
model_url = 'https://www.example.com/malware_detection_model.h5'

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

def calculate_md5_hash(content):
    md5_hash = hashlib.md5(content).hexdigest()
    return md5_hash

def check_malware_with_virustotal(content):
    vt = VirusTotalPublicApi(virus_total_api_key)
    response = vt.scan_buffer(content)
    return response['results']['positives'] > 0

def preprocess_text(text, tokenizer, max_length):
    sequences = tokenizer.texts_to_sequences([text])
    padded_sequences = pad_sequences(sequences, maxlen=max_length, padding='post', truncating='post')
    return padded_sequences

def analyze_website(url):
    content = fetch_website_content(url)
    if not content:
        return

    # Calculate the MD5 hash of the content
    md5_hash = calculate_md5_hash(content)

    # Extract text content from HTML
    text_content = extract_text(content)

    # Perform behavior analysis using PyKronalyze
    behavior_result = analyze(text_content, config={'print': BehaviorPrinter})
    if behavior_result:
        print(f"Behavior analysis results for '{url}':")
        behavior_result.print()

    # Check for malware using VirusTotal
    is_malware = check_malware_with_virustotal(content)
    if is_malware:
        print(f"The website '{url}' is flagged as potential malware by VirusTotal.")

    # Load the malware detection model
    response = requests.get(model_url)
    if response.status_code == 200:
        with open('malware_detection_model.h5', 'wb') as file:
            file.write(response.content)
        model = load_model('malware_detection_model.h5')
        if model:
            # Preprocess the text content
            tokenizer = Tokenizer()
            tokenizer.fit_on_texts([text_content])
            max_length = max([len(sequence.split()) for sequence in tokenizer.texts_to_sequences([text_content])])
            preprocessed_text = preprocess_text(text_content, tokenizer, max_length)

            # Predict malware probability
            malware_probability = model.predict(preprocessed_text)[0][0]

            if malware_probability >= 0.5:
                print(f"The website '{url}' is classified as potential malware with a probability of {malware_probability}.")
            else:
                print(f"The website '{url}' is classified as benign with a probability of {1 - malware_probability}.")


# Test the script
website_url = 'https://www.example.com'
analyze_website(website_url)
