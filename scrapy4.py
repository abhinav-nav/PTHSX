 #Python script that utilizes machine learning to classify a website as malware or benign:





import requests
from bs4 import BeautifulSoup
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import re

# Define a function to extract text content from HTML
def extract_text(html):
    soup = BeautifulSoup(html, 'html.parser')
    text = soup.get_text(separator=' ')
    text = re.sub(r'\s+', ' ', text)
    return text.strip()

# Fetch training data (malicious and benign websites)
malicious_url = 'https://www.example.com/malicious_urls.txt'
benign_url = 'https://www.example.com/benign_urls.txt'

malicious_response = requests.get(malicious_url)
benign_response = requests.get(benign_url)

malicious_urls = malicious_response.text.split('\n')
benign_urls = benign_response.text.split('\n')

# Combine malicious and benign URLs as training data
urls = malicious_urls + benign_urls
labels = ['malicious'] * len(malicious_urls) + ['benign'] * len(benign_urls)

# Fetch website content and extract text features
corpus = []
for url in urls:
    try:
        response = requests.get(url)
        if response.status_code == 200:
            text = extract_text(response.text)
            corpus.append(text)
        else:
            print(f"Failed to fetch content for {url}")
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")

# Convert text features to numerical vectors using TF-IDF
vectorizer = TfidfVectorizer()
X = vectorizer.fit_transform(corpus)

# Split the data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, labels, test_size=0.2, random_state=42)

# Train a random forest classifier
classifier = RandomForestClassifier()
classifier.fit(X_train, y_train)

# Evaluate the classifier
accuracy = classifier.score(X_test, y_test)
print(f"Accuracy: {accuracy}")

# Classify a new website
new_website_url = 'https://www.example.com/new_website'
try:
    response = requests.get(new_website_url)
    if response.status_code == 200:
        new_text = extract_text(response.text)
        new_vector = vectorizer.transform([new_text])
        prediction = classifier.predict(new_vector)[0]
        print(f"The website '{new_website_url}' is classified as {prediction}")
    else:
        print(f"Failed to fetch content for {new_website_url}")
except requests.exceptions.RequestException as e:
    print(f"An error occurred: {e}")
