from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from bs4 import BeautifulSoup
import re
import time
import logging
from urllib.parse import urljoin, urlparse
from threading import Lock
import requests

# Configure logging
logging.basicConfig(level=logging.INFO)

# Thread-safe visited URLs set
visited_urls = set()
visited_urls_lock = Lock()

def safe_add_to_visited(url):
    """Thread-safe addition to visited URLs."""
    with visited_urls_lock:
        if url in visited_urls:
            return False
        visited_urls.add(url)
        return True

# Retry logic for Selenium
def safe_get(driver, url, retries=3):
    """Retries loading a URL with Selenium."""
    for attempt in range(retries):
        try:
            driver.get(url)
            return True
        except Exception as e:
            logging.warning(f"Attempt {attempt + 1}: Failed to load {url}. Retrying... Error: {e}")
            time.sleep(2)
    logging.error(f"Failed to load {url} after {retries} attempts.")
    return False

def enhanced_pattern_matching(response_text):
    """Detect vulnerabilities using response validation."""
    patterns = patterns = {
    'SQL Injection': {
        'payload': "' OR '1'='1",
        'validation': lambda text: "syntax error" in text.lower() or "sql" in text.lower(),
    },
    'Cross-Site Scripting (XSS)': {
        'payload': "<script>alert('XSS')</script>",
        'validation': lambda text: "<script>alert('XSS')</script>" in text,
    },
    'Blind SQL Injection': {
        'payload': "' AND ASCII(SUBSTRING((SELECT database()), 1, 1)) > 77--",
        'validation': lambda text: "true" in text.lower() or "wait" in text.lower(),
    },
    'Time-Based SQL Injection': {
        'payload': "' OR IF(1=1, SLEEP(5), 0)--",
        'validation': lambda response_time: response_time > 5,  # Assuming response_time is measured
    },
    'Reflected XSS': {
        'payload': "<img src=x onerror=alert('XSS') />",
        'validation': lambda text: "<img src=x onerror=alert('XSS') />" in text,
    },
    'Stored XSS': {
        'payload': "<script>alert('Stored XSS')</script>",
        'validation': lambda text: "<script>alert('Stored XSS')</script>" in text,
    },
    'Error-Based SQL Injection': {
        'payload': "' OR 1=1; DROP TABLE users--",
        'validation': lambda text: "database" in text.lower() or "error" in text.lower(),
    },
    'DOM-Based XSS': {
        'payload': "javascript:alert(document.cookie)",
        'validation': lambda text: "document.cookie" in text,
    },
}

    detected_vulnerabilities = []

    for vuln_type, details in patterns.items():
        if details['validation'](response_text):
            detected_vulnerabilities.append({
                'type': vuln_type,
                'description': f"{vuln_type} detected using payload: {details['payload']}"
            })

    return detected_vulnerabilities

def fetch_vulnerabilities_selenium(url, visited_urls, max_depth=3, max_pages=100):
    """Crawl and detect vulnerabilities using Selenium."""
    def crawl_recursive(current_url, depth, crawled_pages):
        if not safe_add_to_visited(current_url) or depth > max_depth or crawled_pages[0] >= max_pages:
            return []

        vulnerabilities = []
        crawled_pages[0] += 1

        # Set up Selenium
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--no-sandbox")

        try:
            driver = webdriver.Chrome(options=chrome_options)
            if not safe_get(driver, current_url):
                return []

            time.sleep(3)
            soup = BeautifulSoup(driver.page_source, 'html.parser')

            # Analyze JavaScript vulnerabilities
            for script_tag in soup.find_all('script'):
                js_code = script_tag.string or ''
                vulnerabilities += analyze_js_for_vulnerabilities(js_code)

            # Extract internal links
            internal_links = []
            for a_tag in soup.find_all('a', href=True):
                link = a_tag['href']
                if not link.startswith(('http', 'mailto:', 'javascript:')):
                    link = urljoin(current_url, link)
                if urlparse(link).netloc == urlparse(current_url).netloc:
                    internal_links.append(link)

            # Recursively follow links
            for link in internal_links:
                vulnerabilities += crawl_recursive(link, depth + 1, crawled_pages)

        except Exception as e:
            logging.error(f"Error while processing {current_url}: {e}")
        finally:
            driver.quit()

        return vulnerabilities

    return crawl_recursive(url, 0, [0])

def analyze_js_for_vulnerabilities(js_code):
    """Analyze JavaScript for potential vulnerabilities."""
    js_vuln_patterns = {
        'XSS': [r'document\.write', r'innerHTML', r'outerHTML'],
        'JavaScript Injection': [r'eval\(', r'setTimeout\(', r'setInterval\(', r'Function\(']
    }
    vulnerabilities = []

    for vuln_type, patterns in js_vuln_patterns.items():
        for pattern in patterns:
            if re.search(pattern, js_code, re.IGNORECASE):
                vulnerabilities.append({
                    'type': vuln_type,
                    'description': f"JavaScript vulnerability detected: {vuln_type} via '{pattern}'"
                })

    return vulnerabilities

# Check if a website is dynamic
def is_dynamic_website(url):
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            if re.search(r'<script', response.text, re.IGNORECASE):
                return True
        else:
            logging.error(f"Failed to fetch URL {url}: {response.status_code}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching URL: {e}")
    return False

# Fetch vulnerabilities based on website type
def fetch_vulnerabilities(url,visited_urls):
    if is_dynamic_website(url):
        return fetch_vulnerabilities_selenium(url, visited_urls)
    else:
        logging.info(f"Static website detected: {url}")
        return []  # Placeholder for static site handling (e.g., requests + BeautifulSoup)

# Main function
if __name__ == "__main__":
    base_url = input("Enter the URL to scan: ").strip()
    visited_urls = set()

    print("Starting advanced vulnerability scanning...")
    vulnerabilities = fetch_vulnerabilities_selenium(base_url, visited_urls, max_depth=3, max_pages=100)

    if vulnerabilities:
        for vuln in vulnerabilities:
            logging.info(f"Vulnerability Detected: {vuln}")
    else:
        logging.info("No vulnerabilities found.")