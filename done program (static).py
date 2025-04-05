from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from bs4 import BeautifulSoup
import re
import time
import logging
import requests
from urllib.parse import urljoin, urlparse
import asyncio
from concurrent.futures import ThreadPoolExecutor

# Configure logging
logging.basicConfig(level=logging.INFO)

def vulners_api(cve_id):
    url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return {
                'description': data['result']['CVE_Items'][0]['cve']['description']['description_data'][0]['value'],
                'severity': data['result']['CVE_Items'][0]['impact']['baseMetricV3']['cvssV3']['baseSeverity'],
                'published_date': data['result']['CVE_Items'][0]['publishedDate']
            }
        return {'description': 'No data available', 'severity': 'Unknown', 'published_date': 'N/A'}
    except Exception as e:
        logging.error(f"Error fetching CVE details for {cve_id}: {e}")
        return {'description': 'Error occurred', 'severity': 'Unknown', 'published_date': 'N/A'}

# Function to fetch CVE details from the CVE database
def get_cve_details(vuln_type):
    # Search for CVEs related to the vulnerability type
    cve_search_results = vulners_api.search(vuln_type)

    # Extract the first 5 results (adjust the number as needed)
    cves = cve_search_results[:5]

    # Create a list to store detailed CVE info
    cve_details = []

    for cve in cves:
        cve_info = {
            'cve': cve.get('id', 'N/A'),
            'description': cve.get('description', 'No description available'),
            'severity': cve.get('severity', 'Unknown'),
            'link': cve.get('url', 'No link available'),
        }
        cve_details.append(cve_info)

    return cve_details


# Define a dictionary to map vulnerabilities to their mitigation strategies
vuln_mitigation_map = {
    'SQL Injection': 'Use prepared statements, parameterized queries, and ORM frameworks to avoid direct user input in queries.',
    'XSS': 'Validate and sanitize user inputs, use content security policies (CSP), and escape output.',
    'Remote Code Execution (RCE)': 'Implement strict input validation and restrict execution of untrusted code.',
    'Sensitive Data Exposure': 'Use encryption for sensitive data both in transit and at rest, implement access controls.',
    'Directory Traversal': 'Sanitize file paths, validate user input, and limit directory access.',
    'Command Injection': 'Validate inputs, avoid dynamic command execution, and use safer libraries.',
    'Authentication Flaws': 'Use multi-factor authentication (MFA), hash passwords securely, and implement rate-limiting.',
    'Broken Access Control': 'Use role-based access control (RBAC), ensure access control is enforced at all levels.',
    'Clickjacking': 'Use X-Frame-Options HTTP header or Content Security Policy (CSP) to prevent your site from being embedded.',
    'Insecure Deserialization': 'Validate and sanitize inputs, and use secure libraries for deserialization.',
    'CSRF': 'Use anti-CSRF tokens and ensure proper validation of requests.'
}


# Function to get the mitigation strategy based on vulnerability description
def get_mitigation(vuln_description):
    for vuln_type in vuln_mitigation_map:
        if vuln_type.lower() in vuln_description.lower():
            return vuln_mitigation_map[vuln_type]
    return "General mitigation: Implement secure coding practices, input validation, and proper access controls."


# Function to analyze JavaScript code for patterns that may indicate vulnerabilities
def analyze_js_for_vulnerabilities(js_code):
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
                    'pattern': pattern,
                    'description': f"JavaScript vulnerability detected: {vuln_type} via '{pattern}'"
                })

    return vulnerabilities


# Function to fetch vulnerabilities from a webpage, including JavaScript checks
def fetch_vulnerabilities_selenium(url, visited_urls):
    # Check if the URL has already been visited
    if url in visited_urls:
        return []
    if url.lower().endswith(('.pdf', '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico', '.mp4', '.avi', '.mp3', '.wav')):
        logging.info(f"Skipping unwanted file: {url}")
        return []
    # Mark the URL as visited
    visited_urls.add(url)

    # Setup Selenium WebDriver with headless option
    chrome_options = Options()
    chrome_options.add_argument("--headless")  # Run in headless mode
    chrome_options.add_argument("--disable-gpu")  # Disable GPU hardware acceleration
    chrome_options.add_argument("--no-sandbox")  # Disable sandboxing (useful for some environments)

    vulnerabilities = []
    try:
        driver = webdriver.Chrome(options=chrome_options)  # Ensure ChromeDriver is installed and configured
        driver.get(url)
        time.sleep(5)  #Allow JavaScript to load completely

        soup = BeautifulSoup(driver.page_source, 'html.parser')
        vulnerabilities = []

        # Common vulnerability patterns
        vuln_patterns = [
            (r'(SQL Injection)', 'Critical'),
            (r'(XSS|Cross-Site Scripting)', 'High'),
            (r'(Remote Code Execution|RCE)', 'Critical'),
            (r'(Sensitive Data Exposure)', 'High'),
            (r'(Directory Traversal)', 'Medium'),
            (r'(Command Injection)', 'Critical'),
            (r'(Authentication Flaws)', 'High'),
            (r'(Broken Access Control)', 'High'),
            (r'(Clickjacking)', 'Medium'),
            (r'(Insecure Deserialization)', 'High'),
            (r'(CSRF|Cross-Site Request Forgery)', 'High')
        ]

        # Search for vulnerabilities based on regex patterns
        for pattern, severity in vuln_patterns:
            for vuln in soup.find_all(string=re.compile(pattern, re.IGNORECASE)):
                cve_match = re.search(r'CVE-\d{4}-\d{4,7}', vuln.strip())
                cve_id = cve_match.group() if cve_match else 'N/A'

                if cve_id != 'N/A':
                    cve_id, published_date, description = get_cve_details(cve_id)
                else:
                    published_date = 'N/A'
                    description = vuln.strip()

                mitigation = get_mitigation(description)
                vulnerabilities.append({
                    'cve_id': cve_id,
                    'description': description,
                    'published_date': published_date,
                    'severity': severity,
                    'mitigation': mitigation
                })

        # JavaScript vulnerability scanning
        for script_tag in soup.find_all('script'):
            js_code = script_tag.string or ''
            js_vulns = analyze_js_for_vulnerabilities(js_code)
            for js_vuln in js_vulns:
                vulnerabilities.append({
                    'cve_id': 'N/A',
                    'description': js_vuln['description'],
                    'published_date': 'N/A',
                    'severity': 'High',
                    'mitigation': vuln_mitigation_map.get(js_vuln['type'], 'Review JavaScript code for security.')
                })

        # Extract internal links and follow them
        internal_links = []
        for a_tag in soup.find_all('a', href=True):
            link = a_tag['href']
            if link.startswith('javascript:void(0)') or link.startswith('mailto:'):
                continue
            if link.startswith('http'):
                if urlparse(link).netloc == urlparse(url).netloc:  # Only follow internal links
                    internal_links.append(link)
            else:
                internal_links.append(urljoin(url, link))

        # Recursively scan internal pages
        for link in internal_links:
            vulnerabilities += fetch_vulnerabilities_selenium(link, visited_urls)

    except Exception as e:
        logging.error(f"Error while processing {url}: {e}")
    finally:
        driver.quit()

    logging.info(f"Found {len(vulnerabilities)} vulnerabilities on {url}.")
    return vulnerabilities
def is_dynamic_website(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            # Parse the response to look for signs of dynamic content (JavaScript)
            if re.search(r'<script', response.text, re.IGNORECASE):
                return True  # Dynamic
            else:
                return False  # Static
        else:
            logging.error(f"Failed to fetch URL {url}: {response.status_code}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching URL: {e}")
    return False  # Default to static if error

def fetch_vulnerabilities(url, visited_urls):
    # Check if the website is dynamic or static
    if is_dynamic_website(url):
        # Use Selenium for dynamic websites
        return fetch_vulnerabilities_selenium(url, visited_urls)
    else:
        # Use simpler method for static websites (requests + BeautifulSoup)
        return fetch_vulnerabilities_static(url)


# Main function to monitor vulnerabilities
async def monitor_vulnerabilities():
    url = input("Enter the URL to scan: ")
    visited_urls = set()
    while True:
        vulnerabilities = await asyncio.to_thread(fetch_vulnerabilities_selenium, url, visited_urls)
        if vulnerabilities:
            for vuln in vulnerabilities:
                logging.info(f"Vulnerability Detected:")
                logging.info(f"  Type: {vuln['severity']}")
                logging.info(f"  CVE ID: {vuln['cve_id']}")
                logging.info(f"  Published Date: {vuln['published_date']}")
                logging.info(f"  Description: {vuln['description']}")
                logging.info(f"  Mitigation: {vuln['mitigation']}")
        else:
            logging.info("No new vulnerabilities found.")
        logging.info("Sleeping for 10 seconds during testing (1 hour in production).")
        await asyncio.sleep(10)


# Start monitoring
asyncio.run(monitor_vulnerabilities())
