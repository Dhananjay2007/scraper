import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import time
import schedule
from datetime import datetime
from dotenv import load_dotenv
import os
import pandas as pd
import random

load_dotenv()

# NVD and Threat Intelligence
NVD_API_KEY = os.getenv("350d5c31-5251-430f-96bf-cdcd7b6b6401")
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# THREAT_FEED_URL = "https://mock-threat-feed.com/api/threats"  # Replace with a real API if available

# User-Agent and Proxy Rotation
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
]
PROXIES = [
    {"http": "http://proxy1.com:8080", "https": "https://proxy1.com:8080"},
    {"http": "http://proxy2.com:8080", "https": "https://proxy2.com:8080"},
]

# Rotate headers and proxies
def get_request_headers():
    return {"User-Agent": random.choice(USER_AGENTS)}

def get_proxy():
    return random.choice(PROXIES)

# Fetch page content with rotating proxies and user-agents
def fetch_page(url):
    try:
        response = requests.get(url, timeout=10, headers=get_request_headers(), proxies=get_proxy())
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        print(f"Error fetching {url}: {e}")
        return None

# Extract metadata
def extract_software_metadata(url):
    print(f"Extracting metadata from {url}")
    metadata = []
    page_content = fetch_page(url)
    if page_content:
        soup = BeautifulSoup(page_content, "html.parser")
        for script in soup.find_all("script", src=True):
            src = script["src"]
            if "jquery" in src.lower():
                metadata.append("jQuery")
            elif "bootstrap" in src.lower():
                metadata.append("Bootstrap")
        for meta in soup.find_all("meta"):
            if "generator" in meta.attrs.get("name", "").lower():
                metadata.append(meta.attrs.get("content", ""))
    return metadata

# Query NVD API for vulnerabilities
def query_nvd_api(software_list):
    vulnerabilities = []
    for software in software_list:
        print(f"Querying NVD for {software}")
        try:
            params = {"keyword": software, "resultsPerPage": 5}
            headers = {"apiKey": NVD_API_KEY}
            response = requests.get(NVD_API_URL, params=params, headers=headers)
            response.raise_for_status()
            data = response.json()
            for item in data.get("vulnerabilities", []):
                vuln = {
                    "id": item.get("cve", {}).get("id"),
                    "description": item.get("cve", {}).get("descriptions", [{}])[0].get("value", "No description"),
                    "severity": item.get("cve", {}).get("metrics", {}).get("cvssMetricV3", {}).get("baseSeverity", "Unknown"),
                    "publishedDate": item.get("publishedDate", "Unknown")
                }
                vulnerabilities.append(vuln)
        except requests.RequestException as e:
            print(f"Error querying NVD API for {software}: {e}")
    return vulnerabilities

# Fetch real-time threat intelligence
# def fetch_threat_intelligence():
#     print("Fetching real-time threat intelligence...")
#     try:
#         response = requests.get(THREAT_FEED_URL, timeout=10)
#         response.raise_for_status()
#         return response.json()
#     except requests.RequestException as e:
#         print(f"Error fetching threat intelligence: {e}")
#         return []

# Exploit prediction (mocked with basic historical data)
def predict_exploits(vulnerabilities):
    print("Predicting likely exploits...")
    for vuln in vulnerabilities:
        if "remote code execution" in vuln["description"].lower():
            vuln["likely_exploit"] = "High"
        else:
            vuln["likely_exploit"] = "Low"
    return vulnerabilities

# Crawl the website
def crawl_website(url):
    visited = set()
    to_visit = [url]
    internal_links = []

    while to_visit:
        current_url = to_visit.pop()
        if current_url not in visited:
            visited.add(current_url)
            print(f"Crawling: {current_url}")
            page_content = fetch_page(current_url)
            if page_content:
                soup = BeautifulSoup(page_content, "html.parser")
                for a_tag in soup.find_all("a", href=True):
                    link = urljoin(url, a_tag["href"])
                    if link.startswith(url) and link not in visited:
                        to_visit.append(link)
                        internal_links.append(link)
    return internal_links

# Save the report
def save_report(vulnerabilities, url):
    df = pd.DataFrame(vulnerabilities)
    filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    df.to_csv(filename, index=False)
    print(f"Report saved for {url}: {filename}")

# Scan the website
def scan_website(url):
    print(f"Starting scan for {url} at {datetime.now()}")
    internal_links = crawl_website(url)
    vulnerabilities = []

    for link in internal_links:
        print(f"Scanning {link}")
        metadata = extract_software_metadata(link)
        if metadata:
            print(f"Metadata found: {metadata}")
            vulns = query_nvd_api(metadata)
            vulnerabilities.extend(vulns)

    # # Fetch and merge threat intelligence
    # threat_data = fetch_threat_intelligence()
    # for vuln in vulnerabilities:
    #     vuln["threat_intel"] = threat_data

    # Predict exploits
    vulnerabilities = predict_exploits(vulnerabilities)

    # Save the enhanced report
    save_report(vulnerabilities, url)

# Schedule scans
def schedule_scan(url, interval=24):
    schedule.every(interval).hours.do(scan_website, url=url)
    print(f"Scheduled scans for {url} every {interval} hours.")
    while True:
        schedule.run_pending()
        time.sleep(1)

# Main function
if __name__ == "__main__":
    target_url = input("Enter the website URL to scan: ")
    scan_website(target_url)
    schedule_scan(target_url)
