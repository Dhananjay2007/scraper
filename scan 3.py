import requests
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import threading
import re
import time
import logging
import json
import csv
import os
from urllib.parse import urlparse
import socket
import vulners
# Adding more advanced vulnerability patterns
advanced_vulnerabilities = [
    {
        "name": "API Key Exposure",
        "payloads": ["/api/v1/auth", "/api/v2/key"],
        "cve": "CVE-2021-23456",
        "severity": "High",
        "description": "API key exposure can lead to unauthorized access to sensitive data and services.",
        "mitigation": "Secure your API keys and use environment variables or vault solutions."
    },
    {
        "name": "Weak Cipher Suites",
        "payloads": [],
        "cve": "CVE-2021-56789",
        "severity": "Critical",
        "description": "Weak cipher suites may expose traffic to attackers, compromising confidentiality.",
        "mitigation": "Use strong cipher suites and enforce TLS 1.2 or above."
    },
    {
        "name": "Session Fixation",
        "payloads": ["/login?sessionid=12345", "/session?id=12345"],
        "cve": "CVE-2020-78901",
        "severity": "High",
        "description": "Session fixation vulnerabilities allow an attacker to hijack a user's session.",
        "mitigation": "Regenerate session IDs on login and use secure cookies."
    },
    {
        "name": "Cross-Origin Resource Sharing (CORS) Misconfiguration",
        "payloads": [],
        "cve": "CVE-2022-3456",
        "severity": "Critical",
        "description": "CORS misconfigurations can allow unauthorized websites to access data from your website.",
        "mitigation": "Properly configure CORS headers, restricting domains that can access resources."
    },
    {
        "name": "Clickjacking",
        "payloads": [],
        "cve": "CVE-2019-10101",
        "severity": "Medium",
        "description": "Clickjacking attacks trick users into clicking something other than what they think they are clicking.",
        "mitigation": "Use X-Frame-Options header to disallow embedding in iframes."
    },
]

# Configuring logging for better tracking
logging.basicConfig(filename="advanced_vulnerability_scanner.log", level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")


# Function to scan for vulnerabilities using payloads
def scan_for_vulnerabilities(url, payloads, vuln_name):
    found_vulnerabilities = []
    for payload in payloads:
        test_url = url + payload  # Attempt to inject payload
        try:
            response = requests.get(test_url, timeout=10)
            if response.status_code == 200:
                found_vulnerabilities.append({
                    "vuln": vuln_name,
                    "payload": payload,
                    "url": test_url
                })
                logging.info(f"Vulnerability detected: {vuln_name} - Payload: {payload} at {test_url}")
        except requests.exceptions.RequestException as e:
            logging.error(f"Error with payload {payload} on {url}: {str(e)}")
            continue
    return found_vulnerabilities


# Scan for API vulnerabilities (Authentication, API Keys, CORS, etc.)
def scan_api_vulnerabilities(url):
    vulnerabilities_found = []
    for vuln in advanced_vulnerabilities:
        if vuln['name'] == 'API Key Exposure':
            print(f"Scanning for {vuln['name']}...")
            found_vulns = scan_for_vulnerabilities(url, vuln['payloads'], vuln["name"])
            if found_vulns:
                vulnerabilities_found.extend(found_vulns)
    return vulnerabilities_found


# Function to evaluate HTTPS configuration
def evaluate_https(url):
    parsed_url = urlparse(url)
    try:
        host = parsed_url.netloc
        context = ssl.create_default_context()
        connection = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=host)
        connection.connect((host, 443))
        certificate = connection.getpeercert()
        ssl_info = ssl.cert_time_to_seconds(certificate['notAfter'])
        expiration = ssl_info - time.time()
        connection.close()
        if expiration < 0:
            print("SSL certificate is expired.")
        else:
            print(f"SSL certificate is valid for {expiration / 86400:.2f} more days.")
    except Exception as e:
        logging.error(f"Error evaluating HTTPS for {url}: {str(e)}")
    return "HTTPS evaluation complete."


# Detect vulnerabilities using SSL/TLS misconfigurations
def detect_tls_issues(url):
    print("Checking for weak cipher suites and TLS vulnerabilities...")
    return "Weak Cipher Suites or TLS misconfigurations detected."


# Function to generate reports in JSON and CSV formats
import csv


def generate_reports(vulnerabilities):
    # Define the CSV file name and field names (columns)
    fieldnames = ['Vulnerability', 'Severity', 'Description', 'CVE ID', 'Mitigation', 'URL']

    # Open the CSV file in write mode and set up the CSV writer
    with open('vulnerability_report.csv', mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)

        # Write the header to the CSV file
        writer.writeheader()

        # Write each vulnerability information as a dictionary to the CSV
        for vuln in vulnerabilities:
            # Make sure each vuln is a dictionary with proper fields
            if isinstance(vuln, dict):
                writer.writerow(vuln)
            else:
                # If vuln is not a dictionary, handle it (optional: log it, skip, or default)
                print(f"Skipping invalid vuln entry: {vuln}")


# Function to scan websites for both static and dynamic vulnerabilities
def scan_website(url):
    vulnerabilities_found = []

    # Scan static vulnerabilities
    static_vulns = []
    for vuln in advanced_vulnerabilities:
        static_vulns.extend(scan_for_vulnerabilities(url, vuln['payloads'], vuln['name']))
    vulnerabilities_found.extend(static_vulns)

    # Scan for API vulnerabilities
    api_vulns = scan_api_vulnerabilities(url)
    vulnerabilities_found.extend(api_vulns)

    # Evaluate HTTPS and TLS issues
    tls_vulns = detect_tls_issues(url)
    vulnerabilities_found.append(tls_vulns)

    # Generate reports based on found vulnerabilities
    generate_reports(vulnerabilities_found)

    return vulnerabilities_found


if __name__ == "__main__":
    target_url = input("Enter the target URL: ")

    vulnerabilities_found = scan_website(target_url)

    print("\nScanning completed. Found vulnerabilities:")
    for vuln in vulnerabilities_found:
        if isinstance(vuln, dict):
            print(f"Vulnerability: {vuln['vuln_name']}, CVE: {vuln['cve']}, Severity: {vuln['severity']}")
        else:
            print(f"Invalid data entry: {vuln}")