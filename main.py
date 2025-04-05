import requests
from bs4 import BeautifulSoup
import re
from reportlab.pdfgen import canvas
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.common.exceptions import WebDriverException
import time

def crawl_website(base_url, max_depth=3):
    visited = set()
    to_visit = [(base_url, 0)]
    urls = []

    while to_visit:
        current_url, depth = to_visit.pop(0)
        if current_url in visited or depth > max_depth:
            continue

        try:
            response = requests.get(current_url, timeout=5)
            soup = BeautifulSoup(response.text, "html.parser")
            visited.add(current_url)
            urls.append(current_url)

            for link in soup.find_all("a", href=True):
                href = link['href']
                if href.startswith("/"):
                    href = base_url + href
                if base_url in href and href not in visited:
                    to_visit.append((href, depth + 1))
        except requests.RequestException:
            continue

    return urls



def crawl_dynamic_content(base_url, max_depth=2):
    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()))
    visited = set()
    to_visit = [(base_url, 0)]
    urls = []

    try:
        while to_visit:
            current_url, depth = to_visit.pop(0)
            if current_url in visited or depth > max_depth:
                continue

            try:
                print(f"Visiting: {current_url}")
                driver.get(current_url)
                time.sleep(2)  # Allow JavaScript to load
                visited.add(current_url)
                urls.append(current_url)

                # Extract links
                links = driver.find_elements(By.TAG_NAME, "a")
                for link in links:
                    href = link.get_attribute("href")
                    if href and base_url in href and href not in visited:
                        to_visit.append((href, depth + 1))
            except WebDriverException:
                continue
    finally:
        driver.quit()

    return list(set(urls))


def scan_vulnerabilities(url):
    vulnerabilities = []

    # Test for SQL Injection
    sql_payload = "' OR '1'='1"
    try:
        response = requests.get(url, params={"id": sql_payload}, timeout=5)
        if "error in your SQL syntax" in response.text.lower():
            vulnerabilities.append({
                "url": url,
                "type": "SQL Injection",
                "severity": "High",
                "description": "SQL Injection detected."
            })
    except requests.RequestException:
        pass

    # Test for XSS
    xss_payload = "<script>alert('XSS')</script>"
    try:
        response = requests.get(url, params={"q": xss_payload}, timeout=5)
        if xss_payload in response.text:
            vulnerabilities.append({
                "url": url,
                "type": "Cross-Site Scripting (XSS)",
                "severity": "Medium",
                "description": "Reflected XSS detected."
            })
    except requests.RequestException:
        pass

    return vulnerabilities


def scan_forms_with_vulnerabilities(url):
    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()))
    vulnerabilities = []

    try:
        driver.get(url)
        forms = driver.find_elements(By.TAG_NAME, "form")
        for form in forms:
            inputs = form.find_elements(By.TAG_NAME, "input")
            for input_element in inputs:
                if input_element.get_attribute("type") in ["text", "search"]:
                    # Inject XSS Payload
                    input_element.send_keys("<script>alert('XSS')</script>")
                    form.submit()
                    time.sleep(2)
                    if "<script>alert('XSS')</script>" in driver.page_source:
                        vulnerabilities.append({
                            "url": url,
                            "type": "Cross-Site Scripting (XSS)",
                            "severity": "Medium",
                            "description": "Reflected XSS detected in form submission."
                        })
    except WebDriverException as e:
        print(f"Error scanning forms on {url}: {e}")
    finally:
        driver.quit()

    return vulnerabilities


def generate_report(vulnerabilities, filename="report.pdf"):
    c = canvas.Canvas(filename)
    c.drawString(100, 750, "Vulnerability Report")
    y = 730
    for vuln in vulnerabilities:
        c.drawString(100, y, f"URL: {vuln['url']}, Type: {vuln['type']}, Severity: {vuln['severity']}")
        y -= 20
    c.save()
    return filename

if __name__ == "__main__":
    base_url = input("Enter the URL to scan: ").strip()
    urls = crawl_website(base_url)
    print("Starting dynamic crawling...")
    urls = crawl_dynamic_content(base_url)
    print(f"Discovered {len(urls)} URLs.")
    all_vulnerabilities = []

    for url in urls:
        vulns = scan_vulnerabilities(url)
        print(f"Scanning {url} for vulnerabilities...")
        vulns = scan_forms_with_vulnerabilities(url)
        if all_vulnerabilities:
            report_file = generate_report(all_vulnerabilities)
            print(f"Scan completed. Report saved to {report_file}.")
        else:
            print("No vulnerabilities detected.")




