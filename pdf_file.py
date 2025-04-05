import os
import re
import requests
import pdfplumber
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from webdriver_manager.chrome import ChromeDriverManager
import pandas as pd

def extract_vulnerability_data_from_pdf(pdf_path):
    structured_data = []
    with pdfplumber.open(pdf_path) as pdf:
        for page in pdf.pages:
            print(f"Processing page {page.page_number}...")
            table = page.extract_table()
            if table:
                print(f"Extracted table from page {page.page_number}: {table}")
                structured_data.extend(table)
            else:
                text = page.extract_text()
                if text:
                    print(f"Extracted text from page {page.page_number}: {text}")
                    structured_data.append(text)
    return structured_data


def parse_data_to_structured_format(data):
    structured_records = []
    current_advisory = {}
    parsing_products = False
    parsing_vulnerability = False

    for item in data:
        if isinstance(item, str):
            # Check for key sections
            if "Affected Products" in item:
                parsing_products = True
                parsing_vulnerability = False
                continue
            elif "Vulnerability" in item:
                parsing_vulnerability = True
                parsing_products = False
                continue
            elif "CVSS" in item or "Severity" in item:
                parsing_vulnerability = False
                parsing_products = False

            # Extract metadata
            if "Advisory ID" in item:
                current_advisory["Advisory ID"] = item.split(":")[1].strip() if ":" in item else None
            elif "Published on" in item:
                current_advisory["Published Date"] = item.split("on")[1].strip() if "on" in item else None
            elif "Last updated" in item:
                current_advisory["Last Updated"] = item.split("on")[1].strip() if "on" in item else None

        # Handle tables
        elif isinstance(item, list):
            if parsing_products:
                if item and item[0] and ("CENTUM" in item[0] or "Exaopc" in item[0]):  # Example product filters
                    product = {"Product Name": item[0], "Version": item[1] if len(item) > 1 else None}
                    current_advisory.setdefault("Affected Products", []).append(product)
            elif parsing_vulnerability:
                if item and item[0] and "Access Vector" in item[0]:  # Example vulnerability data
                    current_advisory["CVSS Details"] = {key: value for key, value in zip(item[::2], item[1::2])}

        # Save advisory when complete
        if current_advisory and "Advisory ID" in current_advisory:
            structured_records.append(current_advisory)
            current_advisory = {}

    print(f"Structured Records: {structured_records}")
    return structured_records




def scrape_yokogawa_advisories():
    # Setup Chrome WebDriver
    options = webdriver.ChromeOptions()
    options.add_argument("--headless")
    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)

    try:
        # Navigate to the advisory page
        url = "https://www.yokogawa.com/in/library/resources/white-papers/yokogawa-security-advisory-report-list/"
        driver.get(url)

        # Wait for the page to load
        driver.implicitly_wait(5)

        # Parse the page content
        soup = BeautifulSoup(driver.page_source, 'html.parser')

        # Find all tables with advisory links
        data_tables = soup.find_all('table', class_='stripe table1')

        all_advisories = []
        for data_table in data_tables:
            rows = data_table.find_all('tr')
            for row in rows:
                cells = row.find_all('td')
                for cell in cells:
                    link = cell.find('a')
                    if link and 'href' in link.attrs:
                        href = link['href']
                        pdf_url = f"https:{href}"

                        # Download the PDF
                        pdf_response = requests.get(pdf_url)
                        pdf_path = "temp.pdf"
                        with open(pdf_path, "wb") as f:
                            f.write(pdf_response.content)

                        # Extract and parse data
                        raw_data = extract_vulnerability_data_from_pdf(pdf_path)
                        structured_data = parse_data_to_structured_format(raw_data)

                        # Add additional metadata
                        for record in structured_data:
                            record["Website"] = "Yokogawa"
                            record["URL"] = pdf_url

                        all_advisories.extend(structured_data)

                        # Clean up temporary file
                        os.remove(pdf_path)

        # Save to CSV
        def save_to_csv(structured_records, filename="yokogawa_advisories.csv"):
            if structured_records:
                df = pd.DataFrame(structured_records)
                print(f"Data to be saved:\n{df}")
                df.to_csv(filename, index=False)
                print(f"Advisory data saved to {filename}")
            else:
                print("No structured records found. Nothing to save.")

    finally:
        driver.quit()

# Run the scraper
scrape_yokogawa_advisories()
