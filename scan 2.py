from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.action_chains import ActionChains
from bs4 import BeautifulSoup
import time
import re
import pandas as pd
import requests
from selenium.webdriver.chrome.options import Options

# Initialize WebDriver for dynamic content (use Chrome driver)
driver = webdriver.Chrome()


# Function to scrape individual vulnerability advisory page
def scrape_vulnerability_page(url):

    chrome_options = Options()
    driver.get(url)
    time.sleep(3)  # Wait for the page to load

    soup = BeautifulSoup(driver.page_source, "html.parser")

    # Regular expression for finding CVE IDs
    cve_pattern = r'CVE-\d{4}-\d{4,7}'

    vulnerabilities = []

    # Loop through paragraphs or divs that may contain vulnerability data
    for paragraph in soup.find_all(['p', 'div', 'li']):
        text = paragraph.get_text()

        # Look for CVE IDs in the text
        if re.search(cve_pattern, text):
            cve_id = re.search(cve_pattern, text).group(0)
            description = text.strip()
            severity = 'Critical/High'  # Placeholder, modify according to the text
            product = 'OEM Product'  # Placeholder, modify for real product name
            published_date = 'N/A'  # Placeholder, modify to extract published date
            mitigation = 'Check OEM advisory for mitigation'  # Placeholder

            # Append extracted vulnerability information
            vulnerabilities.append({
                'CVE_ID': cve_id,
                'Description': description,
                'Severity': severity,
                'Published Date': published_date,
                'Product': product,
                'Mitigation Steps': mitigation
            })

    return vulnerabilities


# Function to crawl the website and gather links to security advisories
def crawl_website_for_vulnerabilities(start_url):
    driver.get(start_url)
    time.sleep(3)

    # Get all the links on the website
    soup = BeautifulSoup(driver.page_source, "html.parser")
    links = soup.find_all('a', href=True)

    # Filter out links that might lead to security advisory pages
    advisory_links = []
    for link in links:
        if 'security' in link['href'] or 'advisory' in link['href']:
            advisory_links.append(link['href'])

    # Removing duplicates (if any)
    advisory_links = list(set(advisory_links))

    # List to store all scraped vulnerability data
    all_vulnerabilities = []

    # Iterate over all security/advisory links and scrape the data
    for link in advisory_links:
        full_url = start_url + link if link.startswith('/') else link
        print(f"Scraping: {full_url}")
        vulnerabilities = scrape_vulnerability_page(full_url)
        all_vulnerabilities.extend(vulnerabilities)

    return all_vulnerabilities


# Example start URL (replace with the actual URL of the OEM website)
start_url = "https://www.intel.com/"

# Scrape the website for vulnerabilities
vulnerability_data = crawl_website_for_vulnerabilities(start_url)

# Convert scraped data into a DataFrame for structured format
df = pd.DataFrame(vulnerability_data)

# Save the data into a CSV file for reporting purposes
df.to_csv('oem_vulnerabilities_report.csv', index=False)

# Print out the DataFrame to check the scraped data
print(df)

# Close the WebDriver after scraping is done
driver.quit()