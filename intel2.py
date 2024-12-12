import time
import pandas as pd
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager

# Configuration for WebDriver
options = webdriver.ChromeOptions()
# options.add_argument("--headless")
options.add_argument("--disable-gpu")
options.add_argument("--no-sandbox")

def scrape_intel_advisories():
    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
    main_url = "https://www.intel.com/content/www/us/en/security-center/default.html"

    try:
        # Step 1: Scrape the main advisories page
        driver.get(main_url)
        time.sleep(5)  # Wait for the page to load
        main_page_html = driver.page_source
        soup = BeautifulSoup(main_page_html, 'html.parser')

        advisory_rows = soup.find_all('tr', class_='data')
        main_data = []

        for row in advisory_rows:
            cols = row.find_all('td')
            if len(cols) >= 4:
                advisory_url = row.find('a')['href'] if row.find('a') else None
                base_url = "https://www.intel.com"
                advisory_url = base_url + advisory_url if advisory_url and advisory_url.startswith('/') else advisory_url

                main_data.append({
                    "Advisory": cols[0].text.strip(),
                    "Advisory ID": cols[1].text.strip(),
                    "Published Date": cols[2].text.strip(),
                    "Updated Date": cols[3].text.strip(),
                    "URL": advisory_url
                })

        # Convert to DataFrame
        main_df = pd.DataFrame(main_data)

        # Step 2: Scrape details from individual advisory pages
        detailed_data = []
        for advisory in main_data:
            if advisory["URL"]:
                driver.get(advisory["URL"])
                WebDriverWait(driver, 10).until(
                    EC.presence_of_all_elements_located((By.TAG_NAME, "h3"))
                )

                advisory_html = driver.page_source
                advisory_soup = BeautifulSoup(advisory_html, 'html.parser')

                advisory_id = advisory_soup.find('title').text.strip()
                h3_tags = advisory_soup.find_all('h3')
                advisory_details = {
                    "Advisory ID": advisory_id,
                    "CVE IDs": [],
                    "Description": None,
                    "CVSS Base Score 3.1": None,
                    "CVSS Vector 3.1": None,
                    "CVSS Base Score 4.0": None,
                    "CVSS Vector 4.0": None
                }

                for h3_tag in h3_tags:
                    if h3_tag.text.strip() == "Vulnerability Details:":
                        for sibling in h3_tag.find_next_siblings():
                            if sibling.name == "h3":
                                break
                            if sibling.name == "p":
                                try:
                                    key, value = sibling.text.split(':', 1)
                                    key, value = key.strip(), value.strip()
                                    if key == "CVEID":
                                        advisory_details["CVE IDs"].append(value)
                                    elif key == "Description":
                                        advisory_details["Description"] = value
                                    elif key == "CVSS Base Score 3.1":
                                        advisory_details["CVSS Base Score 3.1"] = value
                                    elif key == "CVSS Vector 3.1":
                                        advisory_details["CVSS Vector 3.1"] = value
                                    elif key == "CVSS Base Score 4.0":
                                        advisory_details["CVSS Base Score 4.0"] = value
                                    elif key == "CVSS Vector 4.0":
                                        advisory_details["CVSS Vector 4.0"] = value
                                except ValueError:
                                    continue
                    if h3_tag.text.strip() == "Affected Products:":
                        affected_products = []
                        for sibling in h3_tag.find_next_siblings():
                            if sibling.name == "h3":
                                break
                            affected_products.append(sibling.text.strip())
                        advisory_details["Affected Products"] = " ".join(affected_products)

                        # Extract "Recommendation" section
                    if h3_tag.text.strip() == "Recommendation:":
                        recommendation = []
                        for sibling in h3_tag.find_next_siblings():
                            if sibling.name == "h3":
                                break
                            recommendation.append(sibling.text.strip())
                        advisory_details["Recommendation"] = " ".join(recommendation)

                detailed_data.append(advisory_details)

        # Convert to DataFrame
        detailed_df = pd.DataFrame(detailed_data)

        # Merge main and detailed data
        final_df = main_df.merge(detailed_df, on="Advisory ID", how="left")


        # Save to CSV
        final_df.to_csv("intel_advisories_combined.csv", index=False)
        print("Data saved to intel_advisories_combined.csv")


    finally:
        driver.quit()

# Run the scraper
scrape_intel_advisories()
