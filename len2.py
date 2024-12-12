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
# options.add_argument("--headless")  # Uncomment to run in headless mode
options.add_argument("--disable-gpu")
options.add_argument("--no-sandbox")

def scrape_lenovo_advisories():
    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
    main_url = "https://support.lenovo.com/us/en/product_security/ps500001-lenovo-product-security-advisories"

    try:
        # Step 1: Scrape the main advisories page
        driver.get(main_url)
        time.sleep(5)  # Wait for the page to load
        main_page_html = driver.page_source
        soup = BeautifulSoup(main_page_html, 'html.parser')

        advisory_rows = soup.find_all('tr')
        main_data = []

        for row in advisory_rows:
            cols = row.find_all('td')
            if len(cols) >= 3:
                advisory_url = row.find('a')['href'] if row.find('a') else None
                base_url = "https://support.lenovo.com"
                advisory_url = base_url + advisory_url if advisory_url and advisory_url.startswith('/') else advisory_url

                main_data.append({
                    "Advisory": cols[0].text.strip(),
                    "Published Date": cols[1].text.strip(),
                    "Severity": cols[2].text.strip(),
                    "URL": advisory_url
                })

        # Convert to DataFrame
        main_df = pd.DataFrame(main_data)
        print("Main DataFrame columns:", main_df.columns)

        # Rename "Advisory" to "Advisory ID" to match detailed_df
        main_df.rename(columns={"Advisory": "Advisory ID"}, inplace=True)

        # Step 2: Scrape details from individual advisory pages
        detailed_data = []
        for advisory in main_data:
            if advisory["URL"]:
                driver.get(advisory["URL"])
                WebDriverWait(driver, 10).until(
                    EC.presence_of_all_elements_located((By.TAG_NAME, "p"))
                )

                advisory_html = driver.page_source
                advisory_soup = BeautifulSoup(advisory_html, 'html.parser')

                # Locate Product Impact heading
                product_impact_tag = advisory_soup.find('p', string=lambda x: x and "Product Impact" in x)
                if not product_impact_tag:
                    continue

                # Extract all necessary <p> siblings until another section or end
                advisory_details = {
                    "Advisory ID": advisory["Advisory"],
                    "Product Impact": None,
                    "Description": None,
                    "CVE IDs": [],
                }

                for sibling in product_impact_tag.find_next_siblings():
                    if sibling.name != "p":
                        break

                    # Extract text details from <p> tags
                    text = sibling.get_text(strip=True)
                    if "Product Impact" in text:
                        advisory_details["Product Impact"] = text
                    elif "CVE-" in text:
                        advisory_details["CVE IDs"].append(text)
                    else:
                        advisory_details["Description"] = advisory_details["Description"] + "\n" + text if advisory_details["Description"] else text

                detailed_data.append(advisory_details)

        # Convert to DataFrame
        detailed_df = pd.DataFrame(detailed_data)
        print("Detailed DataFrame columns:", detailed_df.columns)

        # Check for empty or missing 'Advisory ID' in detailed_df
        if detailed_df.empty or 'Advisory ID' not in detailed_df.columns:
            print("Detailed DataFrame is empty or missing 'Advisory ID'. Skipping merge.")
            detailed_df = pd.DataFrame(columns=["Advisory ID", "Product Impact", "Description", "CVE IDs"])

        # Merge safely
        final_df = main_df.merge(detailed_df, on="Advisory ID", how="left")

        # Save to CSV
        final_df.to_csv("lenovo_advisories_combined.csv", index=False)
        print("Data saved to lenovo_advisories_combined.csv")

    finally:
        driver.quit()

# Run the scraper
scrape_lenovo_advisories()
