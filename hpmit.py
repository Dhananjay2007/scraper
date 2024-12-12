import requests
import csv
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.options import Options
import time

# API and Selenium setup
BASE_API_URL = "https://support.hp.com/wcc-services/kaas/us-en/security-bulletins"
REDIRECT_URL_KEY = "redirectURL"
DEFAULT_TIMEOUT = 15
OUTPUT_COLUMNS = ["redirectURL", "title", "hpID", "severity", "cve", "creationDate", "bulletinUpdateDate", "Mitigation", "Severity Details"]


def initialize_webdriver():
    """
    Initialize Selenium WebDriver with headless Chrome options.
    """
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--window-size=1920,1080")
    chrome_options.add_argument(
        "user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36"
    )
    service = Service(ChromeDriverManager().install())
    driver_instance = webdriver.Chrome(service=service, options=chrome_options)
    return driver_instance


def fetch_api_data(product_name):
    """
    Fetch data from the API using the user-provided product name.
    """
    print(f"Fetching data for product: {product_name}")
    params = {
        "query": product_name,
        "sortBy": "bulletinUpdateDate",
        "sortOrder": "desc",
        "authState": "anonymous",
        "template": "Document_SC",
    }
    headers = {"Content-Type": "application/json", "User-Agent": "Python Script"}
    try:
        response = requests.get(BASE_API_URL, params=params, headers=headers, timeout=DEFAULT_TIMEOUT)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching data from API: {e}")
        return None


def fetch_cve_data_with_selenium(driver_instance, url):
    """
    Use Selenium to fetch CVE data from a redirect URL.
    """
    try:
        print(f"Fetching page with Selenium: {url}")
        driver_instance.get(url)

        # Wait for the table to load
        WebDriverWait(driver_instance, 20).until(
            EC.presence_of_element_located((By.TAG_NAME, "table"))
        )

        # Extract the page source and parse with BeautifulSoup
        soup = BeautifulSoup(driver_instance.page_source, "html.parser")

        # Parse CVE table
        cve_data = []
        tables = soup.find_all("table")
        for table in tables:
            rows = table.find_all("tr")
            for row in rows[1:]:  # Skip header row
                cells = row.find_all("td")
                if len(cells) >= 2:  # Ensure enough columns exist
                    cve_id = cells[0].text.strip()
                    severity = cells[1].text.strip()
                    cve_data.append({"CVE ID": cve_id, "Severity": severity})
        return cve_data
    except Exception as e:
        print(f"Error fetching data with Selenium: {e}")
        return []
    finally:
        time.sleep(5)  # Delay between requests


class MitigationExtractor:
    """
    Class to extract mitigation strategies for a given product.
    """
    def __init__(self, driver_instance):
        self.driver = driver_instance

    def extract_mitigation(self, url):
        """
        Extract mitigation strategies from the given redirect URL.
        """
        try:
            print(f"Extracting mitigation strategies from: {url}")
            self.driver.get(url)

            # Wait for the specific mitigation content to load
            WebDriverWait(self.driver, 20).until(
                EC.presence_of_element_located((By.CLASS_NAME, "explanation"))
            )

            # Parse the page source
            soup = BeautifulSoup(self.driver.page_source, "html.parser")

            # Locate the div containing mitigation details
            mitigation_div = soup.find("div", class_="explanation")
            if not mitigation_div:
                return ["No specific mitigations found."]

            # Extract all <p> tags inside the div
            mitigations = []
            for p in mitigation_div.find_all("p"):
                text_content = p.get_text(strip=True)
                if text_content:  # Avoid empty strings
                    mitigations.append(text_content)

            # Add any links inside the mitigation content
            for link in mitigation_div.find_all("a", href=True):
                link_text = f"Link: {link.get('href')}"
                mitigations.append(link_text)

            return mitigations if mitigations else ["No specific mitigations found."]
        except Exception as e:
            print(f"Error extracting mitigation strategies: {e}")
            return ["Error extracting mitigation strategies."]


def construct_full_url(partial_url):
    """
    Ensures the URL is complete with the correct scheme and domain.
    """
    if not partial_url.startswith("http"):
        return f"https://support.hp.com/{partial_url.lstrip('/')}"
    return partial_url


def save_to_csv(data, output_file):
    """
    Save the extracted data to a CSV file.
    """
    try:
        with open(output_file, mode="w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=OUTPUT_COLUMNS)
            writer.writeheader()
            for entry in data:
                writer.writerow(entry)
        print(f"Data saved to {output_file}")
    except IOError as e:
        print(f"Error writing to CSV file: {e}")


def main():
    """
    Main script logic.
    """
    product_name = input("Enter the product name or keyword to search for vulnerabilities: ").strip()
    if not product_name:
        print("Product name cannot be empty. Exiting.")
        return

    output_file = f"security2_bulletins_{product_name.replace(' ', '_')}.csv"

    # Fetch API data
    api_data = fetch_api_data(product_name)
    if not api_data or "data" not in api_data:
        print("No data retrieved from API.")
        return

    # Initialize WebDriver and MitigationExtractor
    driver_instance = initialize_webdriver()
    mitigation_extractor = MitigationExtractor(driver_instance)

    # Process each bulletin for CVE details and mitigations
    json_data = []
    for bulletin in api_data["data"]:
        redirect_url = construct_full_url(bulletin.get(REDIRECT_URL_KEY, ""))
        bulletin["redirectURL"] = redirect_url  # Ensure complete redirect URL

        # Handle empty CVE list by scraping
        if not bulletin.get("cve"):
            print(f"CVE list empty for: {bulletin['title']}. Fetching data...")
            cve_details = fetch_cve_data_with_selenium(driver_instance, redirect_url)
            bulletin["cve"] = [cve["CVE ID"] for cve in cve_details]

        # Extract mitigation strategies
        bulletin["Mitigation"] = mitigation_extractor.extract_mitigation(redirect_url)

        # Add severity details placeholder
        bulletin["Severity Details"] = []

        json_data.append({key: bulletin.get(key, "") for key in OUTPUT_COLUMNS})

    # Save data in CSV format
    save_to_csv(json_data, output_file)

    # Quit WebDriver
    driver_instance.quit()


if __name__ == "__main__":
    main()
