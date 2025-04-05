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
from selenium.common.exceptions import WebDriverException
import time

# API and Selenium setup
BASE_API_URL = "https://support.hp.com/wcc-services/kaas/us-en/security-bulletins"
REDIRECT_URL_KEY = "redirectURL"
DEFAULT_TIMEOUT = 15
OUTPUT_COLUMNS = ["Product Name", "CVE ID", "Severity", "Vendors"]


from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager

def initialize_webdriver():
    """
    Initialize Selenium WebDriver with headless Chrome options.
    """
    try:
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--window-size=1920,1080")
        chrome_options.add_argument("--disable-blink-features=AutomationControlled")
        chrome_options.add_argument("--enable-javascript")
        chrome_options.add_argument(
            "user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36"
        )

        # Initialize the driver
        service = Service(ChromeDriverManager().install())
        driver_instance = webdriver.Chrome(service=service, options=chrome_options)
        return driver_instance
    except Exception as e:
        print(f"Error initializing WebDriver: {e}")
        raise


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
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Python Script",
    }
    try:
        response = requests.get(BASE_API_URL, params=params, headers=headers, timeout=DEFAULT_TIMEOUT)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching data from API: {e}")
        return None


def fetch_cve_data_with_selenium(driver_instance, url):
    """
    Use Selenium to fetch CVE and severity data from a redirect URL.
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
                if len(cells) >= 4:
                    cve_id = cells[0].text.strip()
                    severity = cells[2].text.strip()
                    vendors = cells[4].text.strip()
                    cve_data.append({"CVE ID": cve_id, "Severity": severity, "Vendors": vendors})
        return cve_data
    except Exception as e:
        print(f"Error fetching data with Selenium: {e}")
        return []
    finally:
        time.sleep(5)  # Delay between requests


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

    output_file = f"security_bulletins_{product_name.replace(' ', '_')}.csv"

    # Initialize WebDriver
    driver_instance = initialize_webdriver()

    # Fetch API data
    api_data = fetch_api_data(product_name)
    if not api_data or "data" not in api_data:
        print("No data retrieved from API.")
        return

    # Process each bulletin and fetch CVE data
    extracted_data = []
    for bulletin in api_data["data"]:
        title = bulletin.get("title", "Unknown")
        redirect_url = bulletin.get(REDIRECT_URL_KEY)
        if not redirect_url:
            print(f"No redirect URL found for: {title}")
            continue

        # Ensure redirect URL is complete
        full_url = construct_full_url(redirect_url)

        print(f"Processing: {title} | URL: {full_url}")
        cve_details = fetch_cve_data_with_selenium(driver_instance, full_url)
        for detail in cve_details:
            extracted_data.append({
                "Product Name": title,
                "CVE ID": detail["CVE ID"],
                "Severity": detail["Severity"],
                "Vendors": detail["Vendors"]
            })

    # Save data to CSV
    if extracted_data:
        save_to_csv(extracted_data, output_file)
    else:
        print("No CVE data extracted.")

    # Quit Selenium WebDriver
    driver_instance.quit()


if __name__ == "__main__":
    main()
