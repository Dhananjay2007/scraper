import requests
import csv
import datetime
from bs4 import BeautifulSoup

def fetch_vulnerabilities(product_title):
    # Define the API endpoint and parameters
    url = 'https://sec.cloudapps.cisco.com/security/center/publicationService.x'
    params = {
        'title': product_title,  # Use user-provided product title
        'limit': 100,
        'offset': 0,
        'sort': '-day_sir'
    }

    # Send the GET request
    try:
        response = requests.get(url, params=params, timeout=10)  # Added timeout for better control
        response.raise_for_status()  # Raise HTTPError for bad responses
    except requests.exceptions.RequestException as e:
        print(f"An error occurred while making the request: {e}")
        return None

    # Check if the request was successful
    try:
        data = response.json()
        if not data:
            print(f"No vulnerability records found for the product: {product_title}")
            return []
        else:
            print(f"Fetched {len(data)} vulnerability records for the product: {product_title}")
            return data
    except ValueError:
        print("Failed to parse JSON response. Please check the API response format.")
        return None

def scrape_affected_products(url):
    # Send a GET request to the vulnerability URL
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"An error occurred while accessing the advisory page: {e}")
        return []

    # Parse the HTML content
    soup = BeautifulSoup(response.text, 'html.parser')

    # Extract the affected products from the relevant section
    affected_products = []
    vulnerable_section = soup.find('div', {'id': 'vulnerableproducts'})
    if vulnerable_section:
        product_list = vulnerable_section.find('ul')
        if product_list:
            for li in product_list.find_all('li'):
                affected_products.append(li.get_text(strip=True))

    return affected_products

def save_to_csv(data, product_title):
    # Define the CSV filename with timestamp to prevent overwriting
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_product_title = "_".join(product_title.split()).replace("/", "_")
    filename = f"vulnerabilities_{safe_product_title}_{timestamp}.csv"

    # Define the CSV headers based on the provided JSON structure
    headers = [
        'Identifier', 'Title', 'First Published', 'Last Published',
        'Severity', 'CVE', 'CWE', 'Summary', 'Affected Products', 'URL'
    ]

    try:
        with open(filename, mode='w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=headers)

            # Write the header
            writer.writeheader()

            # Write each vulnerability as a row in the CSV
            for record in data:
                affected_products = scrape_affected_products(record.get('url', ''))
                writer.writerow({
                    'Identifier': record.get('identifier', 'N/A'),
                    'Title': record.get('title', 'N/A'),
                    'First Published': record.get('firstPublished', 'N/A'),
                    'Last Published': record.get('lastPublished', 'N/A'),
                    'Severity': record.get('severity', 'N/A'),
                    'CVE': record.get('cve', 'N/A'),
                    'CWE': record.get('cwe', 'N/A'),
                    'Summary': record.get('summary', 'N/A'),
                    'Affected Products': "; ".join(affected_products) if affected_products else 'N/A',
                    'URL': record.get('url', 'N/A')
                })

        print(f"Data successfully written to {filename}")

    except IOError as e:
        print(f"IO error occurred while writing to CSV: {e}")
    except Exception as e:
        print(f"An unexpected error occurred while writing to CSV: {e}")

def main():
    # Get product title from the user
    product_title = input("Enter the product name (title) for which you want to fetch vulnerabilities: ").strip()

    if not product_title:
        print("Product name cannot be empty. Please try again.")
        return

    # Fetch vulnerability data
    vulnerabilities = fetch_vulnerabilities(product_title)

    # If data is fetched successfully and is not empty, save it to CSV
    if vulnerabilities:
        save_to_csv(vulnerabilities, product_title)
    elif vulnerabilities is None:
        print("An error occurred during data fetching. CSV file was not created.")

if __name__ == "__main__":
    main()
