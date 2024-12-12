import requests
import sys
import json
from bs4 import BeautifulSoup

def fetch_vulnerabilities(product_title):
    # Define the API endpoint and parameters
    url = 'https://sec.cloudapps.cisco.com/security/center/publicationService.x'
    params = {
        'title': product_title,  # Use user-provided product title
        'limit': 10,
        'offset': 0,
        'sort': '-day_sir'
    }

    # Send the GET request
    try:
        response = requests.get(url, params=params, timeout=10)  # Added timeout for better control
        response.raise_for_status()  # Raise HTTPError for bad responses
    except requests.exceptions.RequestException as e:
        print(f"An error occurred while making the request: {e}", file=sys.stderr)
        return None

    # Check if the request was successful
    try:
        data = response.json()
        if not data:
            print(f"No vulnerability records found for the product: {product_title}", file=sys.stderr)
            return []
        else:
            print(f"Fetched {len(data)} vulnerability records for the product: {product_title}", file=sys.stderr)
            return data
    except ValueError:
        print("Failed to parse JSON response. Please check the API response format.", file=sys.stderr)
        return None

def scrape_affected_products(url):
    # Send a GET request to the vulnerability URL
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"An error occurred while accessing the advisory page: {e}", file=sys.stderr)
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

def main():
    # Get product title from command-line arguments
    if len(sys.argv) < 2:
        print("Usage: python script.py <product_title>", file=sys.stderr)
        sys.exit(1)

    product_title = " ".join(sys.argv[1:]).strip()

    # Fetch vulnerability data
    vulnerabilities = fetch_vulnerabilities(product_title)

    # If data is fetched successfully, print it as JSON
    if vulnerabilities:
        output = []
        for record in vulnerabilities:
            affected_products = scrape_affected_products(record.get('url', ''))
            output.append({
                'Identifier': record.get('identifier', 'N/A'),
                'Title': record.get('title', 'N/A'),
                'First Published': record.get('firstPublished', 'N/A'),
                'Last Published': record.get('lastPublished', 'N/A'),
                'Severity': record.get('severity', 'N/A'),
                'CVE': record.get('cve', 'N/A'),
                'CWE': record.get('cwe', 'N/A'),
                'Summary': record.get('summary', 'N/A'),
                'Affected Products': affected_products if affected_products else ['N/A'],
                'URL': record.get('url', 'N/A')
            })

        # Print the output as JSON
        print(json.dumps(output, indent=4))
    elif vulnerabilities is None:
        print("An error occurred during data fetching. No output generated.", file=sys.stderr)

if __name__ == "__main__":
    main()
