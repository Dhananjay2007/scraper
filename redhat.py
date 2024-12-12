import requests
import csv
import os
import datetime
from bs4 import BeautifulSoup

def get_vulnerability_data(product_name, api_token=None):
    """
    Fetches vulnerability data from Red Hat's API based on the provided product name.

    Args:
        product_name (str): The name of the Red Hat product.
        api_token (str, optional): API token for authentication. Defaults to None.

    Returns:
        list: A list of vulnerability records (dictionaries) if successful.
        None: If an error occurs.
    """
    # Base URL
    base_url = "https://access.redhat.com/hydra/rest/search/kcs"

    # Query parameters
    params = {
        'q': product_name,
        'start': 0,
        'hl': 'true',
        'hl.fl': 'lab_description',
        'hl.simple.pre': '<mark>',
        'hl.simple.post': '</mark>',
        'fq': 'portal_advisory_type:("Security Advisory") AND documentKind:("Errata")',
        'facet': 'true',
        'facet.mincount': 1,
        'rows': 100,  # Increased to fetch up to 100 results; adjust as needed
        'fl': 'id,portal_severity,portal_product_names,portal_CVE,portal_publication_date,portal_synopsis,view_uri,allTitle',
        'sort': 'portal_publication_date desc',
        'p': 1,
        'facet.field': ['portal_severity', 'portal_advisory_type'],
        'fq': 'portal_product_filter:*|*'
    }

    # Headers with optional authentication
    headers = {
        'Accept': 'application/json'
    }

    if api_token:
        headers['Authorization'] = f'Bearer {api_token}'

    try:
        response = requests.get(base_url, params=params, headers=headers, timeout=10)
        response.raise_for_status()  # Raise an error for bad status codes

        data = response.json()

        # Check if the response contains vulnerabilities
        if 'response' in data and 'docs' in data['response']:
            vulnerabilities = data['response']['docs']
            if vulnerabilities:
                print(f"Fetched {len(vulnerabilities)} vulnerability records for the product: {product_name}")
                return vulnerabilities
            else:
                print("No vulnerabilities found for the specified product.")
                return []
        else:
            print("Unexpected response format.")
            return []

    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err} - {response.text}")
    except requests.exceptions.RequestException as req_err:
        print(f"Request exception occurred: {req_err}")
    except Exception as err:
        print(f"An error occurred: {err}")

    return []

def extract_security_bulletin_id(vuln_record):
    """
    Extracts the security bulletin ID from a vulnerability record.

    Args:
        vuln_record (dict): A single vulnerability record.

    Returns:
        str: The security bulletin ID (e.g., 'RHSA-2024:10779') if found.
        None: If not found.
    """
    # Assuming the 'id' field contains the security bulletin ID
    return vuln_record.get('id', None)

def scrape_mitigation_strategies(security_bulletin_id):
    """
    Scrapes mitigation strategies from Red Hat's security bulletin page based on the bulletin ID.

    Args:
        security_bulletin_id (str): The security bulletin ID (e.g., 'RHSA-2024:10779').

    Returns:
        dict: A dictionary containing mitigation strategies extracted from the page.
              Keys include 'Solution' and 'Description'.
        None: If an error occurs during scraping.
    """
    # Construct the URL
    base_url = "https://access.redhat.com/errata/"
    url = f"{base_url}{security_bulletin_id}"

    headers = {
        'User-Agent': 'Mozilla/5.0 (compatible; VulnerabilityScraper/1.0; +https://yourdomain.com/)',
        'Accept-Language': 'en-US,en;q=0.9',
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred while fetching {url}: {http_err} - {response.text}")
        return None
    except requests.exceptions.RequestException as req_err:
        print(f"Request exception occurred while fetching {url}: {req_err}")
        return None
    except Exception as err:
        print(f"An unexpected error occurred while fetching {url}: {err}")
        return None

    # Parse the HTML content
    soup = BeautifulSoup(response.text, 'html.parser')

    mitigation_data = {}

    # Extract the 'Solution' section
    solution_div = soup.find('div', id='solution')
    if solution_div:
        solution_text = solution_div.get_text(separator=' ', strip=True)
        mitigation_data['Solution'] = solution_text
    else:
        mitigation_data['Solution'] = 'N/A'

    # Extract the 'Description' section
    description_div = soup.find('div', id='description')
    if description_div:
        description_text = description_div.get_text(separator=' ', strip=True)
        mitigation_data['Description'] = description_text
    else:
        mitigation_data['Description'] = 'N/A'

    return mitigation_data

def write_to_csv(vulnerabilities, filename):
    """
    Saves the collected vulnerability and mitigation data to a CSV file.

    Args:
        vulnerabilities (list): A list of vulnerability records with mitigation strategies.
        filename (str): The desired name for the CSV file.
    """
    # Define the CSV headers
    headers = [
        'ID',
        'Severity',
        'CVE',
        'Publication Date',
        'Synopsis',
        'View URI',
        'Title',
        'Solution',
        'Description'
    ]

    try:
        with open(filename, mode='w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=headers)

            # Write the header
            writer.writeheader()

            # Write each vulnerability as a row in the CSV
            for vuln in vulnerabilities:
                writer.writerow({
                    'ID': vuln.get('id', 'N/A'),
                    'Severity': vuln.get('portal_severity', 'N/A'),
                    'CVE': vuln.get('portal_CVE', 'N/A'),
                    'Publication Date': vuln.get('portal_publication_date', 'N/A'),
                    'Synopsis': vuln.get('portal_synopsis', 'N/A'),
                    'View URI': vuln.get('view_uri', 'N/A'),
                    'Title': vuln.get('allTitle', 'N/A'),
                    'Description': vuln.get('Description', 'N/A'),
                    'Solution': vuln.get('Solution', 'N/A')
                })

        print(f"Data successfully written to {filename}")

    except IOError as e:
        print(f"IO error occurred while writing to CSV: {e}")
    except Exception as e:
        print(f"An unexpected error occurred while writing to CSV: {e}")

def main():
    """
    Main function to orchestrate fetching vulnerabilities, scraping mitigation strategies,
    and saving the data to a CSV file.
    """
    # Get product name from the user
    product_name = input("Enter the Red Hat product name: ").strip()

    if not product_name:
        print("Product name cannot be empty.")
        return

    # Prompt for API token (optional)
    use_token = input("Do you want to provide an API token? (y/n): ").strip().lower()
    api_token = None
    if use_token == 'y':
        api_token = input("Enter your Red Hat API token: ").strip()
        if not api_token:
            print("API token was not provided. Proceeding without authentication.")
            api_token = None

    # Fetch vulnerability data
    vulnerabilities = get_vulnerability_data(product_name, api_token)

    if vulnerabilities:
        # Iterate over each vulnerability and scrape mitigation strategies
        for vuln in vulnerabilities:
            security_bulletin_id = extract_security_bulletin_id(vuln)
            if security_bulletin_id:
                print(f"Scraping mitigation strategies for bulletin ID: {security_bulletin_id}")
                mitigation = scrape_mitigation_strategies(security_bulletin_id)
                if mitigation:
                    vuln.update(mitigation)
                else:
                    vuln['Solution'] = 'N/A'
                    vuln['Description'] = 'N/A'
            else:
                vuln['Solution'] = 'N/A'
                vuln['Description'] = 'N/A'

        # Define the CSV filename
        safe_product_name = "_".join(product_name.split()).replace("/", "_")
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"vulnerabilities_{safe_product_name}_{timestamp}.csv"

        # Write to CSV
        write_to_csv(vulnerabilities, filename)
    else:
        print("No data to write to CSV.")

if __name__ == "__main__":
    main()
