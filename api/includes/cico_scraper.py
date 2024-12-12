# fetch_vulnerabilities_module.py
import requests
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
        raise RuntimeError(f"An error occurred while making the request: {e}")

    # Check if the request was successful
    try:
        data = response.json()
        if not data:
            return []
        return data
    except ValueError:
        raise ValueError("Failed to parse JSON response. Please check the API response format.")

def scrape_affected_products(url):
    # Send a GET request to the vulnerability URL
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"An error occurred while accessing the advisory page: {e}")

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