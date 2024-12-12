import requests
import pandas as pd

# API Endpoints
VULNERABILITY_API_URL = "https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability"
AFFECTED_PRODUCT_API_URL = "https://api.msrc.microsoft.com/sug/v2.0/en-US/affectedProduct"

# Function to fetch vulnerabilities for a specific product
def fetch_vulnerabilities_by_product(product_name):
    try:
        # Define headers and query parameters
        headers = {"Accept": "application/json"}
        params = {
            "$orderBy": "releaseDate desc"
        }

        # Send the GET request
        response = requests.get(VULNERABILITY_API_URL, headers=headers, params=params)
        response.raise_for_status()

        # Parse the JSON response
        data = response.json()
        vulnerabilities = data.get("value", [])

        if not vulnerabilities:
            print("No vulnerabilities found.")
            return None

        # Filter vulnerabilities by product name
        product_name_lower = product_name.lower()
        filtered_vulnerabilities = [
            vuln for vuln in vulnerabilities
            if product_name_lower in vuln.get("tag", "").lower()
        ]

        if not filtered_vulnerabilities:
            print(f"No vulnerabilities found for the product: {product_name}")
            return None

        return filtered_vulnerabilities

    except requests.exceptions.RequestException as e:
        print(f"Error fetching vulnerabilities: {e}")
        return None

# Function to fetch product details for a given CVE
def fetch_affected_products(cve_id):
    try:
        # Define headers and query parameters
        headers = {"Accept": "application/json"}
        params = {
            "$orderBy": "releaseDate desc",
            "$filter": f"cveNumber eq '{cve_id}'"
        }

        # Send the GET request
        response = requests.get(AFFECTED_PRODUCT_API_URL, headers=headers, params=params)
        response.raise_for_status()

        # Parse the JSON response
        data = response.json()
        affected_products = data.get("value", [])

        if not affected_products:
            return []

        # Extract relevant fields
        records = []
        for product in affected_products:
            mitigation = "N/A"
            mitigation_download_url = "N/A"
            fixed_build_number = "N/A"

            # Extract kbArticles details if available
            kb_articles = product.get("kbArticles", [])
            if kb_articles:
                mitigation = kb_articles[0].get("downloadName", "N/A")
                mitigation_download_url = kb_articles[0].get("downloadUrl", "N/A")
                fixed_build_number = kb_articles[0].get("fixedBuildNumber", "N/A")

            records.append({
                "Product ID": product.get("productId"),
                "Mitigation": mitigation,
                "Mitigation Download URL": mitigation_download_url,
                "Fixed Build Number": fixed_build_number,
            })

        return records

    except requests.exceptions.RequestException as e:
        print(f"Error fetching affected products for CVE {cve_id}: {e}")
        return []

# Main script to combine data
if __name__ == "__main__":
    # Get product name from the user
    product_name = input("Enter the product name: ").strip()

    # Fetch vulnerabilities for the specified product
    vulnerabilities = fetch_vulnerabilities_by_product(product_name)

    if vulnerabilities:
        combined_records = []

        for vuln in vulnerabilities:
            cve_id = vuln["cveNumber"]
            affected_products = fetch_affected_products(cve_id)

            for product in affected_products:
                combined_records.append({
                    "CVE Number": vuln["cveNumber"],
                    "Title": vuln["cveTitle"],
                    "Severity": vuln["severity"],
                    "Impact": vuln["impact"],
                    "Base Score": vuln["baseScore"],
                    "Release Date": vuln["releaseDate"],
                    "Latest Revision Date": vuln["latestRevisionDate"],
                    **product
                })

        # Convert to DataFrame and save as CSV
        df = pd.DataFrame(combined_records)

        if not df.empty:
            csv_file = f"{product_name.replace(' ', '_')}_vulnerabilities.csv"
            df.to_csv(csv_file, index=False)
            print(f"Data saved to {csv_file}")
            print(df.head())
        else:
            print(f"No affected products found for the product: {product_name}")
    else:
        print(f"No vulnerabilities found for the product: {product_name}")
