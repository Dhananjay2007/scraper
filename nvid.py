import requests
import csv
from bs4 import BeautifulSoup


def fetch_specific_table_from_url(url):
    """Fetches the specific mitigation table from the given URL."""
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")

        # Find all tables
        tables = soup.find_all("table")

        # Loop through tables to find the one matching the given headers
        for table in tables:
            headers = [th.get_text(strip=True).lower() for th in table.find_all("th")]
            if headers == ["software product", "operating system", "driver branch", "affected driver versions",
                           "updated driver version"]:
                # Extract rows from the correct table
                rows = [
                    [td.get_text(strip=True) for td in row.find_all("td")]
                    for row in table.find_all("tr")
                    if row.find_all("td")  # Ensure the row has data
                ]
                return {"headers": headers, "rows": rows}
        return None  # No matching table found
    except requests.RequestException as e:
        print(f"Error fetching mitigation table: {e}")
        return None


def fetch_vulnerability_records_and_save(product_name, output_file="vulnerabilities_nvidia.csv"):
    url = "https://www.nvidia.com/content/dam/en-zz/Solutions/product-security/product-security.json"

    try:
        # Fetch the JSON data from the URL
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()

        # Extract relevant data from the JSON structure
        vulnerabilities = []
        for record in data.get("data", []):
            # Parse the title field to extract plain text and URL
            raw_title = record.get("title", "N/A")
            soup = BeautifulSoup(raw_title, "html.parser")
            parsed_title = soup.get_text()
            url_tag = soup.find("a")
            detail_url = url_tag["href"] if url_tag else None

            mitigation_rows = []
            if detail_url:
                table_data = fetch_specific_table_from_url(detail_url)
                if table_data:
                    mitigation_rows = table_data["rows"]

            if product_name.lower() in parsed_title.lower():
                if mitigation_rows:
                    for row in mitigation_rows:
                        vulnerabilities.append({
                            "Title": parsed_title if parsed_title else "N/A",
                            "Bulletin ID": record.get("bulletin id", "N/A"),
                            "Severity": record.get("severity", "N/A"),
                            "CVE Identifiers": record.get("cve identifier(s)", "N/A"),
                            "Publish Date": record.get("publish date", "N/A"),
                            "Last Updated": record.get("last updated", "N/A"),
                            "Software Product": row[0] if len(row) > 0 else "N/A",
                            "Operating System": row[1] if len(row) > 1 else "N/A",
                            "Driver Branch": row[2] if len(row) > 2 else "N/A",
                            "Affected Driver Versions": row[3] if len(row) > 3 else "N/A",
                            "Updated Driver Version": row[4] if len(row) > 4 else "N/A"
                        })
                else:
                    vulnerabilities.append({
                        "Title": parsed_title if parsed_title else "N/A",
                        "Bulletin ID": record.get("bulletin id", "N/A"),
                        "Severity": record.get("severity", "N/A"),
                        "CVE Identifiers": record.get("cve identifier(s)", "N/A"),
                        "Publish Date": record.get("publish date", "N/A"),
                        "Last Updated": record.get("last updated", "N/A"),
                        "Software Product": "N/A",
                        "Operating System": "N/A",
                        "Driver Branch": "N/A",
                        "Affected Driver Versions": "N/A",
                        "Updated Driver Version": "N/A"
                    })

        # Save to CSV file
        if vulnerabilities:
            with open(output_file, mode="w", newline="", encoding="utf-8") as file:
                writer = csv.DictWriter(file, fieldnames=vulnerabilities[0].keys())
                writer.writeheader()
                writer.writerows(vulnerabilities)

            print(f"Vulnerability records for '{product_name}' saved to {output_file}.")
        else:
            print(f"No vulnerabilities found for the product: {product_name}")

    except requests.RequestException as e:
        print(f"Error fetching data: {e}")
    except ValueError:
        print("Error decoding JSON response.")


if __name__ == "__main__":
    product_name = input("Enter the product name to search vulnerabilities: ")
    fetch_vulnerability_records_and_save(product_name)
