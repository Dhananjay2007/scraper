import pandas as pd
from bs4 import BeautifulSoup

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
import time

options = webdriver.ChromeOptions()
#options.add_argument("--headless")
options.add_argument("--disable-gpu")
options.add_argument("--no-sandbox")

driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)

url = "https://support.apple.com/en-us/100100"
driver.get(url)

# Wait for content to load
time.sleep(5)

# Extract page content
html_content = driver.page_source
driver.quit()

from bs4 import BeautifulSoup
soup = BeautifulSoup(html_content, 'html.parser')
data_tables = soup.find_all('tr')
# Prepare a list to hold the extracted data
data = []

# Iterate through each row
for data_table in data_tables:
    cols = data_table.find_all('td')  # Extract all <td> elements

    # Check if the row has enough columns to extract data
    if len(cols) >= 3:
        advisory = cols[0].text.strip()  # Text inside the first <td>
        advisory_id = cols[1].text.strip()  # Text inside the second <td>
        published_date = cols[2].text.strip()  # Text inside the third <td>
        #updated_date = cols[3].text.strip()  # Text inside the fourth <td>

        # Append the extracted data as a dictionary
        data.append({
            "Advisory": advisory,
            "Advisory ID": advisory_id,
            "Published Date": published_date,
            #"Updated Date": updated_date,
        })


df = pd.DataFrame(data)

# Print the DataFrame to verify
print(df)

# Save to an Excel file
output_file = "../scrapers/reports/apple_advisories.csv"
df.to_csv(output_file, index=False)

print(f"Data has been written to {output_file}")

# Find and process the table


