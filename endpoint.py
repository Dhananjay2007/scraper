from browsermobproxy import Server
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import json
import re
import time

# Path to BrowserMob Proxy binary
BROWSERMOB_PROXY_PATH = '/path/to/browsermob-proxy'  # Update this path

# Path to ChromeDriver
CHROMEDRIVER_PATH = '/path/to/chromedriver'  # Update this path

# Initialize and start the BrowserMob Proxy server
server = Server(BROWSERMOB_PROXY_PATH + "/bin/browsermob-proxy")
server.start()
proxy = server.create_proxy()

# Configure Selenium to use the proxy
chrome_options = Options()
chrome_options.add_argument(f'--proxy-server={proxy.proxy}')

# Optional: Run Chrome in headless mode
chrome_options.add_argument('--headless')

# Initialize Selenium WebDriver
driver = webdriver.Chrome(executable_path=CHROMEDRIVER_PATH, options=chrome_options)

# Start capturing the network traffic
proxy.new_har("vulnerability_site", options={'captureHeaders': True, 'captureContent': True})

# Navigate to the target OEM website
target_url = 'https://www.example-oem.com/security-advisories'  # Replace with actual URL
driver.get(target_url)

# Wait for the page to load completely
time.sleep(5)  # Adjust sleep time as needed based on page complexity

# Interact with the page if necessary to trigger API calls
# For example, clicking buttons, scrolling, etc.
# Example:
# button = driver.find_element_by_id('load-more')
# button.click()
# time.sleep(2)

# Retrieve the captured network traffic
har_data = proxy.har  # HAR format data

# Stop the proxy and close the browser
driver.quit()
server.stop()

# Function to extract API endpoints from HAR data
def extract_api_endpoints(har):
    api_endpoints = set()
    for entry in har['log']['entries']:
        request = entry['request']
        url = request['url']
        method = request['method']
        headers = {header['name']: header['value'] for header in request['headers']}
        # Filter requests that are likely to be API calls
        # Common indicators:
        # - URLs containing '/api/', '/v1/', '/v2/', etc.
        # - JSON responses
        # - Specific headers like 'Content-Type: application/json'
        if re.search(r'/api/|/v1/|/v2/|/rest/|/graphql/', url, re.IGNORECASE):
            api_endpoints.add(url)
        elif 'Accept' in headers and 'application/json' in headers['Accept']:
            api_endpoints.add(url)
    return api_endpoints

# Extract API endpoints
api_endpoints = extract_api_endpoints(har_data)

# Display the discovered API endpoints
print("Discovered API Endpoints:")
for endpoint in api_endpoints:
    print(endpoint)
