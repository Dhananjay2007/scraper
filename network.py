import requests
import json


def fetch_security_bulletins():
    # Get user input for the search query
    query = input("Enter the product name or keyword to search for vulnerabilities: ").strip()

    # Validate input
    if not query:
        print("Query cannot be empty. Exiting.")
        return

    # Define the API endpoint
    url = "https://support.hp.com/wcc-services/kaas/us-en/security-bulletins"

    # Query parameters
    params = {
        "query": query,
        "sortBy": "bulletinUpdateDate",  # Fixed sorting by update date
        "sortOrder": "desc",  # Fixed sorting in descending order
        "authState": "anonymous",
        "template": "Document_SC"
    }
    print(f"Fetching data from URL: {url}")

    # Headers
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Python Script"
    }

    try:
        # Send the GET request
        response = requests.get(url, headers=headers, params=params)

        # Check response status
        if response.status_code == 200:
            data = response.json()

            # Debugging: Print the entire JSON response
            # print("\nComplete JSON Response:")
            # print(json.dumps(data, indent=4))  # Pretty-print the JSON response

            # Extract and display relevant fields
            if "data" in data and isinstance(data["data"], list) and len(data["data"]) > 0:
                print("\nSecurity Bulletins Found:\n")
                for bulletin in data["data"]:
                    print(f"Title: {bulletin.get('title')}")
                    print(f"Description: {bulletin.get('description', 'No description available')}")
                    print(f"Update Date: {bulletin.get('bulletinUpdateDate')}")
                    print(f"Severity: {bulletin.get('severity')}")
                    print(f"Link: https://support.hp.com/{bulletin.get('redirectURL')}")
                    print("-" * 40)
            else:
                print("No security bulletins found in the response.")
                print(f"Available keys in the response: {data.keys()}")

            # Optionally save the response to a file
            save_option = input("Do you want to save the results to a file? (yes/no): ").strip().lower()
            if save_option == "yes":
                file_name = f"hp_security_bulletins_{query}.json"
                with open(file_name, "w") as file:
                    json.dump(data, file, indent=4)
                print(f"Results saved to {file_name}.")
        else:
            print(f"Failed to fetch data: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"An error occurred: {e}")


# Run the function
fetch_security_bulletins()
