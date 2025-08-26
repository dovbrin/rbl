import os
import requests
import json
import re
import datetime

# --- Cortex XDR API credentials (stored securely as GitHub secrets) ---
XDR_API_KEY = os.getenv("XDR_API_KEY")
XDR_API_KEY_ID = os.getenv("XDR_API_ID")
XDR_FQDN = os.getenv("XDR_BASE_URL")

# --- GitHub repository details ---
GITHUB_REPO_URL = "https://raw.githubusercontent.com/<YOUR_GITHUB_USER>/<YOUR_REPO_NAME>/<YOUR_BRANCH>/"
IOC_FILES = ["iplist.txt", "fqdnlist.txt", "hashlist.txt"]

# --- Cortex XDR API endpoint ---
url = f"https://{XDR_FQDN}/public_api/v1/indicators/insert_jsons"

def fetch_file_from_github(file_path):
    """Fetches the raw content of a file from GitHub."""
    full_url = GITHUB_REPO_URL + file_path
    response = requests.get(full_url)
    response.raise_for_status()
    return response.text

def parse_iocs(file_content, ioc_type):
    """Parses a text file and returns a list of IoCs."""
    iocs = []
    for line in file_content.splitlines():
        line = line.strip()
        if line and not line.startswith('#'):  # Ignore comments
            iocs.append({
                "indicator": line,
                "type": ioc_type,
                "severity": "HIGH",
                "expiration_date": int((datetime.datetime.now() + datetime.timedelta(days=90)).timestamp()),
                "comment": f"IOC from GitHub repo via API - {ioc_type}",
                "reputation": "BAD",
                "reliability": "A"
            })
    return iocs

def main():
    """Main function to orchestrate fetching, parsing, and sending IoCs."""
    all_iocs = []
    for file_name in IOC_FILES:
        try:
            file_content = fetch_file_from_github(file_name)
            
            # Infer IOC type from filename or apply a specific mapping
            if file_name == "ips.txt":
                ioc_type = "IP"
            elif file_name == "domains.txt":
                ioc_type = "DOMAIN"
            elif file_name == "hashes.txt":
                ioc_type = "HASH"
            else:
                continue

            all_iocs.extend(parse_iocs(file_content, ioc_type))
        except requests.exceptions.RequestException as e:
            print(f"Error fetching file {file_name} from GitHub: {e}")
            continue

    if not all_iocs:
        print("No IoCs to send.")
        return

    payload = {
        "request_data": all_iocs,
        "validate": True
    }

    headers = {
        "Authorization": XDR_API_KEY,
        "x-xdr-auth-id": XDR_API_KEY_ID,
        "Content-Type": "application/json"
    }

    try:
        response = requests.post(url, headers=headers, data=json.dumps(payload))
        response.raise_for_status()
        print("Successfully added IoCs to Cortex XDR.")
        print(f"API Response: {response.json()}")
    except requests.exceptions.RequestException as e:
        print(f"Error sending IoCs to Cortex XDR: {e}")
        print(f"Response content: {response.text}")

if __name__ == "__main__":
    main()
