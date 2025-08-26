import requests
import json
import uuid
import datetime

# ====================================================================
# --- Replace with your Cortex XDR API credentials and FQDN ---
# ====================================================================
XDR_API_KEY = "YOUR_API_KEY"
XDR_API_KEY_ID = "YOUR_KEY_ID"
XDR_FQDN = "api-YOURTENANTFQDN"  # e.g., api-emea.xdr.apifilter.com

def generate_canary_domain():
    """Generates a unique canary domain name using a UUID."""
    unique_id = uuid.uuid4().hex[:12]
    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M")
    return f"canary-{timestamp}-{unique_id}.test.com"

def create_ioc_payload(domain):
    """Creates the JSON payload for a single domain IOC."""
    # Set expiration for 30 days from now
    expiration_timestamp = int((datetime.datetime.now() + datetime.timedelta(days=30)).timestamp())
    
    return {
        "request_data": [
            {
                "indicator": domain,
                "type": "DOMAIN",
                "severity": "LOW",
                "expiration_date": expiration_timestamp,
                "comment": "Canary domain for API validation. Not malicious.",
                "reputation": "GOOD",  # Use GOOD to avoid triggering production alerts
                "reliability": "A",
                "class": "Canary_Domain"
            }
        ],
        "validate": True
    }

def send_ioc_to_cortex(payload):
    """Sends the IOC payload to the Cortex XDR Public API."""
    url = f"https://api-ono.xdr.eu.paloaltonetworks.com/public_api/v1/indicators/insert_jsons"
    headers = {
    "Authorization": XDR_API_KEY,
    "x-xdr-auth-id": XDR_API_KEY_ID,  # <-- Use the correct variable name
    "Content-Type": "application/json"
}
    
    print(f"Sending IOCs to {url}...")
    
    try:
        response = requests.post(url, headers=headers, data=json.dumps(payload))
        response.raise_for_status()  # Raise an exception for bad status codes
        
        response_json = response.json()
        print("\nSuccessfully added IOC to Cortex XDR.")
        print("API Response:")
        print(json.dumps(response_json, indent=2))
        return response_json
        
    except requests.exceptions.RequestException as e:
        print(f"\nError adding IOC: {e}")
        if response is not None:
            print(f"Response content: {response.text}")
        return None

if __name__ == "__main__":
    # 1. Generate the canary domain
    canary_domain = generate_canary_domain()
    print(f"Generated canary domain: {canary_domain}")
    
    # 2. Create the API payload
    payload = create_ioc_payload(canary_domain)
    
    # 3. Send the IOC
    response = send_ioc_to_cortex(payload)
    
    if response and response.get('reply', {}).get('status') == 'success':
        print("\nCanary domain IOC has been submitted. Check your Cortex XDR console.")

