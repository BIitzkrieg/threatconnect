import base64
import json
import requests
import time
import hmac
import hashlib
import urllib.parse

indicator_url = "https://*.threatconnect.com/api/v3/indicators/" # Populate your TC Instace URL
owner_url = "https://*.threatconnect.com/api/v3/security/owners/" # Populate your TC Instace URL
indicator_path = "/api/v3/indicators/"
owner_path = "/api/v3/security/owners/"
api_method = "GET"
api_id = "" # API Account ID here
secret_key = ''  # Your key here
    owner_list = []
    timestamp = str(int(time.time()))
    signature = f"{owner_path}:{api_method}:{timestamp}"
    secret_byte_key = bytes(secret_key, 'UTF-8')
    message = signature.encode('UTF-8')
    digest = hmac.new(secret_byte_key, message, hashlib.sha256).digest()
    hashed_result = base64.b64encode(digest).decode('UTF-8')
    headers = {"Timestamp": timestamp, "Authorization": f"TC {api_id}:{hashed_result}"}
    try:
        response = requests.get(owner_url, headers=headers)
        response.raise_for_status()
        json_response = response.json()
        if json_response.get('data'):
            for owner in json_response['data']:
                owner_list.append(owner['name'])
            if "Push to HHS" in owner_list:
                owner_list.remove("Push to HHS")
            return owner_list
        else:
            print("No owners found in response")
            return []
    except requests.RequestException as e:
        print(f"Error fetching owners: {e}")
        return []

def tcLogic(ioc):
    owner_list_logic = getOwners()
    if not owner_list_logic:
        print("No owners available to query")
        return
    found = False  # Flag to track if IOC is found in any owner
    for owner in owner_list_logic:
        timestamp = str(int(time.time()))
        signature = f"{indicator_path}{urllib.parse.quote(ioc, safe='')}?owner={urllib.parse.quote(owner, safe='')}:{api_method}:{timestamp}"
        secret_byte_key = bytes(secret_key, 'UTF-8')
        message = signature.encode('UTF-8')
        digest = hmac.new(secret_byte_key, message, hashlib.sha256).digest()
        hashed_result = base64.b64encode(digest).decode('UTF-8')
        headers = {"Timestamp": timestamp, "Authorization": f"TC {api_id}:{hashed_result}"}
        built_url = f"{indicator_url}{urllib.parse.quote(ioc, safe='')}?owner={urllib.parse.quote(owner, safe='')}"
        try:
            response = requests.get(built_url, headers=headers)
            response.raise_for_status()
            json_response = response.json()
            if json_response.get('data'):
                found = True  # IOC found in this owner
                data = json_response['data']
                rating = data.get('rating')
                confidence = data.get('confidence')
                if rating and confidence:
                    print(f"Found rating and confidence for {ioc}: rating={rating}, confidence={confidence}")
                elif rating:
                    print(f"Found only rating for {ioc}: rating={rating}")
                elif confidence:
                    print(f"Found only confidence for {ioc}: confidence={confidence}")
                else:
                    print(f"No rating or confidence found for {ioc}")
                print(f"Summary: {data.get('summary')}, Owner: {data.get('ownerName')}, Type: {data.get('type')}")
            time.sleep(0.5)  # Avoid rate limiting
        except requests.RequestException as e:
            if response.status_code == 400:
                json_response = response.json()
                if "No indicator found" in json_response.get('message', ''):
                    pass  # Do not print here; handle after loop
                else:
                    print(f"Error 400 for IOC {ioc} in {owner}: {response.text}")
            else:
                print(f"Error querying IOC {ioc} in {owner}: {e}")
    if not found:
        print(f"IOC {ioc} not found in any sources")

def tcMain():
    try:
        with open("ioc.txt", "r") as f:
            contents = f.read()
            file_as_list = list(dict.fromkeys(contents.splitlines()))
            if not file_as_list:
                print("Error: ioc.txt is empty or contains no valid IOCs")
                return
            for ioc in file_as_list:
                if ioc.strip():
                
                    # Create a box around the IOC
                    box_width = 50  # Fixed width for the box
                    print("#" * box_width)
                    print(f"# IOC:{ioc.center(box_width - 8)} #")  # Center the IOC
                    print("#" * box_width)
                    tcLogic(ioc)
    except FileNotFoundError:
        print("Error: ioc.txt file not found")
    except Exception as e:
        print(f"Error reading ioc.txt: {e}")

def main():
    tcMain()

if __name__ == '__main__':
    main()
