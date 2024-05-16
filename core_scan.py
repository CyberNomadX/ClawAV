import hashlib
import os
import requests
import json
import time

# Config file location
CONFIG_FILE = 'config.json'

# Load API key from config file
def load_config():
    if not os.path.exists(CONFIG_FILE):
        raise FileNotFoundError(f"{CONFIG_FILE} not found. Please create it with your VirusTotal API key.")

    with open(CONFIG_FILE, 'r') as f:
        config = json.load(f)

    api_key = config.get('virustotal_api_key')
    if not api_key:
        raise ValueError("No API key found in config.json.")
    
    return api_key

API_KEY = load_config()
BASE_URL = 'https://www.virustotal.com/vtapi/v2/'
CACHE_FILE = 'cache.json'
REQUESTS_PER_MINUTE = 4  # VirusTotal free API allows 4 requests per minute
REQUESTS_PER_DAY = 500  # VirusTotal free API allows 500 requests per day

# Sample database of known malicious file hashes (local database)
local_virus_db = {
    "e99a18c428cb38d5f260853678922e03": "Example Virus",
    # Add more known virus hashes here
}

# Load cache from file with improved error handling
def load_cache():
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return {}
    return {}

# Save cache to file
def save_cache(cache):
    with open(CACHE_FILE, 'w') as f:
        json.dump(cache, f)

# Calculate MD5 hash of a file
def calculate_md5(file_path):
    hasher = hashlib.md5()
    with open(file_path, 'rb') as f:
        buf = f.read()
        hasher.update(buf)
    return hasher.hexdigest()

# Check file with VirusTotal and cache the result with enhanced error handling
def check_virustotal(file_hash, file_path, cache, requests_count):
    if file_hash in cache:
        return cache[file_hash]

    params = {'apikey': API_KEY, 'resource': file_hash}
    try:
        if requests_count >= REQUESTS_PER_MINUTE:
            print("Rate limit exceeded, sleeping for 60 seconds")
            time.sleep(60)
            requests_count = 0

        response = requests.get(BASE_URL + 'file/report', params=params)
        requests_count += 1
        response.raise_for_status()  # Raise an HTTPError for bad responses (4xx and 5xx)
        print(f"VirusTotal response status code: {response.status_code}")
        print(f"VirusTotal response content: {response.content.decode()}")  # Log the raw content

        result = response.json()

        if result['response_code'] == 1:  # File found in VirusTotal database
            if result['positives'] > 0:
                detection = f"VirusTotal detection: {result['positives']}/{result['total']} detections"
            else:
                detection = "No threats detected by VirusTotal."
            cache[file_hash] = detection
            save_cache(cache)
            return detection

        elif result['response_code'] == 0:  # File not found, submit the file for scanning
            print(f"File not found in VirusTotal database, submitting for analysis: {file_path}")
            files = {'file': (file_path, open(file_path, 'rb'))}
            response = requests.post(BASE_URL + 'file/scan', files=files, params={'apikey': API_KEY})
            requests_count += 1
            response.raise_for_status()
            result = response.json()
            print(f"File submitted for analysis: {result}")
            detection = "File submitted for analysis, please try again later."
            cache[file_hash] = detection
            save_cache(cache)
            return detection

        elif response.status_code == 204:  # Rate limiting exceeded
            print("Rate limit exceeded, sleeping for 60 seconds")
            time.sleep(60)
            return check_virustotal(file_hash, file_path, cache, requests_count)

        else:
            detection = "Unexpected response from VirusTotal."
            cache[file_hash] = detection
            save_cache(cache)
            return detection

    except requests.exceptions.RequestException as e:
        print(f"Error contacting VirusTotal: {e}")
        return "Error contacting VirusTotal"
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON response from VirusTotal: {e}")
        return "Error decoding JSON response from VirusTotal"

# Scan a single file
def scan_file(file_path, cache, requests_count):
    file_hash = calculate_md5(file_path)
    if file_hash in local_virus_db:
        return local_virus_db[file_hash]

    # Check with VirusTotal and cache the result
    return check_virustotal(file_hash, file_path, cache, requests_count)

# Scan a directory
def scan_directory(directory, cache, requests_count):
    results = {}
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            result = scan_file(file_path, cache, requests_count)
            if result:
                results[file_path] = result
    return results

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Scan files and directories for viruses.")
    parser.add_argument('path', help="Path to the file or directory to scan")
    args = parser.parse_args()

    cache = load_cache()
    requests_count = 0

    if os.path.isfile(args.path):
        result = scan_file(args.path, cache, requests_count)
        if result:
            print(f"Threat detected: {result}")
        else:
            print("No threats detected.")
    elif os.path.isdir(args.path):
        results = scan_directory(args.path, cache, requests_count)
        if results:
            for file_path, virus in results.items():
                print(f"Threat detected in {file_path}: {virus}")
        else:
            print("No threats detected.")
    else:
        print("Invalid path. Please provide a valid file or directory.")
