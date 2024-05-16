import hashlib
import os
import requests
import json
import time

# Configuration and API keys
CONFIG_FILE = 'config.json'
HYBRID_ANALYSIS_API_KEY = 'your_hybrid_analysis_api_key'
HYBRID_ANALYSIS_BASE_URL = 'https://www.hybrid-analysis.com/api/v2/'

# Load VirusTotal API key from config file
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
VIRUSTOTAL_BASE_URL = 'https://www.virustotal.com/vtapi/v2/'
CACHE_FILE = 'cache.json'
REQUESTS_PER_MINUTE = 4  # VirusTotal free API allows 4 requests per minute
REQUESTS_PER_DAY = 500  # VirusTotal free API allows 500 requests per day

# Local database of known malicious file hashes including EICAR test hash
local_virus_db = {
    "44d88612fea8a8f36de82e1278abb02f": "EICAR Test File",
    "e99a18c428cb38d5f260853678922e03": "Example Virus",
    # Add more known virus hashes here
}

# Load cache from file with error handling
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

# Check file with Hybrid Analysis and return the result
def check_hybrid_analysis(file_hash):
    headers = {'api-key': HYBRID_ANALYSIS_API_KEY, 'User-Agent': 'Falcon Sandbox'}
    response = requests.get(f'{HYBRID_ANALYSIS_BASE_URL}search/hash', headers=headers, params={'hash': file_hash})
    if response.status_code == 200:
        return response.json()
    else:
        return None

# Check file with VirusTotal and cache the result with error handling
def check_virustotal(file_hash, file_path, cache):
    if file_hash in cache:
        return cache[file_hash]

    params = {'apikey': API_KEY, 'resource': file_hash}
    try:
        print(f"Checking VirusTotal for {file_hash}...")
        response = requests.get(VIRUSTOTAL_BASE_URL + 'file/report', params=params)
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
            response = requests.post(VIRUSTOTAL_BASE_URL + 'file/scan', files=files, params={'apikey': API_KEY})
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
            return check_virustotal(file_hash, file_path, cache)

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
def scan_file(file_path, cache):
    file_hash = calculate_md5(file_path)
    if file_hash in local_virus_db:
        print(f"File {file_path} matches local virus database. {local_virus_db[file_hash]}")
        return local_virus_db[file_hash]

    print(f"Scanning file: {file_path}")
    hybrid_analysis_result = check_hybrid_analysis(file_hash)
    if hybrid_analysis_result:
        if hybrid_analysis_result.get('verdict', '').lower() == 'malicious':
            print(f"Hybrid Analysis found threat for {file_hash}, submitting to VirusTotal")
            return check_virustotal(file_hash, file_path, cache)
        else:
            print(f"No threats detected by Hybrid Analysis with verdict {hybrid_analysis_result.get('verdict', 'unknown')}.")
            if file_hash == "44d88612fea8a8f36de82e1278abb02f":  # Check VirusTotal for EICAR
                print(f"File {file_path} is the EICAR test file. Submitting to VirusTotal for verification.")
                return check_virustotal(file_hash, file_path, cache)
    else:
        print("No response from Hybrid Analysis.")

    return "No threats detected by Hybrid Analysis."

# Scan a directory
def scan_directory(directory, cache):
    results = {}
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            result = scan_file(file_path, cache)
            if result:
                results[file_path] = result
    return results

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Scan files and directories for viruses.")
    parser.add_argument('path', help="Path to the file or directory to scan")
    args = parser.parse_args()

    cache = load_cache()

    if os.path.isfile(args.path):
        result = scan_file(args.path, cache)
        if result:
            print(f"Threat detected: {result}")
        else:
            print("No threats detected.")
    elif os.path.isdir(args.path):
        results = scan_directory(args.path, cache)
        if results:
            for file_path, virus in results.items():
                print(f"Threat detected in {file_path}: {virus}")
        else:
            print("No threats detected.")
    else:
        print("Invalid path. Please provide a valid file or directory.")
