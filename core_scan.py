#!/usr/bin/env python

import hashlib
import os
import requests
import json

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

# Check file with VirusTotal and cache the result
def check_virustotal(file_hash, cache):
    if file_hash in cache:
        return cache[file_hash]

    params = {'apikey': API_KEY, 'resource': file_hash}
    response = requests.get(BASE_URL + 'file/report', params=params)
    result = response.json()

    if result['response_code'] == 1:  # File found in VirusTotal database
        if result['positives'] > 0:
            detection = f"VirusTotal detection: {result['positives']}/{result['total']} detections"
        else:
            detection = "No threats detected by VirusTotal."
        cache[file_hash] = detection
    else:
        detection = "File not found in VirusTotal database."
        cache[file_hash] = detection

    save_cache(cache)
    return detection

# Scan a single file
def scan_file(file_path, cache):
    file_hash = calculate_md5(file_path)
    if file_hash in local_virus_db:
        return local_virus_db[file_hash]

    # Check with VirusTotal and cache the result
    return check_virustotal(file_hash, cache)

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
