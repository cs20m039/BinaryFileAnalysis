import hashlib
import os
import requests
import logging
import time

API_KEY = '385e6cf10525284f31f3aa5a7a6c855bf01bc3fc1551bdb24a74cb076985d635'
VT_URL = 'https://www.virustotal.com/vtapi/v2/file/report'
LOOKUPS_PER_MINUTE = 4
SLEEP_TIME = 60 / LOOKUPS_PER_MINUTE
DAILY_QUOTA = 500

# Set up logging
logging.basicConfig(filename='/home/cs20m039/PycharmProjects/pythonProject/logfiles/file_check_log.txt', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')
console = logging.StreamHandler()
console.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console.setFormatter(formatter)
logging.getLogger('').addHandler(console)

# Start of the script
logging.info("Script started")

request_counter = 0

def file_hash(filepath):
    # Function-specific logging can be added here if needed
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
    except Exception as e:
        logging.error(f"Error reading file {filepath}: {e}")
        return None
    return sha256_hash.hexdigest()

def scan_file(filepath):
    global request_counter
    if request_counter >= DAILY_QUOTA:
        logging.warning("Daily quota reached, stopping further requests.")
        return "error", "Daily quota reached"

    hash = file_hash(filepath)
    if not hash:
        return "error", "Error calculating hash"
    params = {'apikey': API_KEY, 'resource': hash}
    try:
        response = requests.get(VT_URL, params=params)
        request_counter += 1
        # Check if the request was successful
        if response.status_code == 200:
            response_json = response.json()
            # Check if the file has been analyzed before
            if response_json.get('response_code') == 1:
                positives = response_json.get('positives', 0)
                if positives > 0:
                    logging.info(f"Malware detected in file {filepath}. Positives: {positives}")
                else:
                    logging.info(f"No malware detected in file {filepath}.")
            else:
                logging.info(f"File {filepath} not found in VirusTotal database.")
        else:
            logging.error(f"Error querying VirusTotal for file {filepath}: HTTP {response.status_code}")
    finally:
        time.sleep(SLEEP_TIME)

def check_directory(directory):
    logging.info(f"Starting to check directory: {directory}")
    if not os.path.exists(directory):
        logging.error(f"Directory not found: {directory}")
        return
    for root, dirs, files in os.walk(directory):
        for filename in files:
            filepath = os.path.join(root, filename)
            scan_file(filepath)
    logging.info(f"Finished checking directory: {directory}")

# Replace 'YOUR_DIRECTORY_PATH' with the path to the directory you want to scan.
check_directory('/home/cs20m039/thesis/dataset3')

# End of the script
logging.info("Script ended")
