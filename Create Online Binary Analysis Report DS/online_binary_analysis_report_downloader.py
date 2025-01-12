import requests
import json
import os
import hashlib
import time
import sys

# Function to calculate SHA256 hash of a file
def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# Function to get result from VirusTotal using SHA256
def get_virustotal_result(api_key, sha256):
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {
        "x-apikey": api_key
    }
    response = requests.get(url, headers=headers)
    return response.json()

# Function to get result from MalwareBazaar using SHA256
def get_malwarebazaar_result(api_key, sha256):
    url = "https://mb-api.abuse.ch/api/v1/"
    headers = {
        "API-KEY": api_key
    }
    data = {
        "query": "get_info",
        "hash": sha256
    }
    response = requests.post(url, headers=headers, data=data)
    return response.json()

# Function to save result to JSON file with filename as SHA256 hash in a specified directory
def save_to_json(data, sha256, directory):
    # Create the directory if it doesn't exist
    if not os.path.exists(directory):
        os.makedirs(directory)
    
    filename = os.path.join(directory, f"{sha256}.json")
    with open(filename, 'w') as json_file:
        json.dump(data, json_file, indent=4)
    print(f"VT response saved as {filename}") 

def main(virustotal_api_key, malwarebazaar_api_key, binaries_directory, vt_results_directory, mb_results_directory):    
    # Check if the binaries directory exists
    if not os.path.exists(binaries_directory):
        print(f"The directory '{binaries_directory}' does not exist.")
    else:
        
        # Iterate over each file in the binaries directory
        for filename in os.listdir(binaries_directory):
            file_path = os.path.join(binaries_directory, filename)
            
            # Calculate SHA256 hash of the file
            sha256 = calculate_sha256(file_path)    
            
            # Check if the VirusTotal result already exists in the results directory
            vt_result_file_path = os.path.join(vt_results_directory, f"{sha256}.json")
            if os.path.exists(vt_result_file_path):
                print(f"VirusTotal result for {filename} already exists. Skipping VirusTotal request.")
            else:
                # Get result from VirusTotal using the calculated SHA256 hash
                vt_result = get_virustotal_result(virustotal_api_key, sha256)
            
                # Save result to JSON file with filename as SHA256 hash in the specified directory
                save_to_json(vt_result, sha256, vt_results_directory)
            
            # Check if the MalwareBazaar result already exists in the results directory
            mb_result_file_path = os.path.join(mb_results_directory, f"{sha256}.json")
            if os.path.exists(mb_result_file_path):
                print(f"MalwareBazaar result for {filename} already exists. Skipping MalwareBazaar request.")
            else:
                # Get result from MalwareBazaar using the calculated SHA256 hash
                mb_result = get_malwarebazaar_result(malwarebazaar_api_key, sha256)
            
                # Save result to JSON file with filename as SHA256 hash in the specified directory
                save_to_json(mb_result, sha256, mb_results_directory)

        print(f"Results have been saved to\n{vt_results_directory}\n{mb_results_directory}")

if __name__ == "__main__":
    print("\n----------------------------------\n")
    print("[" + __file__ + "]'s last modified: %s" % time.ctime(os.path.getmtime(__file__)))
    print("\n----------------------------------\n")
    # Check if a parameter is provided
    if len(sys.argv) == 5 :

        dir_binary = sys.argv[1]
        print(f"Download Directory:\t{dir_binary}")
    
        file_output = sys.argv[2]
        vt_results_directory = file_output + "/vt/"        
        mb_results_directory = file_output + "/mb/"
        print(f"MB save Directory:\t{mb_results_directory}")
        print(f"VT save Directory:\t{vt_results_directory}")

        virustotal_api_key = sys.argv[3]
        print(f"Virustotal API KEY:\t{virustotal_api_key}")

        malwarebazaar_api_key = sys.argv[4]
        print(f"MalwareBazaar API KEY:\t{malwarebazaar_api_key}")

        main(virustotal_api_key, malwarebazaar_api_key, dir_binary, vt_results_directory, mb_results_directory)
    else:
        print("python3" + __file__ + " <input directory> <output directory> <VT API KEY> <MalwareBazaar API KEY>")

