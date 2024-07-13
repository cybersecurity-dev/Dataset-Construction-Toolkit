#!/bin/bash

# download a single file
download_file() {
  url="$1"
  echo "$url"
  download_dir="$2"
  filename=$(basename "$url")
  filepath="$download_dir/$filename"

  # Check if file already exists using test command for efficiency
  if [[ -f "$filepath" ]]; then
    echo "$filename already exists in $download_dir"
    return 1
  fi

  # Download using wget
  wget -q "$url" -P "$download_dir"

  if [[ $? -eq 0 ]]; then
    echo "Downloaded: $filename"
  else
    echo "Error downloading: $filename"
  fi
}

# Validate wget presence
if ! command -v wget &> /dev/null; then
  echo "Error: wget command not found. Please install it."
  exit 1
fi

# Usage message
if [[ $# -lt 3 ]]; then
  echo "Usage: $0 <URL> <download_directory> <filetype>"
  exit 1
fi

# Get URL and download directory from arguments
main_url="$1/"
download_dir="$2"
filetype="$3"

# Create download directory if it doesn't exist
mkdir -p "$download_dir"

# Download logic based on specific criteria (adjust as needed)
echo "Downloading files of type $filetype from: $main_url"

# Download the HTML content of the URL
html_content=$(wget -q -O - "${main_url}")

# Extract URLs of the specified file type
links=$(echo "${html_content}" | grep -oP '(?<=href=")[^"]*' | grep "\.${filetype}$")

# Loop through extracted links and download files
for link in $links; do
  download_file "$main_url$link" "$download_dir"
done

# Handle download completion or errors
if [[ $? -eq 0 ]]; then
  echo "Download completed."
else
  echo "Download encountered errors."
fi
