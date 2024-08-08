#!/bin/bash

# URL to check for the latest release (replace with the actual URL of the file)
URL="https://github.com/Hemis-Blockchain/Hemis/releases/latest/download/version.txt"

# Function to check for the latest release
check_latest_release() {
  # Send a HEAD request to check if the file exists on the server
  if curl --head --silent --fail "$URL" > /dev/null; then
    echo "File exists. Updating the local files..."
    Hemis-cli stop
    echo "Installing unzip"
sudo apt install unzip -y
echo "unzip installed"
echo "Fetching latest Hemis version"
wget --quiet https://github.com/Hemis-Blockchain/Hemis/releases/latest/download/Hemis-Linux.zip && sudo unzip Hemis-Linux.zip -d /usr/local/bin
echo "Hemis succesfully updated"
echo "Cleanup excess files"
rm Hemis-Linux.zip && rm Hemis-params.zip
Hemisd
    echo "File updated successfully."
  else
    echo "File does not exist. No update needed."
  fi
}

# Execute the function
check_latest_release
