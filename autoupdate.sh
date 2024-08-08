#!/bin/bash

# URL to check for the latest release version.txt
REMOTE_URL="https://github.com/Hemis-Blockchain/Hemis/releases/latest/download/version.txt"

# Local file path to store the version.txt
LOCAL_FILE="/root/version.txt"

# Function to check and update the version file
check_and_update_version() {
  # Download the remote version file to a temporary location
  TEMP_FILE=$(mktemp)

  # Fetch the remote version file
  if curl --silent --fail -o "$TEMP_FILE" "$REMOTE_URL"; then
    echo "Fetched the remote version file."

    # Compare the local and remote version files
    if [ -f "$LOCAL_FILE" ]; then
      if cmp -s "$LOCAL_FILE" "$TEMP_FILE"; then
        echo "Local version is up to date. No update needed."
      else
        echo "New version found. Updating local file..."
        mv "$TEMP_FILE" "$LOCAL_FILE"
        echo "Local version file updated successfully."
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
      fi
    else
      echo "Local version file not found. Creating new local file..."
      mv "$TEMP_FILE" "$LOCAL_FILE"
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
    fi
  else
    echo "Failed to fetch the remote version file. No update performed."
    rm "$TEMP_FILE"
  fi
}

# Execute the function
