#!/bin/bash

# Fetch the latest version
LATEST_VERSION_URL="https://releases.pigeono.io/latest.txt"
VERSION=$(curl -s "$LATEST_VERSION_URL")
if [[ -z "$VERSION" ]]; then
    echo "Failed to fetch the latest version from $LATEST_VERSION_URL"
    exit 1
fi
echo "Latest version: $VERSION"

# Detect OS
OS=$(uname -s)
if [[ "$OS" == "Linux" ]]; then
    OS="linux"
elif [[ "$OS" == "Darwin" ]]; then
    OS="darwin"
else
    echo "Unsupported OS: $OS"
    exit 1
fi

# Detect architecture
ARCH=$(uname -m)
if [[ "$ARCH" == "x86_64" ]]; then
    ARCH="amd64"
elif [[ "$ARCH" == "arm64" || "$ARCH" == "aarch64" ]]; then
    ARCH="arm64"
else
    echo "Unsupported architecture: $ARCH"
    exit 1
fi

# Construct the download URL
URL="https://releases.pigeono.io/${VERSION}/${OS}/${ARCH}/pigeonhole"

# Download the file
echo "Downloading latest version (v$VERSION) to /usr/local/bin/..."
curl -s -o pigeonhole -L "$URL"
if [[ $? -ne 0 ]]; then
    echo "Failed to download the file."
    exit 1
fi

# Make the downloaded file executable
chmod +x pigeonhole
sudo install -m 755 ./pigeonhole /usr/local/bin/
rm -f ./pigeonhole
echo "installed!"
echo "Now try signing in by running 'pigeonhole login'"
