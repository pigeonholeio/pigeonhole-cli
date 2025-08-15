#!/usr/bin/env bash

# Check argument
if [ -z "$1" ]; then
  echo "Usage: $0 <path-to-artefact.yml>"
  exit 1
fi

file="$1"

# Extract current version
current_version=$(grep -E '^\s*version:' "$file" | awk '{print $2}')

# Split into major.minor.patch
IFS='.' read -r major minor patch <<< "$current_version"

# Increment patch
patch=$((patch + 1))

# Build new version
new_version="$major.$minor.$patch"

# Update file in-place
sed -i -E "s/^(\\s*version:).*/\1 $new_version/" "$file"

echo "Bumped version: $current_version -> $new_version"
