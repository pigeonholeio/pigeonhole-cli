#!/bin/bash
# One-time GUID generation for MSI package
# These GUIDs must remain constant across all versions
#
# IMPORTANT: This script is for documentation purposes.
# The GUIDs have already been generated and committed to wix.json
#
# To regenerate GUIDs (NOT RECOMMENDED unless you have a strong reason):
# 1. Backup wix.json
# 2. Run this script: bash generate-guids.sh
# 3. Copy the output and update wix.json
# 4. WARNING: Changing GUIDs will break upgrade paths for existing users!

echo "Generating GUIDs for MSI package..."
echo ""
echo "CRITICAL: These GUIDs must be saved and never changed!"
echo "Add them to build/msi/wix.json"
echo ""
echo "upgrade-code: $(uuidgen)"
echo "files.guid: $(uuidgen)"
echo "env.guid: $(uuidgen)"
echo "shortcuts.guid: $(uuidgen)"
echo ""
echo "Current GUIDs in wix.json:"
echo "upgrade-code: $(grep -oP '"upgrade-code":\s*"\K[^"]+' wix.json)"
echo "files.guid: $(grep -oP '"guid":\s*"\K[^"]+' wix.json | head -1)"
echo "env.guid: $(grep -oP '"guid":\s*"\K[^"]+' wix.json | tail -2 | head -1)"
echo "shortcuts.guid: $(grep -oP '"guid":\s*"\K[^"]+' wix.json | tail -1)"
