#!/bin/bash

# The bump is performed only on the "main" or "master" branch unless a branch is specified with the -b argument
# Reads version from artefact.yml as source of truth and updates it on bump
# Example:
#    ./bump-version.sh -v 1.2.48      # Bump to specific version
#    ./bump-version.sh                # Auto-increment patch version
#    ./bump-version.sh -b staging     # Use staging branch instead

# Check that HEAD is not detached
DETACHED=$(git branch --show-current | wc -l)
if [ $DETACHED -eq 0 ]; then
    echo "HEAD is detached. Please fix it before."
    exit 1
fi

BUILD_BRANCH=''
MANUAL_VERSION=''

# Check if arguments were passed
while getopts "b:v:" option
do
    case $option in
        b)
            BUILD_BRANCH=$OPTARG
            ;;
        v)
            MANUAL_VERSION=$OPTARG
            ;;
    esac
done

# Determine build branch ("main" or "master") if no branch was passed as an argument
if [ -z "$BUILD_BRANCH" ]; then
    if [ "$(git rev-parse --verify main 2>/dev/null)" ]
    then
        BUILD_BRANCH='main'
    else
        if [ "$(git rev-parse --verify master 2>/dev/null)" ]
        then
            BUILD_BRANCH='master'
        else
            echo "Unable to find \"main\" or \"master\" branch. Please use -b arg"
            exit 1
        fi
    fi
fi

# Check that local is not behind origin
git fetch 2>/dev/null
if [ "$(git rev-list --count HEAD..$BUILD_BRANCH)" -gt 0 ]; then
    echo "Local is behind Origin. Please run git pull first."
    exit 1
fi

# Read current version from artefact.yml
CURRENT_VERSION=$(yq eval '.metadata.version' artefact.yml)

if [ -z "$CURRENT_VERSION" ]; then
    echo "Error: Could not read version from artefact.yml"
    exit 1
fi

# Determine next version
if [ -n "$MANUAL_VERSION" ]; then
    NEXT_TAG=$MANUAL_VERSION
else
    # Auto-increment patch version
    NEXT_TAG=$(echo $CURRENT_VERSION | awk -F. '{OFS="."; $NF+=1; print $0}')
fi

echo "Current version: $CURRENT_VERSION"
echo "Next version: $NEXT_TAG"

# Validate semver
SEMVER_REGEX="^[vV]?(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(\\-[0-9A-Za-z-]+(\\.[0-9A-Za-z-]+)*)?(\\+[0-9A-Za-z-]+(\\.[0-9A-Za-z-]+)*)?$"
if ! [[ "$NEXT_TAG" =~ $SEMVER_REGEX ]]; then
    echo 'Version must match semver scheme X.Y.Z[-PRERELEASE][+BUILD]'
    exit 1
fi

TAG=$NEXT_TAG

# Update artefact.yml with new version
yq eval ".metadata.version = \"$TAG\"" -i artefact.yml

# Update version.go with new version (keep in sync)
sed -i.bak "s/Version *= *\"[^\"]*\"/Version = \"$TAG\"/" src/cmd/version.go
rm -f src/cmd/version.go.bak

# Release message
if [[ $TAG =~ ^[v] ]]; then
    # remove "v" letter
    MESSAGE="release ${TAG:1:${#TAG}-1}"
else
    MESSAGE="release $TAG"
fi

# Commit changes
git add artefact.yml src/cmd/version.go
git commit -m "bump version to $TAG"

# Create git tag
git tag -a "$TAG" -m "$MESSAGE"

# Push changes and tags
# read -p "Push new release (Y/n)? [Y]:" -r
REPLY=${REPLY:-Y}
if [[ $REPLY =~ ^[YyOo]$ ]]; then
  git push origin $BUILD_BRANCH --follow-tags
fi

echo "✅ Version bumped to $TAG"
exit 0
