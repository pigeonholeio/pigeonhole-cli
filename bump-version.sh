#!/bin/bash

# The bump is performed only on the "main" or "master" branch unless a branch is specified with the -b argument
# Example :
#    bump-version -b staging


# Check that HEAD is not detached
DETACHED=`git branch --show-current | wc -l`
if [ $DETACHED -eq 0 ]; then
    echo "HEAD is detached. Please fix it before."
    exit 1
fi

BUILD_BRANCH=''

# Check if a branch was passed as an argument
while getopts "b:" option
do
    case $option in
        b)
            BUILD_BRANCH=$OPTARG
            ;;
    esac
done

# Determines the build branch ("main" or "master") if no branch was passed as an argument
if [ -z "$BUILD_BRANCH" ]; then
    if [ `git rev-parse --verify main 2>/dev/null` ]
    then
        BUILD_BRANCH='main'
    else
        if [ `git rev-parse --verify master 2>/dev/null` ]
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

# Guess the next tag
if [[ "$(git tag --merged $BUILD_BRANCH)" ]]; then
    # increment the last tag
    NEXT_TAG=`git describe --tags --abbrev=0 | awk -F. '{OFS="."; $NF+=1; print $0}'`
else
    # there is no tag yet
    NEXT_TAG='0.1.0'
fi

# Ask for next tag
SEMVER_REGEX="^[vV]?(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(\\-[0-9A-Za-z-]+(\\.[0-9A-Za-z-]+)*)?(\\+[0-9A-Za-z-]+(\\.[0-9A-Za-z-]+)*)?$"
SEMVER_VALID=false
TAG=$NEXT_TAG
# while [[ $SEMVER_VALID == false ]]
# do
#     read -p "Next tag [$NEXT_TAG]: " TAG
#     # empty answer
#     if [ -z "$TAG" ]; then
#         # set guessed tag
#         TAG=$NEXT_TAG
#     fi
#     # semver validation
#     if [[ "$TAG" =~ $SEMVER_REGEX ]]; then
#         SEMVER_VALID=true
#     else
#         echo 'Tag must match the semver scheme X.Y.Z[-PRERELEASE][+BUILD]. See https://semver.org/'
#     fi
# done

# Release message
if [[ $TAG =~ ^[v] ]]; then
    # remove "v" letter
    MESSAGE="release ${TAG:1:${#TAG}-1}"
else
    MESSAGE="release $TAG"
fi

# Checks if a commit is needed
if [ -n "$(git status --porcelain)" ]; then
    git add -A .
    git commit -am "bump version"
fi

git tag -a "$TAG" -m "$MESSAGE"

# Ask to push new release
# read -p "Push new release (Y/n)? [Y]:" -r
REPLY=${REPLY:-Y}
if [[ $REPLY =~ ^[YyOo]$  ]]; then
  git push origin $BUILD_BRANCH --follow-tags
fi

exit 0
