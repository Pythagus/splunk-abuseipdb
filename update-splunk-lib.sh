#!/bin/bash
#
# This script updates the Splunk Python libray to
# the given version.
#
# Params:
#   Arg 1: Github branch tag
#
# Author: Damien MOLINA
# Date: 2024-08-03

# Temporary folder in which the Splunk repository
# will be fetched in order to retrieve the Python
# official library.
TEMPORARY_FOLDER="tmp-splunk-lib-repository"

# The current library folder path.
CURRENT_LIB="abuseipdb-app/bin/splunklib"

# The git tag that should be retrieved.
TAG=

# If the temporary folder already exists, then we
# cannot continue this update. So, stop the script.
if [ -d $TEMPORARY_FOLDER ] ; then
    echo "[ERROR] Temporary folder already exists"
    exit 1
fi

# Check whether the "tag" argument was given
# to the script.
if [[ $# -eq 0 ]] ; then
    echo "[ERROR] Missing required argument: tag"
    exit 2
else
    TAG=$1
fi

# Clone the repository in the temporary folder.
git clone https://github.com/splunk/splunk-sdk-python.git --branch "$TAG" $TEMPORARY_FOLDER --quiet -c advice.detachedHead=false

# If the folder doesn't exist, then an error occured.
if [ ! -d $TEMPORARY_FOLDER ] ; then
    echo "ERROR: Git clone failed"
    exit 3
fi

# Remove the old Splunk lib files.
rm -rd $CURRENT_LIB

# Copy the Splunk lib files.
cp -r $TEMPORARY_FOLDER/splunklib $CURRENT_LIB

# Finally, delete the temporary folder.
rm -rfd $TEMPORARY_FOLDER
