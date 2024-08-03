#!/bin/bash
#
# This script builds the app's TarGZ file used to
# update the application's code in SplunkBase.
#
# Author: Damien MOLINA
# Date: 2024-08-03

# The file name of the generated application.
OUTPUT_FILE=abuseipdb.tar.gz

# If the output file already exists, then
# delete it to generate a new one.
if [ -f $OUTPUT_FILE ] ; then
    rm $OUTPUT_FILE
fi

# Generate the new export.
COPYFILE_DISABLE=1 tar --exclude-vcs --exclude="__pycache__" --exclude="log" --format ustar -cvzf abuseipdb.tar.gz abuseipdb-app
