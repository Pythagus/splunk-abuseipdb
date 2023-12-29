#!/bin/bash

COPYFILE_DISABLE=1 tar --exclude-vcs --exclude="__pycache__" --exclude="log" --format ustar -cvzf abuseipdb.tar.gz abuseipdb-app
