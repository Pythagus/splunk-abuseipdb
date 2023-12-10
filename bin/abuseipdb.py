#!/usr/bin/env python

import requests

# The possible actions that this API supports.
ACTIONS = {
    'check': 'get',
    'report': 'post',
}

# This exception is raised when the API reached its limit.
class AbuseIPDBRateLimitReached(Exception):
    pass

# This exception is raised when an invalid parameter was
# given to the AbuseIPDB API. This should not stop the
# process.
class AbuseIPDBInvalidParameter(Exception):
    pass

# Prepare the API to be used.
def prepare(command):
    global API_KEY

    # Get the API key.
    for passwd in command.service.storage_passwords:
        if passwd.username == "abuseipdb" and (passwd.realm is None or passwd.realm.strip() == ""):
            API_KEY = passwd.clear_password

    # Check whether the API key was retrieved.
    if API_KEY is None or API_KEY == "defaults_empty":
        command.error_exit(None, "No API key found for AbuseIPDB. Re-run the app setup.")
    

# This method makes an API call to the
# AbuseIPDB endpoint.
def api(endpoint, params):
    headers = {
        'Key': API_KEY,
        'Accept': 'application/json'
    }

    # If the action is not known.
    if not endpoint in ACTIONS:
        raise Exception("Action %s not supported" % endpoint)
    
    response = requests.request(ACTIONS[endpoint], 'https://api.abuseipdb.com/api/v2/' + endpoint, headers=headers, params=params)
    json = response.json()

    # As refered in https://docs.abuseipdb.com/#api-daily-rate-limits
    if response.status_code == 429:
        raise AbuseIPDBRateLimitReached()
    
    # When testing, this code is returned for when no token
    # is provided, or if the provided one is invalid.
    if response.status_code == 401:
        raise Exception("Invalid AbuseIPDB token given.")
    
    # If a parameter is invalid.
    if response.status_code == 422:
        details = "" 
        
        try:
            details = str(json['errors'][0]['detail'])
        except:
            details = str(json['errors'])

        raise AbuseIPDBInvalidParameter("AbuseIPDB error: " + details)
    
    # If the response is not succesful
    if response.status_code != 200:
        raise Exception("Got status code %d from AbuseIPDB API." % response.status_code)
    
    return json

