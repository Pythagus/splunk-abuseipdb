#!/usr/bin/env python

import requests

# The API key used to authenticate to AbuseIPDB API.
API_KEY = None

# The possible actions that this API supports.
ACTIONS = {
    'blacklist': 'get',
    'check': 'get',
    'check-block': 'get',
    'report': 'post',
    'reports': 'get',
}

# This exception is raised when the API reached its limit.
class AbuseIPDBRateLimitReached(Exception): pass

# This exception is raised when an invalid parameter was
# given to the AbuseIPDB API. This should not stop the
# process.
class AbuseIPDBInvalidParameter(Exception): pass

# This exception is raised when AbuseIPDB API returned
# an error when we called an endpoint.
class AbuseIPDBError(Exception): pass

# This exception is raised when AbuseIPDB API returned
# an error when we called an endpoint.
class AbuseIPDBMissingParameter(Exception): pass

# Get the key from the given service for
# the given app.
def load_api_key(service, app):
    global API_KEY
    
    key = None

    for passwd in service.storage_passwords:
        if passwd.username == app and (passwd.realm is None or passwd.realm.strip() == ""):
            key = passwd.clear_password

            if key == "defaults_empty":
                key = None

    API_KEY = key

# Prepare the API to be used.
def prepare(command):
    # Get the API key.
    load_api_key(service=command.service, app="abuseipdb")

    # Check whether the API key was retrieved.
    if API_KEY is None:
        command.write_error(None, "No API key found for AbuseIPDB. Re-run the app setup.")
        exit(1)
    
# This function returns the details response
# provided by AbuseIPDB API
def _get_http_response_details(json, key = 'detail'):
    details = "" 
        
    try:
        details = str(json['errors'][0][key])
    except:
        details = str(json['errors'])

    return details

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
        # In some cases, a 429 error is returned, but with
        # a different status code inside the error details.
        # So, we are managing the responses differently.
        if int(_get_http_response_details(json, 'status')) == 403:
            raise AbuseIPDBError(_get_http_response_details(json))
        else:
            raise AbuseIPDBRateLimitReached()
    
    # When testing, this code is returned for when no token
    # is provided, or if the provided one is invalid.
    if response.status_code == 401:
        raise AbuseIPDBError("Invalid AbuseIPDB token given.")
    
    # When a parameter is only available for paid AbuseIPDB
    # licence, an HTTP 402 response is returned.
    if response.status_code == 402:
        raise AbuseIPDBInvalidParameter(_get_http_response_details(json))
    
    # If a parameter is invalid.
    if response.status_code == 422:
        raise AbuseIPDBError(_get_http_response_details(json))
    
    # If the response is not succesful
    if response.status_code != 200:
        raise AbuseIPDBError("Got status code %d" % response.status_code)
    
    return json

class Categories:

    # This is the list of allowed categories, as
    # described in https://www.abuseipdb.com/categories.
    VALUES = {
        "1": "DNS Compromise",
        "2": "DNS Poisoning",
        "3": "Fraud Orders",
        "4": "DDoS Attack",
        "5": "FTP Brute-Force",
        "6": "Ping of Death",
        "7": "Phishing",
        "8": "Fraud VoIP",
        "9": "Open Proxy",
        "10": "Web Spam",
        "11": "Email Spam",
        "12": "Blog Spam",
        "13": "VPN IP",
        "14": "Port Scan",
        "15": "Hacking",
        "16": "SQL Injection",
        "17": "Spoofing",
        "18": "Brute-Force",
        "19": "Bad Web Bot",
        "20": "Exploited Host",
        "21": "Web App Attack",
        "22": "SSH",
        "23": "IoT Targeted",
    }

    # Get the id behind the given category.
    def get_id(category, default = None):
        category = str(category).strip()
        values = list(Categories.VALUES.values())
        keys = list(Categories.VALUES.keys())

        if category in values:
            return keys[values.index(category)]
        
        return default
    
    # Get the category associated to the given id.
    def get_category(category_id, default=None):
        category_id = str(category_id).strip()

        if category_id in Categories.VALUES:
            return Categories.VALUES[category_id]
        
        return default
