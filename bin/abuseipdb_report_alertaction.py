import json
import sys
import os
import csv
import gzip
import api as abuseipdb

# Add the Splunk internal library
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import splunklib.client as client

# Possible error codes generated.
ERR_UNKNOWN_EXCEPTION = 1
ERR_API_LIMIT_REACHED = 2

# Log an error message.
def log(message):
    print(message)
    file = open("log/alertaction.log", "a")
    file.write(message + "\n")
    file.close()

# This function opens the results file which is
# like "results.csv.gz". It returns a JSON file
# reader to be easy to iterate on.
def open_result_file(file_name: str):
    return csv.reader(gzip.open(file_name, mode="rt"))

# Get the given parameter in the array.
def get_configuration(data, key):
    try:
        value = data['configuration'][key]

        if value is not None and len(value.strip()) > 0:
            return value
    except: pass

    log("Missing parameter %s" % key)
    sys.exit(1)

# Get the index of the given key in the list.
def get_index(data, key):
    try:
        return data.index(key)
    except:
        return None
    
# Get the cleartext version of the API key.
def load_api_key(app, server_uri, session_key):
    hostname = server_uri.split("://")
    scheme = hostname[0]
    host = hostname[1].split(':')[0]
    port = hostname[1].split(':')[1]
    service = client.connect(scheme=scheme, host=host, port=port, app=app, token=session_key)

    abuseipdb.load_api_key(service, app)


# If this is an execution and not an import.
if __name__ == "__main__":
    # If the command was correctly called by an alert action.
    if len(sys.argv) > 1 and sys.argv[1] == "--execute":
        data = json.loads(sys.stdin.read())

        # Retrieve the main parameters.
        ipfield = get_configuration(data, 'ipfield')
        comment = get_configuration(data, 'comment')
        categories = get_configuration(data, 'categories')

        # Then, get all the results.
        results = open_result_file(data['results_file'])
        header = next(results)

        # Get the possible index of the values in the CSV header.
        ipfield_idx = get_index(header, ipfield)
        comment_idx = get_index(header, comment)
        categories_idx = get_index(header, categories)

        # Retrieve the API key.
        load_api_key(app=data['app'], server_uri=data['server_uri'], session_key=data['session_key'])

        # For each event, report the associated IP.
        for line in results:
            try:
                abuseipdb.api('report', {
                    'ip': line[ipfield_idx] if ipfield_idx is not None else ipfield,
                    'comment': line[comment_idx] if comment_idx is not None else comment,
                    'categories': line[categories_idx] if categories_idx is not None else categories,
                })
            except abuseipdb.AbuseIPDBError: pass
            except abuseipdb.AbuseIPDBInvalidParameter: pass
            except abuseipdb.AbuseIPDBMissingParameter: pass
            except abuseipdb.AbuseIPDBRateLimitReached as e:
                log("API limit reached")
                exit(ERR_API_LIMIT_REACHED)
            except Exception as e:
                log(str(e))
                exit(ERR_UNKNOWN_EXCEPTION)
    else:
        log("Failure: expected argument '--execute'")
else:
    log("Not in __main__. Skipping.")