import json
import sys
import csv
import gzip
import abuseipdb.api
import splunklib.client as client

# Log an error message.
def log(message):
    # Print the message, so that Splunk gets it in the _internal sourcetype.
    print(message)

    # And then add it in a file.
    file = open("alertaction.log", "a")
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
    exit(abuseipdb.api.ERR_MISSING_PARAMETER)

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

    abuseipdb.api.load_api_key(service, app)


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
        load_api_key(app="abuseipdb-app", server_uri=data['server_uri'], session_key=data['session_key'])

        # For each event, report the associated IP.
        for line in results:
            error = None

            final_categories = []
            arr = str(line[categories_idx] if categories_idx is not None else categories).split(',')
            for cat in arr:
                final_categories.append(abuseipdb.api.Categories.get_id(cat, default=cat))

            try:
                abuseipdb.api.call('report', {
                    'ip': line[ipfield_idx] if ipfield_idx is not None else ipfield,
                    'comment': line[comment_idx] if comment_idx is not None else comment,
                    'categories': ",".join(final_categories),
                })
            except abuseipdb.api.AbuseIPDBInvalidParameter: pass
            except abuseipdb.api.AbuseIPDBMissingParameter: pass
            except abuseipdb.api.AbuseIPDBError as e:
                log(str(e))
                exit(abuseipdb.api.ERR_API_ERROR)
            except abuseipdb.api.AbuseIPDBRateLimitReached as e:
                log("API limit reached")
                exit(abuseipdb.api.ERR_API_LIMIT_REACHED)
            except abuseipdb.api.AbuseIPDBUnreachable:
                log("API is unreachable")
                exit(abuseipdb.api.ERR_API_UNREACHABLE)
            except Exception as e:
                log(str(e))
                exit(abuseipdb.api.ERR_UNKNOWN_EXCEPTION)
    else:
        log("Failure: expected argument '--execute'")
else:
    log("Not in __main__. Skipping.")