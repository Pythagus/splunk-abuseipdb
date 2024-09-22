from . import api
from datetime import datetime
from splunklib.binding import HTTPError
import json


# Name of the cache (kv-store) used to store IP details.
IP_CACHE = "AbuseIPDB_Cache_IP"

# Get the current date to keep in mind when the records
# were inserted.
def get_current_date():
    return int(datetime.now().replace(second=0, microsecond=0).timestamp())

# This class will help this script communicating with
# the Splunk KV-store instance.
class IpCache:

    # Initialize the cache.
    # service: Splunk service instance.
    def __init__(self, service, name):
        # Cache TTL.
        self.ttl = int(api.get_config(service, "cache", "ttl"))

        try:
            self.kvstore = service.kvstore[name]
        except KeyError as e:
            raise api.AbuseIPDBCacheNotFound(name) from e

    # Remove old entries from the kv-store.
    def clean(self):
        limit_date = get_current_date() - self.ttl

        self.kvstore.data.delete(json.dumps({
            "record_date": {"$lt": limit_date}
        }))

    # Get the data cached in the KV-store, or return None
    # if the record doesn't exist.
    def get(self, ip):
        try:
            results = self.kvstore.data.query(query=json.dumps({
                "_key": ip
            }))

            if len(results) > 0:
                return results[0]
        except HTTPError: pass
        
        return None

    # Store the data of the given IP.
    def store(self, ip, data):
        # Insert the ip as the _key.
        data['_key'] = ip

        # Add the insertion date.
        data['record_date'] = get_current_date()

        # Finally save the record.
        self.kvstore.data.batch_save(*[data])