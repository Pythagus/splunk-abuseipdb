#!/usr/bin/env python

import os
import sys
import abuseipdb

# Add the Splunk internal library
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators

# This cache is used to reduce the number
# of API calls, if the IP was already called before.
ip_cache = {}

# This function makes a "check" action
# for the given IP address.
def _check(http_params):
    global ip_cache

    ip = http_params['ipAddress']

    # First, we check whether the IP is already in the
    # cache. If so, we don't need to make an API call.
    if ip in ip_cache:
        return ip_cache[ip]

    # Else, let's make an HTTP request!
    response = abuseipdb.api('check', http_params)

    json = response['data']
    data = {
        "type": 'Public' if json['isPublic'] else 'Private',
        "score": json['abuseConfidenceScore'],
        "country": json['countryName'] + " (" + json['countryCode'] + ")",
        "usage": json['usageType'],
        "company": json['isp'],
        "domain": json['domain'],
        "tor": json['isTor'],
        "nbrReports": json['totalReports'],
        "lastReported": json['lastReportedAt']
    }

    ip_cache[ip] = data

    return data

@Configuration()
class AbuseIPDBCheckCommand(StreamingCommand):

    ipfield = Option(
        doc='''
            **Syntax:** **ip=***<fieldname>*
            **Description:** Name of the field which contains the ip''',
        require=True, validate=validators.Fieldname())
    
    maxAgeInDays = Option(
        doc='''
            **Syntax:** **maxAgeInDays=***<integer>*
            **Description:** number of days for the oldest report''',
        require=False, validate=validators.Integer(1), default=90)           

    # This method is called by splunkd before the
    # command executes. It is used to get the configuration
    # data from Splunk.
    def prepare(self):
        try:
            abuseipdb.prepare(self)
        except Exception as e:
            self.error_exit(None, str(e))
            return
        
    # This is the method treating all the events.
    def stream(self, events):
        for event in events:
            try:
                data = _check({
                    'ipAddress': event[self.ipfield],
                    'maxAgeInDays': self.maxAgeInDays,
                    'verbose': None,
                })

                if data is not None:
                    for key in data:
                        event["abuseipdb_" + key] = data[key]
            except abuseipdb.AbuseIPDBRateLimitReached as e:
                self.write_warning("AbuseIPDB API rate limit reached")
            except abuseipdb.AbuseIPDBInvalidParameter as e:
                self.write_warning(str(e))
            except Exception as e:
                self.error_exit(None, str(e))
                return
            
            yield event


# Finally, say to Splunk that this command exists.
dispatch(AbuseIPDBCheckCommand, sys.argv, sys.stdin, sys.stdout, __name__)
