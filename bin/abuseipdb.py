#!/usr/bin/env python

import os
import sys
import ipaddress
import api as abuseipdb

# Add the Splunk internal library
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators

# This cache is used to reduce the number
# of API calls, if the IP was already called before.
IP_CACHE = {}

# This function adds the missing fields after a
# check call.
def _check_ensure_format(data):
    if isinstance(data, list):
        array = []

        for arr in data:
            array.append(_check_ensure_format(arr))

        return array

    return merge_dict(data, {
        "ip": None,
        "type": None,
        "score": None,
        "usage": None,
        "country": None,
        "company": None,
        "domain": None,
        "tor": None,
        "nbrReports": None,
        "lastReported": None,
    }, prefix="")


# This function makes a "check" action
# for the given IP address.
def _check_ip(http_params):
    global IP_CACHE

    ip = http_params['ipAddress']

    # Let's make an HTTP request!
    response = abuseipdb.api('check', http_params)
    json = response['data']
    data = {
        "ip": ip,
        "type": 'Public' if json['isPublic'] else 'Private',
        "score": json['abuseConfidenceScore'],
        "usage": json['usageType'],
        "company": json['isp'],
        "country": json['countryCode'],
        "domain": json['domain'],
        "tor": json['isTor'],
        "nbrReports": json['totalReports'],
        "lastReported": json['lastReportedAt']
    }

    IP_CACHE[ip] = data

    return data

# This function makes a "check" action
# for the given network range.
def _check_range(http_params):
    global IP_CACHE

    range = http_params['network']
 
    # If the IP address contains a "/", then it is a
    # whole network range we need to check. In that case,
    # we need to do a "check-block" operation instead of a
    # simple check.
    response = abuseipdb.api('check-block', http_params)
    json = response['data']

    # If it is a network, we will generate new events
    # for each IP found in the network. The user will
    # be able to merge the data aggregating with the
    # ipfield value.

    # If there are data in the response, then
    # iterate on the result. Else, just return
    # an empty object, so that we keep the initial
    # event intact.
    if json['reportedAddress']:
        data = []

        for values in json['reportedAddress']:
            data.append({
                "ip": values['ipAddress'],
                "nbrReports": values['numReports'],
                "lastReported": values['mostRecentReport'],
                "score": values['abuseConfidenceScore'],
                "country": values['countryCode'],
            })
    else: 
        data = {}

    IP_CACHE[range] = data

    return data

# Merge the two dictionnaries by making
# a fresh new one.
def merge_dict(dict1, dict_abuseipdb, prefix="abuseipdb_"):
    new_dict = {k:v for k, v in dict1.items()}

    for key, value in dict_abuseipdb.items():
        prefixed_key = prefix + key

        if prefixed_key not in new_dict:
            new_dict[prefixed_key] = value
    
    return new_dict

@Configuration()
class AbuseIPDBCommand(StreamingCommand):

    mode = Option(
        doc='''
            **Syntax:** **mode=***<check|blacklist|report>*
            **Description:** Mode used to interact with AbuseIPDB API''',
        require=False, validate=validators.Set('check', 'blacklist', 'report'), default="check")

    ipfield = Option(
        doc='''
            **Syntax:** **ipfield=***<fieldname>*
            **Description:** Name of the field which contains the ip''',
        require=False, validate=validators.Fieldname())
    
    publiconly = Option(
        doc='''
            **Syntax:** **publiconly=***<bool>*
            **Description:** Should only public IP be considered''',
        require=False, validate=validators.Boolean(), default=False)
    
    maxAgeInDays = Option(
        doc='''
            **Syntax:** **maxAgeInDays=***<integer>*
            **Description:** number of days for the oldest report''',
        require=False, validate=validators.Integer(1), default=30)

    confidence = Option(
        doc='''
            **Syntax:** **confidence=***<integer>*
            **Description:** Minimum confidence level''',
        require=False, validate=validators.Integer(0), default=100)
    
    limit = Option(
        doc='''
            **Syntax:** **limit=***<integer>*
            **Description:** maximum number of IP to get''',
        require=False, validate=validators.Integer(1), default=10000)
    
    ipVersion = Option(
        doc='''
            **Syntax:** **ipVersion=***<4|6|mixed>*
            **Description:** number of days for the oldest report''',
        require=False, validate=validators.Set("4", "6", "mixed"), default="mixed")
    
    onlyCountries = Option(
        doc='''
            **Syntax:** **onlyCountries=***<string>*
            **Description:** get the IP addresses of a specific country (separated by comma)''',
        require=False, default=None)
    
    exceptCountries = Option(
        doc='''
            **Syntax:** **exceptCountries=***<string>*
            **Description:** remove specific countries from the blacklisted IP addresses list (separated by comma)''',
        require=False, default=None)
    
    categories = Option(
        doc='''
            **Syntax:** **categories=***<string>*
            **Description:** malicious pattern categories (separated by comma)''',
        require=False)
    
    comment = Option(
        doc='''
            **Syntax:** **comment=***<string>*
            **Description:** malicious actiivty comment''',
        require=False)     

    # This method is called by splunkd before the
    # command executes. It is used to get the configuration
    # data from Splunk.
    def prepare(self):
        try:
            abuseipdb.prepare(self)
        except Exception as e:
            self.error_exit(None, str(e))
            return
    
    # After this method is called, it ensures that the
    # given parameter is not None.
    def ensureParameter(self, param: str):
        if getattr(self, param) is None:
            raise Exception("AbuseIPDB: field %s required (mode = %s)" % (param, self.mode))

    # Make an API call for checking a given
    # IP address. By the way, it could also
    # be a network range to be checked.
    def check(self, event):
        # First, ensure all the required parameters are given.
        self.ensureParameter('ipfield')
        self.ensureParameter('maxAgeInDays')

        # If there is no IP field at this step, then
        # return an empty array <=> no data retrieved.
        if not self.ipfield in event or event[self.ipfield] is None:
            return {}
        
        ip = event[self.ipfield]
        
        # First, we check whether the IP is already in the
        # cache. If so, we don't need to make an API call.
        if ip in IP_CACHE:
            return IP_CACHE[ip]
        
        # If it is a range, then we have to do
        # a "check-block" call.
        if "/" in ip:
            # If the "public only" flag is set, and the IP is private,
            # then don't do the API call.
            try:
                if self.publiconly and ipaddress.ip_network(ip, strict=False).is_private:
                    return {}
            except ValueError: # Exception raised when the value is not an IP address
                return {}
            
            return _check_range({
                'network': ip,
                'maxAgeInDays': self.maxAgeInDays
            })
        
        # If the "public only" flag is set, and the IP is private,
        # then don't do the API call.
        try:
            if self.publiconly and ipaddress.ip_address(ip).is_private:
                return {}
        except ValueError: # Exception raised when the value is not an IP address
            return {}

        return _check_ip({
            'ipAddress': ip,
            'maxAgeInDays': self.maxAgeInDays
        })
    
    # Get all the IP known for abusive behavior.
    def blacklist(self):
        # First, ensure all the required parameters are given.
        self.ensureParameter('confidence')
        self.ensureParameter('limit')
        self.ensureParameter('ipVersion')

        # Let's make an HTTP request!
        response = abuseipdb.api('blacklist', {
            'confidenceMinimum': self.confidence,
            'limit': self.limit,
            'onlyCountries': self.onlyCountries,
            'exceptCountries': self.exceptCountries,
            'ipVersion': None if self.ipVersion == "mixed" else self.ipVersion,
        })

        values = []
        for data in response['data']:
            values.append({
                'ip': data['ipAddress'],
                'country': data['countryCode'],
                'abuseScore': data['abuseConfidenceScore'],
                'lastReportedAt': data['lastReportedAt'],
            })

        return values
    
    # Report a given IP address as malicious in AbuseIPDB API
    def report(self, event):
        # First, ensure all the required parameters are given.
        self.ensureParameter('ipfield')
        self.ensureParameter('categories')
        self.ensureParameter('comment')

        # Let's make an HTTP request!
        error = None
        json = {}

        try:
            response = abuseipdb.api('report', {
                'ip': event[self.ipfield],
                'categories': self.categories,
                'comment': self.comment,
            })
            json = response['data']
        except abuseipdb.AbuseIPDBError as e:
            error = str(e)

        return {
            'abuseScore': json['abuseConfidenceScore'] if 'abuseConfidenceScore' in json else None,
            'status': 'success' if error is None else 'failure',
            'error': error,
        }
        
    # This is the method treating all the events.
    def stream(self, events):
        # If this is a blacklist call, then we
        # remove all previous events, and put a
        # single empty event.
        if self.mode == "blacklist":
            events = [{}]

        for event in events:
            try:
                data = list()

                # If it is a "check an IP" call.
                if self.mode == "check":
                    data = _check_ensure_format(self.check(event))
                elif self.mode == "blacklist":
                    data = self.blacklist()
                elif self.mode == "report":
                    data = self.report(event)

                data = data if isinstance(data, list) else [data]

                for arr in data:
                    new_event = merge_dict(event, arr)
                    yield new_event
            except abuseipdb.AbuseIPDBRateLimitReached as e:
                self.write_warning("AbuseIPDB API rate limit reached")
                yield event
            except abuseipdb.AbuseIPDBInvalidParameter as e:
                self.write_warning(str(e))
                yield event
            except abuseipdb.AbuseIPDBError as e:
                self.write_warning("AbuseIPDB error: %s" % str(e))
                yield event
            except Exception as e:
                self.error_exit(None, str(e))
                return


# Finally, say to Splunk that this command exists.
dispatch(AbuseIPDBCommand, sys.argv, sys.stdin, sys.stdout, __name__)