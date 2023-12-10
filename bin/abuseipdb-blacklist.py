#!/usr/bin/env python

import os
import sys
import abuseipdb

# Add the Splunk internal library
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option, validators


@Configuration()
class AbuseIPDBBlacklistCommand(GeneratingCommand):

    confidence = Option(
        doc='''
            **Syntax:** **confidence=***<integer>*
            **Description:** Minimum confidence level''',
        require=False, validate=validators.Integer(0), default=100)
    
    limit = Option(
        doc='''
            **Syntax:** **limit=***<integer>*
            **Description:** maximum number of IP to get''',
        require=False, validate=validators.Integer(1))
    
    ipVersion = Option(
        doc='''
            **Syntax:** **ipVersion=***<4|6|mixed>*
            **Description:** number of days for the oldest report''',
        require=False, validate=validators.Match("IP version (4, 6 or mixed)", "^(4|6|mixed)$"), default="mixed")
    
    onlyCountries = Option(
        doc='''
            **Syntax:** **onlyCountries=***<string>*
            **Description:** get the IP addresses of a specific country (separated by comma)''',
        require=False)
    
    exceptCountries = Option(
        doc='''
            **Syntax:** **exceptCountries=***<string>*
            **Description:** remove specific countries from the blacklisted IP addresses list (separated by comma)''',
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
        
    # This is the method treating all the events.
    def generate(self):
        try:
            # Let's make an HTTP request!
            response = abuseipdb.api('blacklist', {
                'confidenceMinimum': self.confidence,
                'limit': self.limit,
                'onlyCountries': self.onlyCountries,
                'exceptCountries': self.exceptCountries,
                'ipVersion': self.ipVersion,
            })

            for data in response['data']:
                yield {
                    'ip': data['ipAddress'],
                    'country': data['ipAddress'],
                    'abuseScore': data['abuseConfidenceScore'],
                    'lastReportedAt': data['lastReportedAt'],
                }
        except abuseipdb.AbuseIPDBRateLimitReached as e:
            self.write_warning("AbuseIPDB API rate limit reached")
        except abuseipdb.AbuseIPDBInvalidParameter as e:
            self.write_warning(str(e))
        except Exception as e:
            self.error_exit(None, str(e))
            return


# Finally, say to Splunk that this command exists.
dispatch(AbuseIPDBBlacklistCommand, sys.argv, sys.stdin, sys.stdout, __name__)
