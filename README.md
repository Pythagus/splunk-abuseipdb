# Splunk app for AbuseIPDB
This app was developed by [Damien Molina](https://www.linkedin.com/in/d-molina/). I was trying to use AbuseIPDB public API with Splunk Enterprise, but none of the available applications were doing what I wanted to do, even the official one. So, here it is!

- [How to use](#how-to-use)
    - [`check` command](#command-check)
    - [`report` command](#command-report)
    - [`reports` command](#command-reports)
    - [`blacklist` command](#command-blacklist)
- [Updates](#updates)
- [About this app](#the-end)


# <a id="how-to-use">#</a> How to use it
First thing, here is an exhaustive list of the possible commands this app is supporting.

You can tell the `abuseipdb` command what to do using the `mode` option like `| abuseipdb mode=report`.

**Note:** default mode is `check`

<br>

## <a id="command-check">#</a> Check - Check an IP abuse score
This command retrieves the abuse confidence score of a given IP address.
If the command passes, new fields will be added to every events.

### Parameters
- **mode=check**: The command mode for checking an IP.
- **ip**: An explicit IP address, or a Splunk field name containing the IP.
- **age**: *(optional)* Time range to check the IP on. Integer between `1` and `365`, default is `30`.
- **publiconly**: *(optional)* A boolean to only check public IP addresses for saving some API calls. Default is `False`.

### Examples
In the middle of a search:
```
... | abuseipdb mode=check ip=ip | ...
```

Copy-paste example: (ip option as a field-name)
```
| makeresults
| eval ip_in_event = "64.62.197.152" 
| abuseipdb mode=check ip=ip_in_event
```

That could also have been replaced with: *(ip option as a string)*
```
| abuseipdb mode=check ip="64.62.197.152"
| table *
```

**Note:** You can either pass an IP address (like 127.0.0.1) or a network range (like 192.168.0.0/24) to this command. With a range:

```
| makeresults
| eval range = "64.62.197.152/30" 
| abuseipdb mode=check ip=range age=10
```

<br>

## <a id="command-report">#</a> Report - Report an IP for abusive behavior
This command reports the given IP address for abusive behavior.

### Parameters
- **mode=report**: The command mode for reporting an IP.
- **ip**: An explicit IP address, or a Splunk field name containing the IP.
- **categories**: The abusive categories the IP is matching (separated by comma), as described in [AbuseIPDB documentation](https://www.abuseipdb.com/categories).
- **comment**: A descriptive text of the attack i.e. server logs, port numbers, etc.


### Examples

#### In the middle of a search
```
... | abuseipdb mode=report ip=ip category="1,3" comment="XSS attempts" | ...
```

Copy-paste example:
```
| makeresults
| eval ip_in_event = "127.0.0.2" 
| abuseipdb mode=report ip=ip_in_event categories=2 comment="For a test"
```

But all parameters can be passed from the event:
```
| makeresults
| eval ip_in_event = "127.0.0.2", categories = "1,3", comment = "For testing purpose"
| abuseipdb mode=report ip=ip_in_event categories=categories comment=comment
```

**Note::** be sure to not send any personally identifiable message in the `comment` field.

<br>

## <a id="command-reports">#</a> Reports - See reports of a given IP
This command gathers all reports sent regarding a given IP address.

### Parameters
- **mode=reports**: The command mode for getting the reports an IP
- **ip**: An explicit IP address, or a Splunk field name containing the IP
- **age**: *(optional)* Time range to check the IP on. Integer between `1` and `365`, default is `30`.


### Examples
This search must be used on the top-level search.
```
| abuseipdb mode=reports ip="64.62.197.152"
| table *
```

Example with the categories:
```
| abuseipdb mode=reports ip="64.62.197.152" age=10
| table *
| makemv delim="," abuseipdb_categories 
| lookup AbuseIPDB_Categories id as abuseipdb_categories
```

<br>

## <a id="command-blacklist">#</a> Blacklist - Get all IP with a confidence score
This command gets all the IP addresses with a specific confidence score and upper.

### Parameters
- **mode=blacklist**: The command mode for getting a list of the most abusive IP addresses.
- **confidence**: The minimum confidence score to request (integer between 1 and 100).
- **limit**: *(optional)* The maximum number of requests to request to the API. Default: `100`.
- **ipVersion**: *(optional)* What IP versions should only be requested. Possible values: `4`, `6` or `mixed` (both 4 and 6). Default: `mixed`.
- **onlyCountries**: *(optional)* Specific countries to request only, separated by comma.
- **exceptCountries**: *(optional)* Remove some countries from the API request, separated by comma.

**Note:** the number of returned results mainly depends on your subscription. See AbuseIPDB website to have more details.

### Examples
For example, if you want to get all IP addresses with at least 90% of abuse confidence score: (90% and higher)
```
| abuseipdb mode=blacklist confidence=90
| table *
```

# <a id="updates">#</a> Updates
This section focuses on updating the application.

## <a id="update-lookup">#</a> Update the AbuseIPDB_Categories lookup
I didn't find a "programmatic" way to update the lookup, as AbuseIPDB is only giving an HTML array... So, the best way I found for now is to use the following `JavaScript` code in the 

```js
var categories = "\n"
document.querySelectorAll('table tbody tr').forEach(function(tr) {
    var td = tr.querySelectorAll('td')
    categories +=  td[0].innerText + ',"' + td[1].innerText + '","' + td[2].innerText + '"' + "\n"
}) 
```

# About this app <a id="the-end"></a>
You are welcome to contribute to this app by submitting a pull request. I will be very glad to improve this app!