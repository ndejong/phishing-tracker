# Phishing Tracker

[![PyPi](https://img.shields.io/pypi/v/phishing-tracker.svg)](https://pypi.python.org/pypi/phishing-tracker/)
[![Python Versions](https://img.shields.io/pypi/pyversions/phishing-tracker.svg)](https://github.com/ndejong/phishing-tracker/)
[![Build Status](https://api.travis-ci.org/ndejong/phishing-tracker.svg?branch=master)](https://travis-ci.org/ndejong/phishing-tracker/)
[![License](https://img.shields.io/github/license/ndejong/phishing-tracker.svg)](https://github.com/ndejong/phishing-tracker)

Utility to manage sets of phishing links making it easier to track their removal progress over time.

Project started out of frustration in dealing over-and-over again with phishing threat-actors and wanting an easy tool
to handle the tracking of these links over time without needing to roll out a full-fledged CERT stack (eg The Hive)

Captures everything per-run in a single JSON file making it easy to compare and track change over time - and integrate
with other tooling if desired.

See examples to get a clear idea on usage and possibilities.

## Features
* Batch mode with `.yml` configuration file
* Single shot mode by passing link/hostname/domain in at cli
* Collects useful reference-information and artifacts per phish link stored in an easy reference json file
* Create rules to define expected (or desired) analyzers output responses
* Easy to re-run and hence re-compare the latest status of phish-links over time
* Debug mode output to STDERR

## Analyzers
* dig-domain - determine domain relative to TLD and collect A, CNAME, NS, MX, TXT records
* dig-hostname - collect hostname A, AAAA, CNAME, NS, MX, TXT records
* http-get - perform http (clear-text) GET request capturing request/response headers and response content
* https-get - as per http-get using HTTPS
* https-certificate - obtain the https SSL certificate and parse certificate attributes 
* smtp-headers - connect to hostname/domain MX records and capture the server header 
* whois - perform a whois and parse associated attributes

## Analyzers - Todo
* Safe Browsing lookup - https://developers.google.com/safe-browsing/v4/lookup-api
* Virustotal lookup - https://developers.virustotal.com/reference#url-scan

## Install
#### via PyPi
```bash
pip3 install phishing-tracker
```

#### via Source
```bash
git clone https://github.com/ndejong/phishing-tracker
cd phishing-tracker
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
python3 setup.py clean
python3 setup.py test
python3 setup.py install
```

## Project
* [github.com/ndejong/phishing-tracker](https://github.com/ndejong/phishing-tracker)

## Analyzer Response Reports
```dns_domainname_aaaa_record
dns_domainname_a_record
dns_domainname_cname_record
dns_domainname_mx_record
dns_domainname_ns_record
dns_domainname_txt_record
dns_domainname_unknown_tld
dns_hostname_aaaa_record
dns_hostname_a_record
dns_hostname_cname_record
dns_hostname_eq_dns_domainname
dns_hostname_mx_record
dns_hostname_ns_record
dns_hostname_txt_record
http_exception
http_hostname_<statuscode>_response
https_certificate_exception
https_certificate_hostname_mismatch
https_exception
https_hostname_<statuscode>_response
smtp_domainname_active
smtp_exception
smtp_hostname_active
whois_domainname_record
whois_exception
```

## Examples
* [examples01.yml](https://github.com/ndejong/phishing-tracker/blob/master/examples/examples01.yml)


## Authors
[Nicholas de Jong](https://nicholasdejong.com)

## License
BSD-2-Clause - see LICENSE file for full details.
