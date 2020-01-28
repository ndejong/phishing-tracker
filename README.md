# Phishing Tracker

[![PyPi](https://img.shields.io/pypi/v/phishing-tracker.svg)](https://pypi.python.org/pypi/phishing-tracker/)
[![Python Versions](https://img.shields.io/pypi/pyversions/phishing-tracker.svg)](https://github.com/ndejong/phishing-tracker/)
[![Build Status](https://api.travis-ci.org/ndejong/phishing-tracker.svg?branch=master)](https://travis-ci.org/ndejong/phishing-tracker/)
[![License](https://img.shields.io/github/license/ndejong/phishing-tracker.svg)](https://github.com/ndejong/phishing-tracker)

Utility to manage sets of phishing links making it easier to track their removal progress over time.

## Features
* Batch mode with `.yml` configuration file
* Single shot mode by passing link/hostname/domain in at cli
* Collects useful reference-information and artifacts per phish link stored in an easy reference json file
* Create rules to define expected (or desired) analyzers output responses
* Easy to re-run and hence re-compare the latest status of phish-links over time
* Debug mode output to STDERR

## Analyzers
* dig-domain - determine domain relative to TLD and collect A, CNAME, NS, MX, TXT records
* dig-hostname - collect A, AAAA, CNAME, NS, MX, TXT records
* http-get - perform http (clear-text) GET request capturing request/response headers and response content
* https-get - perform same as per http-get using HTTPS
* https-certificate - obtain the https SSL certificate and parse attributes 
* smtp-headers - connect to hostname/domain MX records and capture the server header 
* whois - perform a whois and parse associated attributes

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

## Examples
Pending

****

## Authors
[Nicholas de Jong](https://nicholasdejong.com)

## License
BSD-2-Clause - see LICENSE file for full details.
