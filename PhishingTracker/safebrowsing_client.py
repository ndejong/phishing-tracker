
from . import NAME
from . import VERSION

# ===
# Credit
# ===
# The Hive - Cortex-Analyzers - GoogleSafebrowsing
# https://github.com/TheHive-Project/Cortex-Analyzers/tree/master/analyzers/GoogleSafebrowsing
# ===

import json
import requests


class SearchTypeNotSupportedError(Exception):
    pass


class SafebrowsingClient:

    def __init__(self, key):
        self.api_key = key
        self.url = 'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={}'.format(key)
        self.client_id = NAME
        self.client_version = VERSION

    def __prepare_body(self, search_value, search_type='url'):

        body = {
            'client': {
                'clientId': self.client_id,
                'clientVersion': self.client_version
            }
        }

        if search_type == 'url':
            data = {
                'threatTypes': ['THREAT_TYPE_UNSPECIFIED', 'MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
                'platformTypes': ['PLATFORM_TYPE_UNSPECIFIED', 'ANY_PLATFORM'],
                'threatEntryTypes': ['URL']
            }
        else:
            raise SearchTypeNotSupportedError('Currently supported search types are \'url\'.')

        data['threatEntries'] = [{'url': search_value}]
        body['threatInfo'] = data
        return body

    def __query_safebrowsing(self, search_value, search_type='url'):

        headers = {
            'User-Agent': '{}/{}'.format(NAME, VERSION)
        }

        r = requests.post(
            self.url,
            headers=headers,
            json=self.__prepare_body(search_value=search_value, search_type=search_type),
        )

        return r.json()

    def query_url(self, url):
        return self.__query_safebrowsing(search_value=url)

    # TODO: Add another function for querying IPs
    def query_ip(self, ip):
        pass
