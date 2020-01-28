
import requests
from .useragent import user_agent

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class PhishingTrackerWeb:

    @staticmethod
    def analyzer(url):

        headers = {
            'User-Agent': user_agent(),
            'Cache-Control': 'no-cache'
        }

        try:
            r = requests.get(url, headers=headers, verify=False, allow_redirects=False)
        except Exception as e:
            return {'exception': str(e)}

        data = {
            'request': {
                'url': url,
                'headers': dict(r.request.headers),
            },
            'response': {
                'status_code': r.status_code,
                'headers': dict(r.headers),
                'text': r.text,
            }
        }

        return data
