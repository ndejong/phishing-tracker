
from .safebrowsing_client import SafebrowsingClient


class PhishingTrackerSafeBrowsing:

    @staticmethod
    def analyzer(url, api_key):

        try:
            data = SafebrowsingClient(key=api_key).query_url(url)
        except Exception as e:
            return {'exception': str(e)}

        return data
