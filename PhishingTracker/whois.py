
import whois
from . import PhishingTrackerMeta


class PhishingTrackerWhois:

    @staticmethod
    def analyzer(reference):
        try:
            data = dict(whois.whois(PhishingTrackerMeta.domain_name(reference)))
        except Exception as e:
            data = {'exception': str(e)}
        return data
