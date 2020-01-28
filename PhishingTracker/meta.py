
import tldextract
from urllib.parse import unquote_plus


class PhishingTrackerMeta:

    @staticmethod
    def meta_data(reference):
        return {
            'reference': reference,
            'host_name': PhishingTrackerMeta.host_name(reference),
            'domain_name': PhishingTrackerMeta.domain_name(reference),
            'url_decode': PhishingTrackerMeta.url_decode(reference),
        }

    @staticmethod
    def domain_name(reference):
        return unquote_plus(tldextract.extract(reference).registered_domain.lower())

    @staticmethod
    def host_name(reference):
        return unquote_plus(tldextract.extract(reference).fqdn.lower())

    @staticmethod
    def url_decode(reference, prefix='https'):

        #  www.foobar.com
        #  www.foobar.com/foo.bar.html
        if not reference.startswith('http'):
            reference = prefix + '://' + reference

        #  //www.foobar.com/foo/bar.html
        if reference.startswith('//'):
            reference = prefix + ':' + reference

        return unquote_plus(reference)
