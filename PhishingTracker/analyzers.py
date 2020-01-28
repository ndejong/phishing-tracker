
from . import PhishingTrackerCertificate
from . import PhishingTrackerDig
from . import PhishingTrackerSmtp
from . import PhishingTrackerWeb
from . import PhishingTrackerWhois

import copy


class PhishingTrackerAnalyzers:

    def __init__(self, __logger=None):
        global logger
        logger = __logger

    def analyzers(self, data, analyzers=None):

        logger.info('analyzers: {}'.format(', '.join(analyzers)))

        analyzer_data = {}

        if 'whois' in analyzers:
            logger.debug('whois analyzer: {}'.format(data['meta']['domain_name']))
            analyzer_data['whois'] = PhishingTrackerWhois.analyzer(data['meta']['domain_name'])

        if 'dig' in analyzers or 'smtp' in analyzers:
            analyzer_data['dig'] = {}

            logger.debug('dig-domain analyzer: {}'.format(data['meta']['domain_name']))
            if data['meta']['domain_name'] is not None:
                analyzer_data['dig']['domain_name'] = PhishingTrackerDig.analyzer(record=data['meta']['domain_name'])

            if data['meta']['host_name'] != data['meta']['domain_name'] and data['meta']['domain_name'] is not None:
                logger.debug('dig-host analyzer: {}'.format(data['meta']['host_name']))
                if data['meta']['host_name'] is not None:
                    analyzer_data['dig']['host_name'] = PhishingTrackerDig.analyzer(record=data['meta']['host_name'])

        if 'smtp' in analyzers and 'dig' in analyzer_data:
            analyzer_data['smtp'] = {}
            if 'domain_name' in analyzer_data['dig'] and analyzer_data['dig']['domain_name'] is not None and len(analyzer_data['dig']['domain_name']['MX']) > 0:
                logger.debug('smtp-domain analyzer: {}'.format(', '.join(analyzer_data['dig']['domain_name']['MX']) ))
                analyzer_data['smtp']['domain_name'] = PhishingTrackerSmtp.analyzer(analyzer_data['dig']['domain_name']['MX'])
            if 'host_name' in analyzer_data['dig'] and len(analyzer_data['dig']['host_name']['MX']) > 0:
                logger.debug('smtp-host analyzer: {}'.format(', '.join(analyzer_data['dig']['host_name']['MX']) ))
                analyzer_data['smtp']['host_name'] = PhishingTrackerSmtp.analyzer(analyzer_data['dig']['host_name']['MX'])

        http_url = data['meta']['url_decode']
        if http_url.startswith('https://'):
            http_url = http_url.replace('https://', 'http://')

        https_url = data['meta']['url_decode']
        if https_url.startswith('http://'):
            https_url = https_url.replace('http://', 'https://')

        if 'http' in analyzers:
            logger.debug('http-get analyzer: {}'.format(http_url))
            analyzer_data['http'] = PhishingTrackerWeb.analyzer(url=http_url)

        if 'https' in analyzers or 'https_certificate' in analyzers:
            logger.debug('https-get analyzer: {}'.format(https_url))
            analyzer_data['https'] = PhishingTrackerWeb.analyzer(url=https_url)

        if 'https_certificate' in analyzers:
            logger.debug('https-certificate analyzer: {}'.format(https_url))
            analyzer_data['https_certificate'] = PhishingTrackerCertificate.analyzer(hostname=data['meta']['host_name'])

        return copy.copy(analyzer_data)

    def analyzers_report(self, data, analyzer_report_sets_expected=None, analyzer_report_sets_not_expected=None):

        status = []
        analyzers_data = data['analyzers']

        if 'dig' in analyzers_data:
            if 'host_name' in analyzers_data['dig'] and analyzers_data['dig']['host_name'] is not None:
                if len(analyzers_data['dig']['host_name']['A']) > 0:
                    status.append('dns_hostname_a_record')
                if len(analyzers_data['dig']['host_name']['AAAA']) > 0:
                    status.append('dns_hostname_aaaa_record')
                if len(analyzers_data['dig']['host_name']['CNAME']) > 0:
                    status.append('dns_hostname_cname_record')
                if len(analyzers_data['dig']['host_name']['MX']) > 0:
                    status.append('dns_hostname_mx_record')
                if len(analyzers_data['dig']['host_name']['NS']) > 0:
                    status.append('dns_hostname_ns_record')
                if len(analyzers_data['dig']['host_name']['TXT']) > 0:
                    status.append('dns_hostname_txt_record')

            if 'domain_name' in analyzers_data['dig'] and analyzers_data['dig']['domain_name'] is not None:
                if len(analyzers_data['dig']['domain_name']['A']) > 0:
                    status.append('dns_domainname_a_record')
                if len(analyzers_data['dig']['domain_name']['AAAA']) > 0:
                    status.append('dns_domainname_aaaa_record')
                if len(analyzers_data['dig']['domain_name']['CNAME']) > 0:
                    status.append('dns_domainname_cname_record')
                if len(analyzers_data['dig']['domain_name']['MX']) > 0:
                    status.append('dns_domainname_mx_record')
                if len(analyzers_data['dig']['domain_name']['NS']) > 0:
                    status.append('dns_domainname_ns_record')
                if len(analyzers_data['dig']['domain_name']['TXT']) > 0:
                    status.append('dns_domainname_txt_record')

        if data['meta']['host_name'] == data['meta']['domain_name']:
            if len(data['meta']['domain_name']) > 0:
                status.append('dns_hostname_eq_dns_domainname')
            else:
                status.append('dns_domainname_unknown_tld')

        if 'http' in analyzers_data:
            if 'exception' in analyzers_data['http']:
                status.append('http_exception')
            if 'response' in analyzers_data['http'] and 'status_code' in analyzers_data['http']['response']:
                status.append('http_hostname_{}_response'.format(analyzers_data['http']['response']['status_code']))

        if 'https' in analyzers_data:
            if 'exception' in analyzers_data['https']:
                status.append('https_exception')
            if 'response' in analyzers_data['https'] and 'status_code' in analyzers_data['https']['response']:
                status.append('https_hostname_{}_response'.format(analyzers_data['https']['response']['status_code']))

        if 'https_certificate' in analyzers_data:
            if 'exception' in analyzers_data['https_certificate']:
                status.append('https_certificate_exception')
            https_certificate_names = []
            if 'subject' in analyzers_data['https_certificate'] and 'commonName' in analyzers_data['https_certificate']['subject']:
                https_certificate_names.append(analyzers_data['https_certificate']['subject']['commonName'])
            if 'subjectAltName' in analyzers_data['https_certificate'] and 'DNS' in analyzers_data['https_certificate']['subjectAltName']:
                https_certificate_names.extend(analyzers_data['https_certificate']['subjectAltName']['DNS'])
            https_certificate_name_found = False
            for https_certificate_name in https_certificate_names:
                if https_certificate_name == '*.{}'.format(data['meta']['domain_name']) or https_certificate_name == data['meta']['host_name']:
                    https_certificate_name_found = True
                    break
            if https_certificate_name_found is False:
                status.append('https_certificate_hostname_mismatch')

        if 'smtp' in analyzers_data:
            if 'exception' in analyzers_data['smtp']:
                status.append('smtp_exception')
            if 'domain_name' in analyzers_data['smtp'] and analyzers_data['smtp']['domain_name'] is not None and len(analyzers_data['smtp']['domain_name']) > 0:
                for item_k, item_v in analyzers_data['smtp']['domain_name'].items():
                    if 'status_code' in item_v and item_v['status_code'] in [220]:
                        if 'smtp_domainname_active' not in status:
                            status.append('smtp_domainname_active')
            if 'host_name' in analyzers_data['smtp'] and analyzers_data['smtp']['host_name'] is not None and len(analyzers_data['smtp']['host_name']) > 0:
                for item_k, item_v in analyzers_data['smtp']['host_name'].items():
                    if 'status_code' in item_v and item_v['status_code'] in [220]:
                        if 'smtp_hostname_active' not in status:
                            status.append('smtp_hostname_active')

        if 'whois' in analyzers_data:
            if 'exception' in analyzers_data['whois']:
                status.append('whois_exception')
            else:
                status.append('whois_domainname_record')

        analyzer_report_sets = {
            'expected': None,
            'not_expected': None
        }

        if analyzer_report_sets_expected and type(analyzer_report_sets_expected) is list:
            analyzer_report_sets['expected'] = False
            for item_set in analyzer_report_sets_expected:
                if type(item_set) is str:
                    item_set = [item_set]
                item_set_count = 0
                for item in item_set:
                    if item in status:
                        item_set_count += 1
                if item_set_count == len(item_set):
                    analyzer_report_sets['expected'] = True
                    break

        if analyzer_report_sets_not_expected and type(analyzer_report_sets_not_expected) is list:
            analyzer_report_sets['not_expected'] = False
            for item_set in analyzer_report_sets_not_expected:
                if type(item_set) is str:
                    item_set = [item_set]
                item_set_count = 0
                for item in item_set:
                    if item in status:
                        item_set_count += 1
                if item_set_count == len(item_set):
                    analyzer_report_sets['not_expected'] = True
                    break

        report_data = {
            'reference': data['meta']['reference'],
            'reports': status,
            'analyzer_report_sets': analyzer_report_sets
        }
        return copy.copy(report_data)
