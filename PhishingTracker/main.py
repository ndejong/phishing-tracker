
from . import NAME
from . import VERSION
from . import analyzers_available

from .util import json_dumps
from .util import timestamp

from . import PhishingTrackerLogger
from . import PhishingTrackerFile
from . import PhishingTrackerMeta
from . import PhishingTrackerAnalyzers

from . import PhishingTrackerTests


class PhishingTracker:

    debug = None

    def __init__(self, debug=False):

        self.debug = debug

        log_level = 'info'
        if self.debug:
            log_level = 'debug'

        global logger
        logger = PhishingTrackerLogger(level=log_level).logger
        logger.info('{} v{}'.format(NAME, VERSION))

    def main(self, reference=None, filename=None, pathname=None, analyzers=None):

        ts = timestamp()

        if reference is not None:
            self.playbook(reference, analyzers, None, pathname, ts)

        elif filename is not None:
            for item in PhishingTrackerFile(logger).load_config(filename=filename).items():
                if type(item) is not tuple:
                    logger.error('Item found in file is unsupported format: {}'.format(str(item)))
                else:
                    item_analyzers = analyzers
                    item_reference, item_config = item
                    if item_config is None or 'enabled' not in item_config.keys() or \
                            ('enabled' in item_config and item_config['enabled']):
                        self.playbook(item_reference, item_analyzers, item_config, pathname, ts)
        return

    def playbook(self, reference, analyzers, config, pathname, ts):

        # meta
        data = { 'meta': PhishingTrackerMeta.meta_data(reference=reference) }

        logger.info('reference: {}'.format(data['meta']['reference']))
        logger.debug('host_name: {}'.format(data['meta']['host_name']))
        logger.debug('domain_name: {}'.format(data['meta']['domain_name']))
        logger.debug('url_decode: {}'.format(data['meta']['url_decode']))

        # analyzers setup
        if analyzers is None or (type(analyzers) is list and analyzers[0] is None):
            if type(config) is dict and 'analyzers' in config.keys():
                analyzers = config['analyzers']
            else:
                analyzers = analyzers_available
        if 'all' in analyzers:
            analyzers = analyzers_available

        # analyzers
        data['analyzers'] = PhishingTrackerAnalyzers(logger).analyzers(data=data, analyzers=analyzers)

        # analyzer_report_sets_expected setup
        if config is not None and 'analyzer_report_sets_expected' in config:
            analyzer_report_sets_expected = config['analyzer_report_sets_expected']
        else:
            analyzer_report_sets_expected = None

        # analyzer_report_sets_not_expected setup
        if config is not None and 'analyzer_report_sets_not_expected' in config:
            analyzer_report_sets_not_expected = config['analyzer_report_sets_not_expected']
        else:
            analyzer_report_sets_not_expected = None

        # analyzers_report
        data['analyzers_report'] = PhishingTrackerAnalyzers(logger).analyzers_report(
            data=data,
            analyzer_report_sets_expected=analyzer_report_sets_expected,
            analyzer_report_sets_not_expected=analyzer_report_sets_not_expected,
        )

        # analyzer_report_sets - logging
        if 'analyzer_report_sets' in data['analyzers_report'] and data['analyzers_report']['analyzer_report_sets']:
            if 'expected' in data['analyzers_report']['analyzer_report_sets'] and data['analyzers_report']['analyzer_report_sets']['expected'] is False:
                logger.warn('analyzer_report_sets_expected returns false!')
            if 'not_expected' in data['analyzers_report']['analyzer_report_sets'] and data['analyzers_report']['analyzer_report_sets']['not_expected'] is True:
                logger.warn('analyzer_report_sets_not_expected returns true!')

        # tests
        if type(config) is dict and 'tests' in config.keys() and len(config['tests']) > 0:
            data['tests_report'] = PhishingTrackerTests(logger).tests(data=data, tests=config['tests'])

        PhishingTrackerFile(logger).save_datafile(data, ts, pathname)
        self.report_output(data, analyzers_report=True, tests_report=True)

    def report_output(self, data, analyzers_report=True, tests_report=True):
        if analyzers_report is True and 'analyzers_report' in data:
            print(json_dumps({'analyzers_report': data['analyzers_report']}, indent='  '))
        if tests_report is True and 'tests_report' in data and len(data['tests_report']) > 0:
            print(json_dumps({'tests_report': data['tests_report']}, indent='  '))
