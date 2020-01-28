
import re


class PhishingTrackerTests:

    def __init__(self, __logger=None):
        global logger
        logger = __logger

    def tests(self, data, tests=None):

        if tests is None or len(tests) == 0:
            return None

        logger.info('tests: {}'.format(', '.join(tests.keys())))
        test_data = {}

        for test_k, test_v in tests.items():
            if test_k not in data['analyzers']:
                logger.warn('skipping {} test, no related analyzer data available'.format(test_k))
                continue

            if test_k in tests and test_k not in test_data:
                logger.debug('testing {}'.format(test_k))
                response = self.__test(tests=test_v, data=data['analyzers'][test_k])
                if response:
                    test_data[test_k] = response

        return test_data

    def __test(self, tests, data):
        for test in tests:

            if type(test) is not dict:
                logger.error('test not dict type, return None')
                return None

            context = None
            if 'context' in test.keys():
                context = test['context']

            if 'matches' not in test:
                logger.error('test missing "matches" attribute, return None')
                return None

            if type(test['matches']) is list:
                expressions = test['matches']
            else:
                expressions = [str(test['matches'])]

            return self.__test_in_context(expressions, context, data)

    def __test_in_context(self, expressions, context, data):

        if type(data) is dict and context is None:
            for item_k, item_v in data.items():
                string = str(item_v)
                expressions_match_count = 0
                for expression in expressions:
                    if re.search(expression, string):
                        logger.debug('within context {} matched {} in {}'.format(item_k, expression, string))
                        expressions_match_count += 1
                if expressions_match_count == len(expressions):
                    return {
                        'matches': expressions,
                        'context': string[0:120] + ' ...'
                    }

        elif type(data) is dict and context in data:
            string = str(data[context])
            expressions_match_count = 0
            for expression in expressions:
                if re.search(expression, string):
                    logger.debug('within context {} matched {} in "{}"'.format(context, expression, string))
                    expressions_match_count += 1
            if expressions_match_count == len(expressions):
                return {
                    'matches': expressions,
                    'context': string[0:120] + ' ...'
                }

        elif type(data) is dict and context not in data:
            logger.warn('context "{}" not found in data'.format(str(context)))

        else:
            logger.error('unsupported data type presented for {}'.format(str(expressions)))

        return None
