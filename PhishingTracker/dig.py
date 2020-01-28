
import pydig


class PhishingTrackerDig:

    @staticmethod
    def analyzer(record, type='ANY'):

        type = type.upper()

        if type == 'ANY':
            types = [ 'A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT' ]
            data = {}
            for t in types:
                data[t] = PhishingTrackerDig.analyzer(record, t)
            return data

        try:
            response = pydig.query(record, type)
        except Exception as e:
            response = 'Exception: {}'.format(str(e))

        if type == 'TXT':
            response = [s.strip('"') for s in response]
        return response

    @staticmethod
    def test(tests, data):
        pass
