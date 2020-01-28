
from smtplib import SMTP


class PhishingTrackerSmtp:

    @staticmethod
    def analyzer(mx_records):

        if type(mx_records) is not list or len(mx_records) == 0:
            return None

        data = {}

        for mx_record in mx_records:
            if ' ' not in mx_record:
                continue
            _, mx_record_hostname = mx_record.split(' ')

            smtp_response = SMTP().connect(mx_record_hostname)
            if type(smtp_response) is tuple:
                smtp_code, smtp_header = smtp_response
                data[mx_record_hostname] = {
                    'status_code': smtp_code,
                    'header': smtp_header.decode('utf8')
                }

        if len(data) == 0:
            return None

        return data
