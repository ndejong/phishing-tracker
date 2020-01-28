
import os
import ssl
import socket
import tempfile

from .util import json_dumps
from .util import datetime_parse


class PhishingTrackerCertificate:

    @staticmethod
    def analyzer(hostname, port=443, append_raw_certificate=True):
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        sock = context.wrap_socket(conn, server_hostname=hostname)

        try:
            sock.connect((hostname, port))
        except Exception as e:
            return 'Exception: {}'.format(str(e))

        certificate_raw = ssl.DER_cert_to_PEM_cert(sock.getpeercert(True))
        certificate = PhishingTrackerCertificate.__decode_raw_certificate(certificate_raw)

        if append_raw_certificate is True:
            certificate['raw'] = certificate_raw
        return certificate

    @staticmethod
    def __decode_raw_certificate(certificate_raw):

        filename = tempfile.mktemp()

        with open(filename, 'w') as f:
            f.write(certificate_raw)

        try:
            # using and abusing a private _ssl function
            data = dict(ssl._ssl._test_decode_cert(filename))
            os.unlink(filename)
        except Exception:
            return None

        if data is None or len(data) == 0:
            return None

        def _rollup_a(input):
            if type(input) is not tuple:
                return None
            __data = {}
            for item in input:
                attrib, value = item[0]
                __data[attrib] = value
            return __data

        def _rollup_b(input):
            if type(input) is not tuple:
                return None
            __data = {}
            for item in input:
                attrib, value = item
                if attrib in __data:
                    __data[attrib].append(value)
                else:
                    __data[attrib] = [value]
            return __data

        if 'issuer' in data:
            data['issuer'] = _rollup_a(data['issuer'])

        if 'subject' in data:
            data['subject'] = _rollup_a(data['subject'])

        if 'subjectAltName' in data:
            data['subjectAltName'] = _rollup_b(data['subjectAltName'])

        if 'notBefore' in data:
            data['notBefore'] = datetime_parse(data['notBefore'])

        if 'notAfter' in data:
            data['notAfter'] = datetime_parse(data['notAfter'])

        return data
