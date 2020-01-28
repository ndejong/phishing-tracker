
import json
import datetime
import dateparser


def json_dumps(o, indent=None):

    def __json_dumps(o):
        if isinstance(o, datetime.datetime):
            return "{}-{}-{}".format(o.year, o.month, o.day)

    return json.dumps(o, default = __json_dumps, indent=indent)


def timestamp():
    return datetime.datetime.utcnow().strftime("%Y%m%dZ%H%M%S")


def datetime_parse(string):
    return dateparser.parse(string, settings={'TO_TIMEZONE': 'UTC'}).strftime("%Y-%m-%dT%H:%M:%S+00:00")
