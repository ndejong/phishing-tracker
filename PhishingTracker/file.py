
import os
import yaml
import hashlib

from .util import json_dumps


class PhishingTrackerFile:

    def __init__(self, __logger=None):
        global logger
        logger = __logger

    def load_config(self, filename=None):

        config = {}
        try:
            with open(filename, 'r') as f:
                config = yaml.safe_load(f.read())
        except Exception as e:
            logger.fatal(e)
            exit(1)
        logger.info('Loaded {} items from {}'.format(len(config), filename))
        return config

    def save_datafile(self, data, timestamp, pathname=None):

        subpath = os.path.join(data['meta']['domain_name'])
        if pathname is not None:
            subpath = os.path.join(pathname, data['meta']['domain_name'])

        if not os.path.isdir(subpath):
            os.mkdir(subpath)

        md5prefix = hashlib.md5(data['meta']['reference'].encode('utf-8')).hexdigest()[0:4]

        filename = os.path.join(subpath, '{}_{}_{}.json'.format(data['meta']['host_name'], md5prefix, timestamp))
        with open(filename, 'w') as f:
            f.write(json_dumps(data, indent='  '))

        logger.info('Phish data written to {}'.format(filename))
