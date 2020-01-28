#!/usr/bin/env python3

from setuptools import setup, find_packages
from PhishingTracker import NAME
from PhishingTracker import VERSION

with open('README.md', 'r') as f:
    long_description = f.read()

setup(
    name=NAME,
    version=VERSION,
    description='Utility to manage sets of phishing links making it easier to track their removal progress over time.',

    long_description=long_description,
    long_description_content_type='text/markdown',

    classifiers=[
        'Environment :: Console',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Information Technology',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'License :: OSI Approved :: BSD License',
    ],
    keywords=['phish', 'phishing', 'url', 'cyber-crime'],

    author='Nicholas de Jong',
    author_email='contact@nicholasdejong.com',
    url='https://github.com/ndejong/phishing-tracker',
    license='BSD 2-Clause',

    packages=find_packages(),
    zip_safe=False,
    scripts=['bin/phishing-tracker'],

    install_requires=[
        'pydig',
        'pyyaml',
        'requests',
        'dateparser',
        'tldextract',
        'python-whois',
    ],
    setup_requires=['pytest-runner'],
    tests_require=['pytest'],

)
